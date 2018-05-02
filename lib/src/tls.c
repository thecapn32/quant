// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2018, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <bitstring.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

// IWYU pragma: no_include <picotls/../picotls.h>
#include <picotls/minicrypto.h>
#include <picotls/openssl.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#if defined(HAVE_ENDIAN_H)
// e.g., Linux
#include <endian.h>
#elif defined(HAVE_SYS_ENDIAN_H)
// e.g., FreeBSD
#include <sys/endian.h>
#else
#include <arpa/inet.h>
#endif

#include "conn.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"

#ifndef NDEBUG
// #define DEBUG_KEYS
#endif


struct tls_ticket {
    char * sni;
    char * alpn;
    uint8_t * ticket;
    size_t ticket_len;
    struct transport_params tp;
    uint32_t vers;
    uint8_t _unused[4];
    splay_entry(tls_ticket) node;
};


struct ticket_splay {
    splay_head(, tls_ticket);
    char file_name[MAXPATHLEN];
};

static int __attribute__((nonnull))
tls_ticket_cmp(const struct tls_ticket * const a,
               const struct tls_ticket * const b)
{
    int diff = strcmp(a->sni, b->sni);
    if (diff)
        return diff;

    diff = strcmp(a->alpn, b->alpn);
    return diff;
}


SPLAY_PROTOTYPE(ticket_splay, tls_ticket, node, tls_ticket_cmp)
SPLAY_GENERATE(ticket_splay, tls_ticket, node, tls_ticket_cmp)

ptls_context_t tls_ctx = {0};
static struct ticket_splay tickets = splay_initializer(tickets);


#define TLS_MAX_CERTS 10
static ptls_iovec_t tls_certs[TLS_MAX_CERTS];
static ptls_openssl_sign_certificate_t sign_cert = {0};
static ptls_openssl_verify_certificate_t verifier = {0};

static const ptls_iovec_t alpn[] = {{(uint8_t *)"hq-11", 5}};
static const size_t alpn_cnt = sizeof(alpn) / sizeof(alpn[0]);

static ptls_aead_context_t * dec_tckt;
static ptls_aead_context_t * enc_tckt;

#define COOKIE_LEN 64
static uint8_t cookie[COOKIE_LEN];


#define TLS_EXT_TYPE_TRANSPORT_PARAMETERS 26

#define TP_INITIAL_MAX_STREAM_DATA 0x0000
#define TP_INITIAL_MAX_DATA 0x0001
#define TP_INITIAL_MAX_STREAM_ID_BIDI 0x0002
#define TP_IDLE_TIMEOUT 0x0003
#define TP_MAX_PACKET_SIZE 0x0005
#define TP_STATELESS_RESET_TOKEN 0x0006
#define TP_ACK_DELAY_EXPONENT 0x0007
#define TP_INITIAL_MAX_STREAM_ID_UNI 0x0008

#define TP_MAX TP_INITIAL_MAX_STREAM_ID_UNI


static int qhkdf_expand(ptls_hash_algorithm_t * const algo,
                        void * const output,
                        const size_t outlen,
                        const void * const secret,
                        const char * const label)
{
    ptls_buffer_t hkdf_label;
    uint8_t hkdf_label_buf[16];
    int ret;

    ptls_buffer_init(&hkdf_label, hkdf_label_buf, sizeof(hkdf_label_buf));

    ptls_buffer_push16(&hkdf_label, (uint16_t)outlen);
    ptls_buffer_push_block(&hkdf_label, 1, {
        const char * const base_label = "QUIC ";
        ptls_buffer_pushv(&hkdf_label, base_label, strlen(base_label));
        ptls_buffer_pushv(&hkdf_label, label, strlen(label));
    });

    ret = ptls_hkdf_expand(algo, output, outlen,
                           ptls_iovec_init(secret, algo->digest_size),
                           ptls_iovec_init(hkdf_label.base, hkdf_label.off));

Exit:
    ptls_buffer_dispose(&hkdf_label);
    return ret;
}

static ptls_aead_context_t * new_aead(ptls_aead_algorithm_t * const aead,
                                      ptls_hash_algorithm_t * const hash,
                                      const int is_enc,
                                      const void * const secret)
{
    ptls_aead_context_t * ctx = 0;
    uint8_t key[PTLS_MAX_SECRET_SIZE];
    int ret;

    if ((ret = qhkdf_expand(hash, key, aead->key_size, secret, "key")) != 0)
        goto Exit;
#ifdef DEBUG_KEYS
    warn(CRT, "key");
    hexdump(key, aead->key_size);
#endif
    if ((ctx = ptls_aead_new(aead, is_enc, key)) == 0) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((ret = qhkdf_expand(hash, ctx->static_iv, aead->iv_size, secret,
                            "iv")) != 0)
        goto Exit;
#ifdef DEBUG_KEYS
    warn(CRT, "iv");
    hexdump(ctx->static_iv, aead->iv_size);
#endif

    ret = 0;
Exit:
    if (ret != 0 && ctx != 0) {
        ptls_aead_free(ctx);
        ctx = 0;
    }
    ptls_clear_memory(key, sizeof(key));
    return ctx;
}


static int __attribute__((nonnull))
on_ch(ptls_on_client_hello_t * const self __attribute__((unused)),
      ptls_t * const tls,
      const ptls_iovec_t sni,
      const ptls_iovec_t * const prot,
      const size_t prot_cnt,
      const uint16_t * const sig_alg __attribute__((unused)),
      const size_t sig_alg_cnt __attribute__((unused)))
{
    if (sni.len) {
        warn(INF, "\tSNI = %.*s", sni.len, sni.base);
        ensure(ptls_set_server_name(tls, (const char *)sni.base, sni.len) == 0,
               "ptls_set_server_name");
    } else
        warn(INF, "\tSNI = ");


    if (prot_cnt == 0) {
        warn(WRN, "\tALPN = ");
        return 0;
    }

    size_t j;
    for (j = 0; j < alpn_cnt; j++)
        for (size_t i = 0; i < prot_cnt; i++)
            if (memcmp(prot[i].base, alpn[j].base,
                       MIN(prot[i].len, alpn[j].len)) == 0)
                goto done;

    if (j == prot_cnt) {
        warn(WRN, "\tALPN = %.*s (and maybe others, none supported, ignoring)",
             prot[0].len, prot[0].base);
        return 0;
    }

done:
    // mark this ALPN as negotiated
    ptls_set_negotiated_protocol(tls, (char *)alpn[j].base, alpn[j].len);
    warn(INF, "\tALPN = %.*s", alpn[j].len, alpn[j].base);

    return 0;
}


static ptls_on_client_hello_t cb = {on_ch};


static int filter_tp(ptls_t * tls __attribute__((unused)),
                     struct st_ptls_handshake_properties_t * properties
                     __attribute__((unused)),
                     uint16_t type)
{
    return type == TLS_EXT_TYPE_TRANSPORT_PARAMETERS;
}


static uint16_t chk_tp_clnt(const struct q_conn * const c,
                            const uint8_t * const buf,
                            const uint16_t len,
                            const uint16_t pos)
{
    uint16_t i = pos;

    uint32_t vers_initial;
    i = dec(&vers_initial, buf, len, i, sizeof(vers_initial), "0x%08x");

    // parse server versions
    uint8_t n;
    i = dec(&n, buf, len, i, sizeof(n), "%u");
    bool found = false;
    while (n > 0) {
        uint32_t vers;
        n -= sizeof(vers);
        i = dec(&vers, buf, len, i, sizeof(vers), "0x%08x");
        found = found ? found : vers == c->vers;
    }
    ensure(found, "negotiated version found in transport parameters");
    // TODO: validate that version negotiation on these values has same result

    return i;
}


static uint16_t chk_tp_serv(const struct q_conn * const c,
                            const uint8_t * const buf,
                            const uint16_t len,
                            const uint16_t pos)
{
    uint16_t i = pos;

    uint32_t vers_initial;
    i = dec(&vers_initial, buf, len, i, sizeof(vers_initial), "0x%08x");

    if (vers_initial != c->vers_initial)
        warn(ERR, "vers_initial 0x%08x != first received 0x%08x", vers_initial,
             c->vers_initial);

    return i;
}


#define dec_tp(var, w)                                                         \
    do {                                                                       \
        uint16_t l;                                                            \
        i = dec(&l, buf, len, i, sizeof(l), "%u");                             \
        ensure(l == 0 || l == ((w) ? (w) : sizeof(var)), "invalid len %u", l); \
        if (l)                                                                 \
            i = dec((var), buf, len, i, (w) ? (w) : 0, "%u");                  \
    } while (0)


static int chk_tp(ptls_t * tls __attribute__((unused)),
                  ptls_handshake_properties_t * properties,
                  ptls_raw_extension_t * slots)
{
    ensure(slots[0].type == TLS_EXT_TYPE_TRANSPORT_PARAMETERS, "have tp");
    ensure(slots[1].type == UINT16_MAX, "have end");

    // get connection based on properties pointer
    struct q_conn * const c =
        (void *)((char *)properties - offsetof(struct tls, tls_hshake_prop) -
                 offsetof(struct q_conn, tls));

    // set up parsing
    const uint8_t * const buf = slots[0].data.base;
    uint16_t len = (uint16_t)slots[0].data.len;
    uint16_t i = 0;

    if (c->is_clnt)
        i = chk_tp_clnt(c, buf, len, i);
    else
        i = chk_tp_serv(c, buf, len, i);

    uint16_t tpl;
    i = dec(&tpl, buf, len, i, sizeof(tpl), "%u");
    if (tpl != len - i) {
        err_close(c, ERR_TLS_HSHAKE_FAIL, "tp len %u is incorrect", tpl);
        return 1;
    }
    len = i + tpl;

    // keep track of which transport parameters we've seen before
    bitstr_t bit_decl(tp_list, TP_MAX + 1) = {0};

    while (i < len) {
        uint16_t tp;
        i = dec(&tp, buf, len, i, sizeof(tp), "%u");

        // check if this transport parameter is a duplicate
        ensure(tp <= TP_MAX, "unknown tp %u", tp);
        ensure(!bit_test(tp_list, tp), "tp %u is a duplicate", tp);

        switch (tp) {
        case TP_INITIAL_MAX_STREAM_DATA:
            dec_tp(&c->tp_peer.max_strm_data, sizeof(uint32_t));
            warn(INF, "\tinitial_max_stream_data = %u",
                 c->tp_peer.max_strm_data);
            // we need to apply this parameter to all current streams
            struct q_stream * s;
            splay_foreach (s, stream, &c->streams)
                s->out_data_max = c->tp_peer.max_strm_data;
            break;

        case TP_INITIAL_MAX_DATA:
            dec_tp(&c->tp_peer.max_data, sizeof(uint32_t));
            warn(INF, "\tinitial_max_data = %u", c->tp_peer.max_data);
            break;

        case TP_INITIAL_MAX_STREAM_ID_BIDI:
            dec_tp(&c->tp_peer.max_strm_bidi, sizeof(uint16_t));
            c->tp_peer.max_strm_bidi <<= 2;
            c->tp_peer.max_strm_bidi |= c->is_clnt ? 0 : STRM_FL_INI_SRV;
            warn(INF, "\tinitial_max_stream_id_bidi = %u",
                 c->tp_peer.max_strm_bidi);
            break;

        case TP_INITIAL_MAX_STREAM_ID_UNI:
            dec_tp(&c->tp_peer.max_strm_uni, sizeof(uint16_t));
            c->tp_peer.max_strm_uni <<= 2;
            c->tp_peer.max_strm_uni |=
                STRM_FL_DIR_UNI | (c->is_clnt ? 0 : STRM_FL_INI_SRV);
            warn(INF, "\tinitial_max_stream_id_uni = %u",
                 c->tp_peer.max_strm_uni);
            break;

        case TP_IDLE_TIMEOUT:
            dec_tp(&c->tp_peer.idle_to, sizeof(uint16_t));
            warn(INF, "\tidle_timeout = %u", c->tp_peer.idle_to);
            if (c->tp_peer.idle_to > 600)
                warn(ERR, "idle timeout %u > 600", c->tp_peer.idle_to);
            break;

        case TP_MAX_PACKET_SIZE:
            dec_tp(&c->tp_peer.max_pkt, sizeof(uint16_t));
            warn(INF, "\tmax_packet_size = %u", c->tp_peer.max_pkt);
            if (c->tp_peer.max_pkt < 1200 || c->tp_peer.max_pkt > 65527)
                warn(ERR, "tp_peer.max_pkt %u invalid", c->tp_peer.max_pkt);
            break;

        case TP_ACK_DELAY_EXPONENT:
            dec_tp(&c->tp_peer.ack_del_exp, sizeof(uint8_t));
            warn(INF, "\tack_delay_exponent = %u", c->tp_peer.ack_del_exp);
            if (c->tp_peer.ack_del_exp > 20)
                warn(ERR, "tp_peer.ack_del_exp %u invalid",
                     c->tp_peer.ack_del_exp);
            break;

        case TP_STATELESS_RESET_TOKEN:
            ensure(c->is_clnt, "am client");
            uint16_t l;
            i = dec(&l, buf, len, i, sizeof(l), "%u");
            ensure(l == sizeof(c->stateless_reset_token), "valid len");
            memcpy(c->stateless_reset_token, &buf[i],
                   sizeof(c->stateless_reset_token));
            warn(INF,
                 "\tstateless_reset_token = %02x%02x%02x%02x%02x%02x%02x%02x "
                 "%02x%02x%02x%02x%02x%02x%02x%02x",
                 c->stateless_reset_token[0], c->stateless_reset_token[1],
                 c->stateless_reset_token[2], c->stateless_reset_token[3],
                 c->stateless_reset_token[4], c->stateless_reset_token[5],
                 c->stateless_reset_token[6], c->stateless_reset_token[7],
                 c->stateless_reset_token[8], c->stateless_reset_token[9],
                 c->stateless_reset_token[10], c->stateless_reset_token[11],
                 c->stateless_reset_token[12], c->stateless_reset_token[13],
                 c->stateless_reset_token[14], c->stateless_reset_token[15]);
            i += sizeof(c->stateless_reset_token);
            break;

        default:
            die("unsupported transport parameter 0x%04x", tp);
        }
    }

    ensure(i == len, "out of parameters");

    return 0;
}


#define enc_tp(c, tp, var, w)                                                  \
    do {                                                                       \
        const uint16_t param = (tp);                                           \
        i = enc((c)->tls.tp_buf, len, i, &param, sizeof(param), "%u");         \
        const uint16_t bytes = (w);                                            \
        i = enc((c)->tls.tp_buf, len, i, &bytes, sizeof(bytes), "%u");         \
        if (w)                                                                 \
            i = enc((c)->tls.tp_buf, len, i, &(var), bytes, "%u");             \
    } while (0)


void init_tp(struct q_conn * const c)
{
    uint16_t i = 0;
    const uint16_t len = sizeof(c->tls.tp_buf);

    if (c->is_clnt) {
        i = enc(c->tls.tp_buf, len, i, &c->vers_initial,
                sizeof(c->vers_initial), "0x%08x");
    } else {
        i = enc(c->tls.tp_buf, len, i, &c->vers, sizeof(c->vers), "0x%08x");
        const uint8_t vl = ok_vers_len * sizeof(ok_vers[0]);
        i = enc(c->tls.tp_buf, len, i, &vl, sizeof(vl), "%u");
        for (uint8_t n = 0; n < ok_vers_len; n++)
            i = enc(c->tls.tp_buf, len, i, &ok_vers[n], sizeof(ok_vers[n]),
                    "0x%08x");
    }

    // keep track of encoded length
    const uint16_t enc_len_pos = i;
    i += sizeof(uint16_t);

    // convert the stream ID number to a count
    const uint16_t max_strm_bidi = (uint16_t)c->tp_local.max_strm_bidi >> 2;
    enc_tp(c, TP_INITIAL_MAX_STREAM_ID_BIDI, max_strm_bidi, sizeof(uint16_t));

    enc_tp(c, TP_IDLE_TIMEOUT, c->tp_local.idle_to, sizeof(uint16_t));
    enc_tp(c, TP_INITIAL_MAX_STREAM_DATA, c->tp_local.max_strm_data,
           sizeof(uint32_t));
    enc_tp(c, TP_INITIAL_MAX_DATA, c->tp_local.max_data, sizeof(uint32_t));
    enc_tp(c, TP_ACK_DELAY_EXPONENT, c->tp_local.ack_del_exp, sizeof(uint8_t));
    enc_tp(c, TP_MAX_PACKET_SIZE, w_mtu(w_engine(c->sock)), sizeof(uint16_t));

    if (!c->is_clnt) {
        const uint16_t p = TP_STATELESS_RESET_TOKEN;
        i = enc(c->tls.tp_buf, len, i, &p, 2, "%u");
        const uint16_t w = sizeof(c->stateless_reset_token);
        i = enc(c->tls.tp_buf, len, i, &w, 2, "%u");
        ensure(i + sizeof(c->stateless_reset_token) < len, "tp_buf overrun");
        memcpy(&c->tls.tp_buf[i], c->stateless_reset_token,
               sizeof(c->stateless_reset_token));
        warn(DBG, "enc %u byte%s stateless_reset_token at [%u..%u]", w,
             plural(w), i, i + w);
        i += sizeof(c->stateless_reset_token);
    }

    // encode length of all transport parameters
    const uint16_t enc_len = i - enc_len_pos - sizeof(enc_len);
    i = enc_len_pos;
    enc(c->tls.tp_buf, len, i, &enc_len, 2, "%u");

    c->tls.tp_ext[0] = (ptls_raw_extension_t){
        TLS_EXT_TYPE_TRANSPORT_PARAMETERS,
        {c->tls.tp_buf, enc_len + enc_len_pos + sizeof(enc_len)}};
    c->tls.tp_ext[1] = (ptls_raw_extension_t){UINT16_MAX};
}


static void init_ticket_prot(void)
{
    const ptls_cipher_suite_t * const cs = &ptls_openssl_aes128gcmsha256;
    uint8_t output[PTLS_MAX_SECRET_SIZE] = {0};
    memcpy(output, quant_commit_hash,
           MIN(quant_commit_hash_len, sizeof(output)));

    dec_tckt = new_aead(cs->aead, cs->hash, 0, output);
    enc_tckt = new_aead(cs->aead, cs->hash, 1, output);
    ensure(dec_tckt && enc_tckt, "cannot init ticket protection");

    ptls_clear_memory(output, sizeof(output));
}


static ptls_aead_context_t * init_hshk_secret(ptls_cipher_suite_t * const cs,
                                              uint8_t * const sec,
                                              const char * const label,
                                              uint8_t is_enc)
{
    uint8_t output[PTLS_MAX_SECRET_SIZE];
    ensure(qhkdf_expand(cs->hash, output, cs->hash->digest_size, sec, label) ==
               0,
           "qhkdf_expand");
#ifdef DEBUG_KEYS
    warn(CRT, "%s handshake secret", label);
    hexdump(output, cs->hash->digest_size);
#endif
    return new_aead(cs->aead, cs->hash, is_enc, output);
}


void init_hshk_prot(struct q_conn * const c)
{
    // this can be called multiple times due to retry
    if (c->tls.dec_hshk)
        ptls_aead_free(c->tls.dec_hshk);
    if (c->tls.enc_hshk)
        ptls_aead_free(c->tls.enc_hshk);

    static uint8_t qv1_salt[] = {0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c,
                                 0x5c, 0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a,
                                 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38};

    const ptls_cipher_suite_t * const cs = &ptls_openssl_aes128gcmsha256;

    uint8_t sec[PTLS_MAX_SECRET_SIZE];
    const ptls_iovec_t salt = {.base = qv1_salt, .len = sizeof(qv1_salt)};

    const ptls_iovec_t cid = {
        .base = (uint8_t *)(c->is_clnt ? &c->dcid.id : &c->scid.id),
        .len = c->is_clnt ? c->dcid.len : c->scid.len};
    ensure(ptls_hkdf_extract(cs->hash, sec, salt, cid) == 0,
           "ptls_hkdf_extract");
#ifdef DEBUG_KEYS
    warn(CRT, "handshake secret");
    hexdump(sec, PTLS_MAX_SECRET_SIZE);
#endif
    c->tls.dec_hshk =
        init_hshk_secret(cs, sec, c->is_clnt ? "server hs" : "client hs", 0);
#ifdef DEBUG_KEYS
    warn(CRT, "%s iv", c->is_clnt ? "serv" : "clnt");
    hexdump(c->tls.dec_hshk->static_iv, c->tls.dec_hshk->algo->iv_size);
#endif
    c->tls.enc_hshk =
        init_hshk_secret(cs, sec, c->is_clnt ? "client hs" : "server hs", 1);
#ifdef DEBUG_KEYS
    warn(CRT, "%s iv", c->is_clnt ? "clnt" : "serv");
    hexdump(c->tls.enc_hshk->static_iv, c->tls.enc_hshk->algo->iv_size);
#endif
}


static int encrypt_ticket_cb(ptls_encrypt_ticket_t * self
                             __attribute__((unused)),
                             ptls_t * tls
#ifdef NDEBUG
                             __attribute__((unused))
#endif
                             ,
                             int is_encrypt,
                             ptls_buffer_t * dst,
                             ptls_iovec_t src)
{
#ifndef NDEBUG
    struct q_conn * const c = *ptls_get_data_ptr(tls);
#endif
    uint64_t tid;
    if (ptls_buffer_reserve(dst, src.len + quant_commit_hash_len + sizeof(tid) +
                                     enc_tckt->algo->tag_size))
        return -1;

    if (is_encrypt) {
        warn(INF, "creating new 0-RTT session ticket for %s conn %s(% s % s) ",
             conn_type(c), cid2str(&c->scid), ptls_get_server_name(tls),
             ptls_get_negotiated_protocol(tls));

        // prepend git commit hash
        memcpy(dst->base + dst->off, quant_commit_hash, quant_commit_hash_len);
        dst->off += quant_commit_hash_len;

        // prepend ticket id
        arc4random_buf(&tid, sizeof(tid));
        memcpy(dst->base + dst->off, &tid, sizeof(tid));
        dst->off += sizeof(tid);

        // now encrypt ticket
        dst->off += ptls_aead_encrypt(enc_tckt, dst->base + dst->off, src.base,
                                      src.len, tid, 0, 0);

    } else {
        if (src.len < quant_commit_hash_len + sizeof(tid) +
                          dec_tckt->algo->tag_size ||
            memcmp(src.base, quant_commit_hash, quant_commit_hash_len) != 0) {
            warn(WRN,
                 "could not verify 0-RTT session ticket for %s conn %s (%s %s)",
                 conn_type(c), cid2str(&c->scid), ptls_get_server_name(tls),
                 ptls_get_negotiated_protocol(tls));
            return -1;
        }
        uint8_t * src_base = src.base + quant_commit_hash_len;
        size_t src_len = src.len - quant_commit_hash_len;

        memcpy(&tid, src_base, sizeof(tid));
        src_base += sizeof(tid);
        src_len -= sizeof(tid);

        const size_t n = ptls_aead_decrypt(dec_tckt, dst->base + dst->off,
                                           src_base, src_len, tid, 0, 0);

        if (n > src_len) {
            warn(
                WRN,
                "could not decrypt 0-RTT session ticket for %s conn %s (%s %s)",
                conn_type(c), cid2str(&c->scid), ptls_get_server_name(tls),
                ptls_get_negotiated_protocol(tls));
            return -1;
        }
        dst->off += n;

        warn(INF, "verified 0-RTT session ticket for %s conn %s (%s %s)",
             conn_type(c), cid2str(&c->scid), ptls_get_server_name(tls),
             ptls_get_negotiated_protocol(tls));
    }

    return 0;
}


static int save_ticket_cb(ptls_save_ticket_t * self __attribute__((unused)),
                          ptls_t * tls,
                          ptls_iovec_t src)
{
    struct q_conn * const c = *ptls_get_data_ptr(tls);
    warn(NTE, "saving 0-RTT tickets to %s", tickets.file_name);

    FILE * const fp = fopen(tickets.file_name, "wbe");
    ensure(fp, "could not open ticket file %s", tickets.file_name);

    // write git hash
    ensure(fwrite(&quant_commit_hash_len, sizeof(quant_commit_hash_len), 1, fp),
           "fwrite");
    ensure(fwrite(quant_commit_hash, quant_commit_hash_len, 1, fp), "fwrite");

    char * s = 0;
    if (ptls_get_server_name(tls))
        s = strdup(ptls_get_server_name(tls));
    else
        s = calloc(1, sizeof(char));
    char * a = 0;
    if (ptls_get_negotiated_protocol(tls))
        a = strdup(ptls_get_negotiated_protocol(tls));
    else
        a = calloc(1, sizeof(char));
    const struct tls_ticket which = {.sni = s, .alpn = a};
    struct tls_ticket * t = splay_find(ticket_splay, &tickets, &which);
    if (t == 0) {
        // create new ticket
        t = calloc(1, sizeof(*t));
        ensure(t, "calloc");
        t->sni = s;
        t->alpn = a;
        splay_insert(ticket_splay, &tickets, t);
    } else {
        // update current ticket
        free(t->ticket);
        free(s);
        free(a);
    }

    memcpy(&t->tp, &c->tp_peer, sizeof(t->tp));
    t->vers = c->vers;

    t->ticket_len = src.len;
    t->ticket = calloc(1, t->ticket_len);
    ensure(t->ticket, "calloc");
    memcpy(t->ticket, src.base, src.len);

    // write all tickets
    // XXX this currently dumps the entire cache to file on each connection!
    splay_foreach (t, ticket_splay, &tickets) { // NOLINT
        warn(INF, "writing 0-RTT ticket for %s conn %s (%s %s)", conn_type(c),
             cid2str(&c->scid), t->sni, t->alpn);

        size_t len = strlen(t->sni) + 1;
        ensure(fwrite(&len, sizeof(len), 1, fp), "fwrite");
        ensure(fwrite(t->sni, sizeof(*t->sni), len, fp), "fwrite");

        len = strlen(t->alpn) + 1;
        ensure(fwrite(&len, sizeof(len), 1, fp), "fwrite");
        ensure(fwrite(t->alpn, sizeof(*t->alpn), len, fp), "fwrite");

        ensure(fwrite(&t->tp, sizeof(t->tp), 1, fp), "fwrite");
        ensure(fwrite(&t->vers, sizeof(t->vers), 1, fp), "fwrite");

        ensure(fwrite(&t->ticket_len, sizeof(t->ticket_len), 1, fp), "fwrite");
        ensure(fwrite(t->ticket, sizeof(*t->ticket), t->ticket_len, fp),
               "fwrite");
    }

    fclose(fp);
    return 0;
}


static ptls_save_ticket_t save_ticket = {.cb = save_ticket_cb};
static ptls_encrypt_ticket_t encrypt_ticket = {.cb = encrypt_ticket_cb};


void init_tls(struct q_conn * const c)
{
    if (c->tls.t)
        // we are re-initializing during version negotiation
        ptls_free(c->tls.t);
    ensure((c->tls.t = ptls_new(&tls_ctx, !c->is_clnt)) != 0, "ptls_new");
    *ptls_get_data_ptr(c->tls.t) = c;
    if (c->is_clnt)
        ensure(ptls_set_server_name(c->tls.t, c->peer_name, 0) == 0,
               "ptls_set_server_name");

    ptls_handshake_properties_t * const hshk_prop = &c->tls.tls_hshake_prop;

    hshk_prop->additional_extensions = c->tls.tp_ext;
    hshk_prop->collect_extension = filter_tp;
    hshk_prop->collected_extensions = chk_tp;

    if (c->is_clnt) {
        hshk_prop->client.negotiated_protocols.list = alpn;
        hshk_prop->client.negotiated_protocols.count = alpn_cnt;
        hshk_prop->client.max_early_data_size = &c->tls.max_early_data;
    } else {
        // TODO: remove this interop hack eventually
        hshk_prop->server.retry_uses_cookie = 1;
        hshk_prop->server.cookie.key = cookie;
        hshk_prop->server.cookie.additional_data.base = (uint8_t *)&c->peer;
        hshk_prop->server.cookie.additional_data.len = sizeof(c->peer);
        if (ntohs(c->sport) == 4434)
            hshk_prop->server.enforce_retry = 1;
    }

    // try to find an existing session ticket
    struct tls_ticket which = {.sni = c->peer_name,
                               .alpn = (char *)alpn[0].base};
    struct tls_ticket * t = splay_find(ticket_splay, &tickets, &which);
    if (t == 0) {
        // if we couldn't find a ticket, try without an alpn
        which.alpn = "";
        t = splay_find(ticket_splay, &tickets, &which);
    }
    if (t) {
        hshk_prop->client.session_ticket =
            ptls_iovec_init(t->ticket, t->ticket_len);
        memcpy(&c->tp_peer, &t->tp, sizeof(t->tp));
        c->vers_initial = c->vers = t->vers;
        c->try_0rtt = 1;
    }

    init_tp(c);
    if (!c->tls.dec_hshk)
        init_hshk_prot(c);
}


void free_tls(struct q_conn * const c)
{
    if (c->tls.dec_0rtt)
        ptls_aead_free(c->tls.dec_0rtt);
    if (c->tls.enc_0rtt)
        ptls_aead_free(c->tls.enc_0rtt);
    if (c->tls.dec_1rtt)
        ptls_aead_free(c->tls.dec_1rtt);
    if (c->tls.enc_1rtt)
        ptls_aead_free(c->tls.enc_1rtt);
    if (c->tls.dec_hshk)
        ptls_aead_free(c->tls.dec_hshk);
    if (c->tls.enc_hshk)
        ptls_aead_free(c->tls.enc_hshk);
    if (c->tls.t)
        ptls_free(c->tls.t);

    // free ticket cache
    struct tls_ticket *t, *tmp;
    for (t = splay_min(ticket_splay, &tickets); t != 0; t = tmp) {
        tmp = splay_next(ticket_splay, &tickets, t);
        splay_remove(ticket_splay, &tickets, t);
        free(t->sni);
        free(t->alpn);
        free(t->ticket);
        free(t);
    }
}


static ptls_aead_context_t * __attribute__((nonnull))
init_secret(ptls_t * const t,
            const char * const label,
            uint8_t is_enc,
            uint8_t is_early)
{
    const ptls_cipher_suite_t * const cs = ptls_get_cipher(t);
    uint8_t sec[PTLS_MAX_DIGEST_SIZE];
    ensure(ptls_export_secret(t, sec, cs->hash->digest_size, label,
                              ptls_iovec_init(0, 0), is_early) == 0,
           "ptls_export_secret");
#ifdef DEBUG_KEYS
    warn(CRT, "%s secret", label);
    hexdump(sec, cs->hash->digest_size);
#endif

    return new_aead(cs->aead, cs->hash, is_enc, sec);
}


#define LABL_0RTT "EXPORTER-QUIC 0rtt"

void init_0rtt_prot(struct q_conn * const c)
{
    // this can be called multiple times due to version negotiation
    if (c->tls.dec_0rtt)
        ptls_aead_free(c->tls.dec_0rtt);
    if (c->tls.enc_0rtt)
        ptls_aead_free(c->tls.enc_0rtt);

    c->tls.dec_0rtt = init_secret(c->tls.t, LABL_0RTT, 0, 1);
    c->tls.enc_0rtt = init_secret(c->tls.t, LABL_0RTT, 1, 1);
}


#define CLNT_LABL_1RTT "EXPORTER-QUIC client 1rtt"
#define SERV_LABL_1RTT "EXPORTER-QUIC server 1rtt"


static void __attribute__((nonnull)) init_1rtt_prot(struct q_conn * const c)
{
    c->tls.dec_1rtt = init_secret(
        c->tls.t, c->is_clnt ? SERV_LABL_1RTT : CLNT_LABL_1RTT, 0, 0);
    c->tls.enc_1rtt = init_secret(
        c->tls.t, c->is_clnt ? CLNT_LABL_1RTT : SERV_LABL_1RTT, 1, 0);
}


uint32_t tls_io(struct q_stream * const s, struct w_iov * const iv)
{
    uint8_t buf[4096];
    ptls_buffer_t tb;
    ptls_buffer_init(&tb, buf, sizeof(buf));

    int ret = 0;
    do {
        size_t in_len = iv ? iv->len : 0;
        if (ptls_handshake_is_complete(s->c->tls.t))
            ret = ptls_receive(s->c->tls.t, &tb, iv ? iv->buf : 0, &in_len);
        else
            ret = ptls_handshake(s->c->tls.t, &tb, iv ? iv->buf : 0, &in_len,
                                 &s->c->tls.tls_hshake_prop);
        warn(DBG, "in %u (off %u), gen %u, ret %u, left %u", iv ? iv->len : 0,
             iv ? meta(iv).stream_off : 0, tb.off, ret,
             iv ? iv->len - in_len : 0);
        if (iv) {
            iv->buf += in_len;
            iv->len -= in_len;
        }

        if (ret == 0 && s->c->state < CONN_STAT_HSHK_DONE) {
            if (ptls_is_psk_handshake(s->c->tls.t)) {
                if (s->c->is_clnt)
                    s->c->did_0rtt =
                        s->c->try_0rtt & s->c->tls.tls_hshake_prop.client
                                             .early_data_accepted_by_peer;
                else {
                    init_0rtt_prot(s->c);
                    s->c->did_0rtt = 1;
                }
            }

            init_1rtt_prot(s->c);
            conn_to_state(s->c, CONN_STAT_HSHK_DONE);
        } else if (ret == PTLS_ERROR_STATELESS_RETRY) {
            conn_to_state(s->c, CONN_STAT_SEND_RTRY);
            break;
        } else if (ret == PTLS_ERROR_IN_PROGRESS &&
                   s->c->state == CONN_STAT_CH_SENT) {
            conn_to_state(s->c, CONN_STAT_SH);
        } else if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
            err_close(s->c, ERR_TLS_HSHAKE_FAIL, "picotls error %u", ret);
            break;
        }
    } while (iv && iv->len);

    if (tb.off) {
        // enqueue for TX
        struct w_iov_sq o = sq_head_initializer(o);
        q_alloc(w_engine(s->c->sock), &o, (uint32_t)tb.off);
        uint8_t * data = tb.base;
        struct w_iov * ov = 0;
        sq_foreach (ov, &o, next) {
            memcpy(ov->buf, data, ov->len);
            data += ov->len;
        }
        sq_concat(&s->out, &o);
        s->c->needs_tx = true;
    }
    ptls_buffer_dispose(&tb);

    return (uint32_t)ret;
}


static void read_tickets()
{
    FILE * const fp = fopen(tickets.file_name, "rbe");
    if (fp == 0) {
        warn(WRN, "could not read 0-RTT tickets from %s", tickets.file_name);
        return;
    }

    warn(INF, "reading 0-RTT tickets from %s", tickets.file_name);

    // read and verify git hash
    size_t hash_len;
    ensure(fread(&hash_len, sizeof(quant_commit_hash_len), 1, fp), "fread");
    uint8_t buf[8192];
    ensure(fread(buf, sizeof(uint8_t), hash_len, fp), "fread");
    if (hash_len != quant_commit_hash_len ||
        memcmp(buf, quant_commit_hash, hash_len) != 0) {
        warn(WRN, "0-RTT tickets were stored by different %s version, removing",
             quant_name);
        ensure(unlink(tickets.file_name) == 0, "unlink");
        goto done;
    }

    for (;;) {
        // try and read the SNI len
        size_t len;
        if (fread(&len, sizeof(len), 1, fp) != 1)
            // we read all the tickets
            break;

        struct tls_ticket * const t = calloc(1, sizeof(*t));
        ensure(t, "calloc");
        t->sni = calloc(1, len);
        ensure(t->sni, "calloc");
        ensure(fread(t->sni, sizeof(*t->sni), len, fp), "fread");

        ensure(fread(&len, sizeof(len), 1, fp), "fread");
        t->alpn = calloc(1, len);
        ensure(t->alpn, "calloc");
        ensure(fread(t->alpn, sizeof(*t->alpn), len, fp), "fread");

        ensure(fread(&t->tp, sizeof(t->tp), 1, fp), "fwrite");
        ensure(fread(&t->vers, sizeof(t->vers), 1, fp), "fwrite");

        ensure(fread(&len, sizeof(len), 1, fp), "fread");
        t->ticket_len = len;
        t->ticket = calloc(len, sizeof(*t->ticket));
        ensure(t->ticket, "calloc");
        ensure(fread(t->ticket, sizeof(*t->ticket), len, fp), "fread");

        splay_insert(ticket_splay, &tickets, t);
        warn(INF, "got 0-RTT ticket %s %s", t->sni, t->alpn);
    }

done:
    fclose(fp);
}


void init_tls_ctx(const char * const cert,
                  const char * const key,
                  const char * const ticket_store)
{
    FILE * fp = 0;
    if (key) {
        fp = fopen(key, "rbe");
        ensure(fp, "could not open key %s", key);
        EVP_PKEY * const pkey = PEM_read_PrivateKey(fp, 0, 0, 0);
        fclose(fp);
        ensure(pkey, "failed to load private key");
        ptls_openssl_init_sign_certificate(&sign_cert, pkey);
        EVP_PKEY_free(pkey);
    }

    // TODO: replace with ptls_load_certificates()
    if (cert) {
        fp = fopen(cert, "rbe");
        ensure(fp, "could not open cert %s", cert);
        uint8_t i = 0;
        do {
            X509 * const x509 = PEM_read_X509(fp, 0, 0, 0);
            if (x509 == 0)
                break;
            tls_certs[i].len = (size_t)i2d_X509(x509, &tls_certs[i].base);
            X509_free(x509);
        } while (i++ < TLS_MAX_CERTS);
        fclose(fp);

        tls_ctx.certificates.count = i;
        tls_ctx.certificates.list = tls_certs;
    }

    if (ticket_store) {
        strncpy(tickets.file_name, ticket_store, MAXPATHLEN);
        tls_ctx.save_ticket = &save_ticket;
        read_tickets();
    } else {
        tls_ctx.encrypt_ticket = &encrypt_ticket;
        tls_ctx.max_early_data_size = 0xffffffff;
        tls_ctx.ticket_lifetime = 60 * 60 * 24;
        tls_ctx.require_dhe_on_psk = 0;
    }

    ensure(ptls_openssl_init_verify_certificate(&verifier, 0) == 0,
           "ptls_openssl_init_verify_certificate");

    static ptls_key_exchange_algorithm_t * key_exchanges[] = {
        &ptls_openssl_secp256r1, &ptls_minicrypto_x25519, 0};

    tls_ctx.cipher_suites = ptls_openssl_cipher_suites;
    tls_ctx.key_exchanges = key_exchanges;
    tls_ctx.on_client_hello = &cb;
    tls_ctx.random_bytes = ptls_openssl_random_bytes;
    tls_ctx.sign_certificate = &sign_cert.super;
    tls_ctx.verify_certificate = &verifier.super;
    tls_ctx.get_time = &ptls_get_time;

    arc4random_buf(cookie, COOKIE_LEN);

    init_ticket_prot();
}


void cleanup_tls_ctx(void)
{
    ptls_aead_free(dec_tckt);
    ptls_aead_free(enc_tckt);
}


static ptls_aead_context_t * __attribute__((nonnull))
which_aead(const struct q_conn * const c,
           const struct w_iov * const v,
           const bool in)
{
    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        if (meta(v).hdr.type == F_LH_0RTT)
            return in ? c->tls.dec_0rtt : c->tls.enc_0rtt;
        return in ? c->tls.dec_hshk : c->tls.enc_hshk;
    }
    return in ? c->tls.dec_1rtt : c->tls.enc_1rtt;
}


#ifndef NDEBUG
#define aead_type(c, a)                                                        \
    (((a) == (c)->tls.dec_1rtt || (a) == (c)->tls.enc_1rtt)                    \
         ? "1-RTT"                                                             \
         : (((a) == (c)->tls.dec_0rtt || (a) == (c)->tls.enc_0rtt)             \
                ? "0-RTT"                                                      \
                : "cleartext"))
#endif


uint16_t dec_aead(struct q_conn * const c,
                  const struct w_iov * v,
                  const uint16_t hdr_len)
{
    ptls_aead_context_t * const aead = which_aead(c, v, true);
    if (aead == 0)
        return 0;

    const size_t len =
        ptls_aead_decrypt(aead, &v->buf[hdr_len], &v->buf[hdr_len],
                          v->len - hdr_len, meta(v).hdr.nr, v->buf, hdr_len);
    if (len == SIZE_MAX) {
        warn(ERR, "AEAD %s decrypt error", aead_type(c, aead));
        return 0;
    }
    warn(DBG, "verifying %lu-byte %s AEAD over [0..%u] in [%u..%u]",
         v->len - len - hdr_len, aead_type(c, aead),
         v->len - (v->len - len - hdr_len) - 1,
         v->len - (v->len - len - hdr_len), v->len - 1);
    return hdr_len + (uint16_t)len;
}


uint16_t enc_aead(struct q_conn * const c,
                  const struct w_iov * v,
                  const struct w_iov * x,
                  const uint16_t hdr_len)
{
    ptls_aead_context_t * const aead = which_aead(c, v, false);
    ensure(aead, "AEAD is null");

    memcpy(x->buf, v->buf, hdr_len); // copy pkt header
    const size_t len =
        ptls_aead_encrypt(aead, &x->buf[hdr_len], &v->buf[hdr_len],
                          v->len - hdr_len, meta(v).hdr.nr, v->buf, hdr_len);
    warn(DBG, "added %lu-byte %s AEAD over [0..%u] in [%u..%u]",
         len + hdr_len - v->len, aead_type(c, aead), v->len - 1, v->len,
         len + hdr_len - 1);
    return hdr_len + (uint16_t)len;
}
