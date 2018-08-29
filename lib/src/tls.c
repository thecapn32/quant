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

#include <assert.h>
#include <bitstring.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

#ifdef PTLS_OPENSSL
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <picotls/openssl.h>
#endif

#include <picotls/minicrypto.h>
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
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "pn.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"


#ifdef PTLS_OPENSSL
#define CIPHER_SUITE ptls_openssl_aes128gcmsha256
#else
#define CIPHER_SUITE ptls_minicrypto_aes128gcmsha256
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

#ifdef PTLS_OPENSSL
static ptls_openssl_sign_certificate_t sign_cert = {0};
static ptls_openssl_verify_certificate_t verifier = {0};
#endif

// client always tries to negotiate first entry
static const ptls_iovec_t alpn[] = {{(uint8_t *)"hq-14", 5},
                                    {(uint8_t *)"hq-13", 5}};
static const size_t alpn_cnt = sizeof(alpn) / sizeof(alpn[0]);

static struct cipher_ctx dec_tckt;
static struct cipher_ctx enc_tckt;

#define COOKIE_LEN 64
static uint8_t cookie[COOKIE_LEN];

static FILE * tls_log_file;

#define TLS_EXT_TYPE_TRANSPORT_PARAMETERS 0xffa5

#define TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 0
#define TP_INITIAL_MAX_DATA 1
#define TP_INITIAL_MAX_BIDI_STREAMS 2
#define TP_IDLE_TIMEOUT 3
// #define TP_PREFERRED_ADDRESS 4
#define TP_MAX_PACKET_SIZE 5
#define TP_STATELESS_RESET_TOKEN 6
#define TP_ACK_DELAY_EXPONENT 7
#define TP_INITIAL_MAX_UNI_STREAMS 8
#define TP_DISABLE_MIGRATION 9
#define TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 10
#define TP_INITIAL_MAX_STREAM_DATA_UNI 11

#define TP_MAX (TP_INITIAL_MAX_STREAM_DATA_UNI + 1)


// quicly shim
#define HKDF_BASE_LABEL "quic "
#define st_quicly_cipher_context_t cipher_ctx
#define quicly_hexdump(a, b, c) hex2str(a, b)
#define QUICLY_DEBUG 0


// from quicly
static void dispose_cipher(struct st_quicly_cipher_context_t * ctx)
{
    if (ctx->aead)
        ptls_aead_free(ctx->aead);
    if (ctx->pne)
        ptls_cipher_free(ctx->pne);
}


// from quicly
static int setup_cipher(struct st_quicly_cipher_context_t * ctx,
                        ptls_aead_algorithm_t * aead,
                        ptls_hash_algorithm_t * hash,
                        int is_enc,
                        const void * secret)
{
    uint8_t pnekey[PTLS_MAX_SECRET_SIZE];
    int ret;

    *ctx = (struct st_quicly_cipher_context_t){NULL};

    if ((ctx->aead = ptls_aead_new(aead, hash, is_enc, secret,
                                   HKDF_BASE_LABEL)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((ret = ptls_hkdf_expand_label(
             hash, pnekey, aead->ctr_cipher->key_size,
             ptls_iovec_init(secret, hash->digest_size), "pn",
             ptls_iovec_init(NULL, 0), HKDF_BASE_LABEL)) != 0)
        goto Exit;
    if ((ctx->pne = ptls_cipher_new(aead->ctr_cipher, is_enc, pnekey)) ==
        NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (QUICLY_DEBUG) {
        char *secret_hex = quicly_hexdump(secret, hash->digest_size, SIZE_MAX),
             *pnekey_hex =
                 quicly_hexdump(pnekey, aead->ctr_cipher->key_size, SIZE_MAX);
        fprintf(stderr, "%s:\n  aead-secret: %s\n  pne-key: %s\n", __func__,
                secret_hex, pnekey_hex);
        // free(secret_hex);
        // free(pnekey_hex);
    }

    ret = 0;
Exit:
    if (ret != 0) {
        if (ctx->aead != NULL) {
            ptls_aead_free(ctx->aead);
            ctx->aead = NULL;
        }
        if (ctx->pne != NULL) {
            ptls_cipher_free(ctx->pne);
            ctx->pne = NULL;
        }
    }
    ptls_clear_memory(pnekey, sizeof(pnekey));
    return ret;
}

// from quicly
static int setup_initial_key(struct st_quicly_cipher_context_t * ctx,
                             ptls_cipher_suite_t * cs,
                             const void * master_secret,
                             const char * label,
                             int is_enc)
{
    uint8_t aead_secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = ptls_hkdf_expand_label(
             cs->hash, aead_secret, cs->hash->digest_size,
             ptls_iovec_init(master_secret, cs->hash->digest_size), label,
             ptls_iovec_init(NULL, 0), HKDF_BASE_LABEL)) != 0)
        goto Exit;
    if ((ret = setup_cipher(ctx, cs->aead, cs->hash, is_enc, aead_secret)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(aead_secret, sizeof(aead_secret));
    return ret;
}


// from quicly
static int setup_initial_encryption(struct st_quicly_cipher_context_t * ingress,
                                    struct st_quicly_cipher_context_t * egress,
                                    ptls_cipher_suite_t ** cipher_suites,
                                    ptls_iovec_t cid,
                                    int is_client)
{
    static const uint8_t salt[] = {0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c,
                                   0x5c, 0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a,
                                   0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38};
    static const char * labels[2] = {"client in", "server in"};
    ptls_cipher_suite_t ** cs;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* find aes128gcm cipher */
    for (cs = cipher_suites;; ++cs) {
        assert(cs != NULL);
        if ((*cs)->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
            break;
    }

    /* extract master secret */
    if ((ret = ptls_hkdf_extract((*cs)->hash, secret,
                                 ptls_iovec_init(salt, sizeof(salt)), cid)) !=
        0)
        goto Exit;

    /* create aead contexts */
    if ((ret = setup_initial_key(ingress, *cs, secret, labels[is_client], 0)) !=
        0)
        goto Exit;
    if ((ret = setup_initial_key(egress, *cs, secret, labels[!is_client], 1)) !=
        0)
        goto Exit;

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
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
    } else {
        warn(INF, "\tSNI = ");
        const char no_sni[] = "NO SNI GIVEN";
        ensure(ptls_set_server_name(tls, no_sni, sizeof(no_sni)) == 0,
               "ptls_set_server_name");
    }


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

    uint32_t vers_initial = 0;
    i = dec(&vers_initial, buf, len, i, sizeof(vers_initial), "0x%08x");

    // parse server versions
    uint8_t n;
    i = dec(&n, buf, len, i, sizeof(n), "%u");
    bool found = false;
    while (n > 0) {
        uint32_t vers = 0;
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

    if (c->vers != vers_initial && vers_supported(vers_initial))
        warn(ERR, "vers_initial 0x%08x is supported - MITM?", vers_initial);

    return i;
}


#define dec_tp(var, w)                                                         \
    do {                                                                       \
        uint16_t l;                                                            \
        i = dec(&l, buf, len, i, sizeof(l), "%u");                             \
        ensure(l == 0 || l == ((w) ? (w) : sizeof(var)), "invalid len %u", l); \
        if (l)                                                                 \
            i = dec(var, buf, len, i, (w) ? (w) : 0, "%u");                    \
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
        err_close(c, ERR_TRANSPORT_PARAMETER, FRAM_TYPE_CRPT,
                  "tp len %u is incorrect", tpl);
        return 1;
    }
    len = i + tpl;

    // keep track of which transport parameters we've seen before
    bitstr_t bit_decl(tp_list, TP_MAX) = {0};

    while (i < len) {
        uint16_t tp = 0;
        i = dec(&tp, buf, len, i, sizeof(tp), "0x%04x");

        // skip unknown TPs
        if (tp >= TP_MAX) {
            uint16_t unknown_len;
            i = dec(&unknown_len, buf, len, i, sizeof(unknown_len), "%u");
            warn(WRN, "skipping unknown tp 0x%04x w/len %u", tp, unknown_len);
            i += unknown_len;
            continue;
        }

        // check if this transport parameter is a duplicate
        if (bit_test(tp_list, tp)) {
            err_close(c, ERR_TRANSPORT_PARAMETER, FRAM_TYPE_CRPT,
                      "tp 0x%04x is a duplicate", tp);
            return 1;
        }

        switch (tp) {
        case TP_INITIAL_MAX_STREAM_DATA_UNI: {
            dec_tp(&c->tp_peer.max_strm_data_uni, sizeof(uint32_t));
            warn(INF, "\tinitial_max_stream_data_uni = %u",
                 c->tp_peer.max_strm_data_uni);
            // apply this parameter to all current non-crypto streams
            struct q_stream * s;
            splay_foreach (s, stream, &c->streams)
                if (s->id >= 0)
                    s->out_data_max = c->tp_peer.max_strm_data_uni;
            break;
        }

        case TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: {
            dec_tp(&c->tp_peer.max_strm_data_bidi_local, sizeof(uint32_t));
            warn(INF, "\tinitial_max_stream_data_bidi_local = %u",
                 c->tp_peer.max_strm_data_bidi_local);
            // apply this parameter to all current non-crypto streams
            struct q_stream * s;
            splay_foreach (s, stream, &c->streams)
                if (s->id >= 0)
                    s->out_data_max = c->tp_peer.max_strm_data_bidi_local;
            break;
        }

        case TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: {
            dec_tp(&c->tp_peer.max_strm_data_bidi_remote, sizeof(uint32_t));
            warn(INF, "\tinitial_max_stream_data_bidi_remote = %u",
                 c->tp_peer.max_strm_data_bidi_remote);
            // apply this parameter to all current non-crypto streams
            struct q_stream * s;
            splay_foreach (s, stream, &c->streams)
                if (s->id >= 0)
                    s->out_data_max = c->tp_peer.max_strm_data_bidi_remote;
            break;
        }

        case TP_INITIAL_MAX_DATA:
            dec_tp(&c->tp_peer.max_data, sizeof(uint32_t));
            warn(INF, "\tinitial_max_data = %u", c->tp_peer.max_data);
            break;

        case TP_INITIAL_MAX_BIDI_STREAMS:
            dec_tp(&c->tp_peer.max_strm_bidi, sizeof(uint16_t));
            c->tp_peer.max_strm_bidi <<= 2;
            c->tp_peer.max_strm_bidi |= c->is_clnt ? 0 : STRM_FL_INI_SRV;
            warn(INF, "\tinitial_max_stream_id_bidi = %u",
                 c->tp_peer.max_strm_bidi);
            break;

        case TP_INITIAL_MAX_UNI_STREAMS:
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

        case TP_DISABLE_MIGRATION: {
            uint16_t dummy;
            dec_tp(&dummy, sizeof(dummy));
            warn(INF, "\tdisable_migration = true");
            c->tp_peer.disable_migration = true;
            break;
        }

        case TP_STATELESS_RESET_TOKEN:
            ensure(c->is_clnt, "am client");
            uint16_t l;
            i = dec(&l, buf, len, i, sizeof(l), "%u");
            ensure(l == sizeof(act_dcid(c)->srt), "valid len");
            memcpy(act_dcid(c)->srt, &buf[i], sizeof(act_dcid(c)->srt));
            warn(INF, "\tstateless_reset_token = %s",
                 hex2str(act_dcid(c)->srt, sizeof(act_dcid(c)->srt)));
            i += sizeof(act_dcid(c)->srt);
            break;

        default:
            die("unsupported transport parameter %u", tp);
        }
    }

    ensure(i == len, "out of parameters");

    return 0;
}


#define enc_tp(c, tp, var, w)                                                  \
    do {                                                                       \
        const uint16_t param = (tp);                                           \
        i = enc((c)->tls.tp_buf, len, i, &param, sizeof(param), 0, "%u");      \
        const uint16_t bytes = (w);                                            \
        i = enc((c)->tls.tp_buf, len, i, &bytes, sizeof(bytes), 0, "%u");      \
        if (w) {                                                               \
            const uint64_t tmp_var = (var);                                    \
            i = enc((c)->tls.tp_buf, len, i, &tmp_var, bytes, 0, "%u");        \
        }                                                                      \
    } while (0)


void init_tp(struct q_conn * const c)
{
    uint16_t i = 0;
    const uint16_t len = sizeof(c->tls.tp_buf);

    if (c->is_clnt) {
        i = enc(c->tls.tp_buf, len, i, &c->vers_initial,
                sizeof(c->vers_initial), 0, "0x%08x");
    } else {
        i = enc(c->tls.tp_buf, len, i, &c->vers, sizeof(c->vers), 0, "0x%08x");
        const uint8_t vl = ok_vers_len * sizeof(ok_vers[0]);
        i = enc(c->tls.tp_buf, len, i, &vl, sizeof(vl), 0, "%u");
        for (uint8_t n = 0; n < ok_vers_len; n++)
            i = enc(c->tls.tp_buf, len, i, &ok_vers[n], sizeof(ok_vers[n]), 0,
                    "0x%08x");
    }

    // keep track of encoded length
    const uint16_t enc_len_pos = i;
    i += sizeof(uint16_t);

    // convert the stream ID number to a count
    const uint16_t max_strm_bidi = (uint16_t)c->tp_local.max_strm_bidi >> 2;
    enc_tp(c, TP_INITIAL_MAX_BIDI_STREAMS, max_strm_bidi, sizeof(uint16_t));

    enc_tp(c, TP_IDLE_TIMEOUT, c->tp_local.idle_to, sizeof(uint16_t));
    enc_tp(c, TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
           c->tp_local.max_strm_data_bidi_remote, sizeof(uint32_t));
    enc_tp(c, TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
           c->tp_local.max_strm_data_bidi_local, sizeof(uint32_t));
    enc_tp(c, TP_INITIAL_MAX_DATA, c->tp_local.max_data, sizeof(uint32_t));
    enc_tp(c, TP_ACK_DELAY_EXPONENT, c->tp_local.ack_del_exp, sizeof(uint8_t));
    enc_tp(c, TP_MAX_PACKET_SIZE, w_mtu(c->w), sizeof(uint16_t));

    if (!c->is_clnt) { // TODO: change in -13
        const uint16_t p = TP_STATELESS_RESET_TOKEN;
        i = enc(c->tls.tp_buf, len, i, &p, 2, 0, "%u");
        const uint16_t w = sizeof(act_scid(c)->srt);
        i = enc(c->tls.tp_buf, len, i, &w, 2, 0, "%u");
        ensure(i + sizeof(act_scid(c)->srt) < len, "tp_buf overrun");
        i = enc_buf(c->tls.tp_buf, len, i, act_scid(c)->srt,
                    sizeof(act_scid(c)->srt));
    }

    // encode length of all transport parameters
    const uint16_t enc_len = i - enc_len_pos - sizeof(enc_len);
    i = enc_len_pos;
    enc(c->tls.tp_buf, len, i, &enc_len, 2, 0, "%u");

    c->tls.tp_ext[0] = (ptls_raw_extension_t){
        TLS_EXT_TYPE_TRANSPORT_PARAMETERS,
        {c->tls.tp_buf, enc_len + enc_len_pos + sizeof(enc_len)}};
    c->tls.tp_ext[1] = (ptls_raw_extension_t){UINT16_MAX};
}


static void init_ticket_prot(void)
{
    const ptls_cipher_suite_t * const cs = &CIPHER_SUITE;
    uint8_t output[PTLS_MAX_SECRET_SIZE] = {0};
    memcpy(output, quant_commit_hash,
           MIN(quant_commit_hash_len, sizeof(output)));
    setup_cipher(&dec_tckt, cs->aead, cs->hash, 0, output);
    setup_cipher(&enc_tckt, cs->aead, cs->hash, 1, output);
    ptls_clear_memory(output, sizeof(output));
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
                                     enc_tckt.aead->algo->tag_size))
        return -1;

    if (is_encrypt) {
        warn(INF, "creating new 0-RTT session ticket for %s conn %s (%s %s)",
             conn_type(c), scid2str(c), ptls_get_server_name(tls),
             ptls_get_negotiated_protocol(tls));

        // prepend git commit hash
        memcpy(dst->base + dst->off, quant_commit_hash, quant_commit_hash_len);
        dst->off += quant_commit_hash_len;

        // prepend ticket id
        arc4random_buf(&tid, sizeof(tid));
        memcpy(dst->base + dst->off, &tid, sizeof(tid));
        dst->off += sizeof(tid);

        // now encrypt ticket
        dst->off += ptls_aead_encrypt(enc_tckt.aead, dst->base + dst->off,
                                      src.base, src.len, tid, 0, 0);

    } else {
        if (src.len < quant_commit_hash_len + sizeof(tid) +
                          dec_tckt.aead->algo->tag_size ||
            memcmp(src.base, quant_commit_hash, quant_commit_hash_len) != 0) {
            warn(WRN,
                 "could not verify 0-RTT session ticket for %s conn %s (%s %s)",
                 conn_type(c), scid2str(c), ptls_get_server_name(tls),
                 ptls_get_negotiated_protocol(tls));
            return -1;
        }
        uint8_t * src_base = src.base + quant_commit_hash_len;
        size_t src_len = src.len - quant_commit_hash_len;

        memcpy(&tid, src_base, sizeof(tid));
        src_base += sizeof(tid);
        src_len -= sizeof(tid);

        const size_t n = ptls_aead_decrypt(dec_tckt.aead, dst->base + dst->off,
                                           src_base, src_len, tid, 0, 0);

        if (n > src_len) {
            warn(
                WRN,
                "could not decrypt 0-RTT session ticket for %s conn %s (%s %s)",
                conn_type(c), scid2str(c), ptls_get_server_name(tls),
                ptls_get_negotiated_protocol(tls));
            return -1;
        }
        dst->off += n;

        warn(INF, "verified 0-RTT session ticket for %s conn %s (%s %s)",
             conn_type(c), scid2str(c), ptls_get_server_name(tls),
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
             scid2str(c), t->sni, t->alpn);

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
        free_tls(c);
    ensure((c->tls.t = ptls_new(&tls_ctx, !c->is_clnt)) != 0, "ptls_new");
    *ptls_get_data_ptr(c->tls.t) = c;
    if (c->is_clnt)
        ensure(ptls_set_server_name(c->tls.t, c->peer_name, 0) == 0,
               "ptls_set_server_name");

    ptls_buffer_init(&c->tls.tls_io, c->tls.tls_io_buf,
                     sizeof(c->tls.tls_io_buf));

    ptls_handshake_properties_t * const hshk_prop = &c->tls.tls_hshake_prop;

    hshk_prop->additional_extensions = c->tls.tp_ext;
    hshk_prop->collect_extension = filter_tp;
    hshk_prop->collected_extensions = chk_tp;

    if (c->is_clnt) {
        hshk_prop->client.negotiated_protocols.list = &alpn[0];
        hshk_prop->client.negotiated_protocols.count = 1;
        hshk_prop->client.max_early_data_size = &c->tls.max_early_data;
    } else {
        // TODO: remove this interop hack eventually
        hshk_prop->server.retry_uses_cookie = 1;
        hshk_prop->server.cookie.key = cookie;
        hshk_prop->server.cookie.additional_data.base = (uint8_t *)&c->peer;
        hshk_prop->server.cookie.additional_data.len = sizeof(c->peer);
        if (ntohs(c->sport) == 4434)
            // TODO handle differently
            // hshk_prop->server.enforce_retry = 1;
            c->tx_rtry = true;
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

    init_prot(c);
}


void free_prot(struct q_conn * const c)
{
    dispose_cipher(&c->pn_init.in);
    dispose_cipher(&c->pn_init.out);
    dispose_cipher(&c->pn_hshk.in);
    dispose_cipher(&c->pn_hshk.out);
    dispose_cipher(&c->pn_data.in[0]);
    dispose_cipher(&c->pn_data.in[1]);
    dispose_cipher(&c->pn_data.out_0rtt);
    dispose_cipher(&c->pn_data.out_1rtt);
}


void free_tls(struct q_conn * const c)
{
    if (c->tls.t)
        ptls_free(c->tls.t);
    ptls_buffer_dispose(&c->tls.tls_io);
    free_prot(c);
}


void init_prot(struct q_conn * const c)
{
    const ptls_iovec_t cid = {
        .base = (uint8_t *)(c->is_clnt ? &act_dcid(c)->id : &act_scid(c)->id),
        .len = c->is_clnt ? act_dcid(c)->len : act_scid(c)->len};
    ptls_cipher_suite_t * cs = &CIPHER_SUITE;
    setup_initial_encryption(&c->pn_init.in, &c->pn_init.out, &cs, cid,
                             c->is_clnt);
}


int tls_io(struct q_stream * const s, struct w_iov * const iv)
{
    struct q_conn * const c = s->c;
    const size_t in_len = iv ? iv->len : 0;
    const epoch_t epoch_in = strm_epoch(s);
    const size_t prev_off = c->tls.tls_io.off;
    const int ret = ptls_handle_message(
        c->tls.t, &c->tls.tls_io, c->tls.epoch_off, epoch_in, iv ? iv->buf : 0,
        in_len, &c->tls.tls_hshake_prop);
    warn(DBG,
         "epoch %u, in %u (off %u), gen %u (%u-%u-%u-%u-%u), ret %u, "
         "left "
         "%u",
         epoch_in, iv ? iv->len : 0, iv ? meta(iv).stream_off : 0,
         c->tls.tls_io.off, c->tls.epoch_off[0], c->tls.epoch_off[1],
         c->tls.epoch_off[2], c->tls.epoch_off[3], c->tls.epoch_off[4], ret,
         iv ? iv->len - in_len : 0);

    if (ret == 0 && c->state != conn_estb) {
        if (ptls_is_psk_handshake(c->tls.t)) {
            if (c->is_clnt)
                c->did_0rtt =
                    c->try_0rtt &&
                    c->tls.tls_hshake_prop.client.early_data_accepted_by_peer;
            else
                c->did_0rtt = 1;
        }

        // TODO handle differently
        // } else if (ret == PTLS_ERROR_STATELESS_RETRY) {
        //     c->needs_tx = c->tx_rtry = true;

    } else if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
        err_close(c, ERR_TLS(PTLS_ERROR_TO_ALERT(ret)), FRAM_TYPE_CRPT,
                  "picotls error %u", ret);
        return ret;
    }

    if (c->tls.tls_io.off > prev_off) {
        // enqueue for TX
        for (epoch_t e = ep_init; e <= ep_data; e++) {
            const size_t out_len =
                c->tls.epoch_off[e + 1] - c->tls.epoch_off[e];
            if (out_len == 0)
                continue;
            struct q_stream * const se = get_stream(c, crpt_strm_id(e));
            if (se->out_data >= out_len)
                continue;
            warn(ERR, "epoch %u: off %u len %u", e, c->tls.epoch_off[e],
                 out_len);
            struct w_iov_sq o = sq_head_initializer(o);
            q_alloc(w_engine(c->sock), &o, (uint32_t)out_len);
            const uint8_t * data = c->tls.tls_io.base + c->tls.epoch_off[e];
            struct w_iov * ov = 0;
            sq_foreach (ov, &o, next) {
                memcpy(ov->buf, data, ov->len);
                data += ov->len;
            }
            sq_concat(&se->out, &o);
        }
        c->needs_tx = true;
    }

    return ret;
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

        ensure(fread(&t->tp, sizeof(t->tp), 1, fp), "fread");
        ensure(fread(&t->vers, sizeof(t->vers), 1, fp), "fread");

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


static void fprinthex(FILE * const fp, const ptls_iovec_t vec)
{
    for (size_t i = 0; i != vec.len; ++i)
        fprintf(fp, "%02x", vec.base[i]);
}


static void log_secret_cb(ptls_log_secret_t * const self
                          __attribute__((unused)),
                          ptls_t * const tls,
                          const char * const label,
                          ptls_iovec_t secret)
{
    fprintf(tls_log_file, "%s ", label);
    fprinthex(tls_log_file, ptls_get_client_random(tls));
    fprintf(tls_log_file, " ");
    fprinthex(tls_log_file, secret);
    fprintf(tls_log_file, "\n");
    fflush(tls_log_file);
}


static int update_traffic_key_cb(ptls_update_traffic_key_t * const self
                                 __attribute__((unused)),
                                 ptls_t * const tls,
                                 const int is_enc,
                                 const size_t epoch,
                                 const void * const secret)
{
    struct q_conn * const c = *ptls_get_data_ptr(tls);
    ptls_cipher_suite_t * const cipher = ptls_get_cipher(c->tls.t);
    struct cipher_ctx * cipher_slot;

    switch (epoch) {
    case 1: // 0-RTT
        cipher_slot = is_enc ? &c->pn_data.out_0rtt : &c->pn_data.in[0];
        break;

    case 2: // handshake
        cipher_slot = is_enc ? &c->pn_hshk.out : &c->pn_hshk.in;
        break;

    case 3: // 1-RTT
        cipher_slot = is_enc ? &c->pn_data.out_1rtt : &c->pn_data.in[1];
        break;

    default:
        die("epoch %u unknown");
    }

    if (is_enc)
        c->tls.epoch_out = (uint8_t)epoch;

    // warn(DBG, "epoch_out %u in %u", c->tls.epoch_out, epoch_in(c));

    return setup_cipher(cipher_slot, cipher->aead, cipher->hash, is_enc,
                        secret);
}


void init_tls_ctx(const char * const cert,
                  const char * const key,
                  const char * const ticket_store,
                  const char * const tls_log,
                  const bool verify_certs
#ifndef PTLS_OPENSSL
                  __attribute__((unused))
#endif
)
{
    if (key) {
#ifdef PTLS_OPENSSL
        FILE * const fp = fopen(key, "rbe");
        ensure(fp, "could not open key %s", key);
        EVP_PKEY * const pkey = PEM_read_PrivateKey(fp, 0, 0, 0);
        fclose(fp);
        ensure(pkey, "failed to load private key");
        ptls_openssl_init_sign_certificate(&sign_cert, pkey);
        EVP_PKEY_free(pkey);
#else
        // XXX ptls_minicrypto_load_private_key() only works for ECDSA keys
        const int ret = ptls_minicrypto_load_private_key(&tls_ctx, key);
        ensure(ret == 0, "could not open key %s", key);
#endif
    }

    if (cert) {
        const int ret = ptls_load_certificates(&tls_ctx, cert);
        ensure(ret == 0, "ptls_load_certificates");
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

    if (tls_log) {
        tls_log_file = fopen(tls_log, "wbe");
        ensure(tls_log_file, "could not open TLS log %s", tls_log);
    }

#ifdef PTLS_OPENSSL
    ensure(ptls_openssl_init_verify_certificate(&verifier, 0) == 0,
           "ptls_openssl_init_verify_certificate");
#endif

    static ptls_key_exchange_algorithm_t * key_exchanges[] = {
#ifdef PTLS_OPENSSL
        &ptls_openssl_secp256r1,
#endif
        &ptls_minicrypto_x25519, 0};
    static ptls_on_client_hello_t on_client_hello = {on_ch};
    static ptls_log_secret_t log_secret = {log_secret_cb};
    static ptls_update_traffic_key_t update_traffic_key = {
        update_traffic_key_cb};

    tls_ctx.cipher_suites =
#ifdef PTLS_OPENSSL
        ptls_openssl_cipher_suites;
#else
        ptls_minicrypto_cipher_suites;
#endif
    tls_ctx.key_exchanges = key_exchanges;
    tls_ctx.on_client_hello = &on_client_hello;
    tls_ctx.update_traffic_key = &update_traffic_key;
    if (tls_log)
        tls_ctx.log_secret = &log_secret;
    tls_ctx.random_bytes =
#ifdef PTLS_OPENSSL
        ptls_openssl_random_bytes;
#else
        ptls_minicrypto_random_bytes;
#endif

#ifdef PTLS_OPENSSL
    tls_ctx.sign_certificate = &sign_cert.super;
    if (verify_certs)
        tls_ctx.verify_certificate = &verifier.super;
#endif
    tls_ctx.get_time = &ptls_get_time;
    tls_ctx.hkdf_label_prefix = HKDF_BASE_LABEL;

    arc4random_buf(cookie, COOKIE_LEN);

    init_ticket_prot();
}


void free_tls_ctx(void)
{
    dispose_cipher(&dec_tckt);
    dispose_cipher(&enc_tckt);

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


const struct cipher_ctx * which_cipher_ctx(const struct q_conn * const c,
                                           const struct w_iov * const v,
                                           const bool in)
{
    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        if (meta(v).hdr.type == F_LH_0RTT)
            return in ? &c->pn_data.in[0] : &c->pn_data.out_0rtt;
        if (meta(v).hdr.type == F_LH_HSHK)
            return in ? &c->pn_hshk.in : &c->pn_hshk.out;
        return in ? &c->pn_init.in : &c->pn_init.out;
    }
    return in ? &c->pn_data.in[1] : &c->pn_data.out_1rtt;
}


#if !defined(NDEBUG) && defined(DEBUG_MARSHALL)
#define aead_type(c, a)                                                        \
    ((a) == (c)->pn_init.in.aead || (a) == (c)->pn_init.out.aead               \
         ? "Initial"                                                           \
         : ((a) == (c)->pn_hshk.in.aead || (a) == (c)->pn_hshk.out.aead        \
                ? "Handshake"                                                  \
                : ((a) == (c)->pn_data.in[0].aead ||                           \
                           (a) == (c)->pn_data.out_0rtt.aead                   \
                       ? "0-RTT"                                               \
                       : "1-RTT")))
#endif


uint16_t dec_aead(const struct q_conn * const c, const struct w_iov * const v)
{
    const struct cipher_ctx * const ctx = which_cipher_ctx(c, v, true);
    if (unlikely(ctx == 0 || ctx->aead == 0))
        return 0;

    const uint16_t hdr_len = meta(v).hdr.hdr_len;
    ensure(meta(v).hdr.hdr_len, "meta(v).hdr.hdr_len");
    const uint16_t len = v->len - hdr_len;
    if (unlikely(hdr_len > v->len))
        return 0;

    const size_t ret =
        ptls_aead_decrypt(ctx->aead, &v->buf[hdr_len], &v->buf[hdr_len], len,
                          meta(v).hdr.nr, v->buf, hdr_len);
    if (unlikely(ret == SIZE_MAX))
        return 0;

#ifdef DEBUG_MARSHALL
    warn(DBG, "dec %s AEAD over [0..%u] in [%u..%u]", aead_type(c, ctx->aead),
         hdr_len + len - AEAD_LEN - 1, hdr_len + len - AEAD_LEN,
         hdr_len + len - 1);
#endif

    return hdr_len + len;
}


uint16_t enc_aead(const struct q_conn * const c,
                  const struct w_iov * const v,
                  const struct w_iov * const x,
                  const uint16_t nr_pos)
{
    const struct cipher_ctx * const ctx = which_cipher_ctx(c, v, false);
    if (unlikely(ctx == 0 || ctx->aead == 0))
        return 0;

    const uint16_t hdr_len = meta(v).hdr.hdr_len;
    ensure(meta(v).hdr.hdr_len, "meta(v).hdr.hdr_len");
    memcpy(x->buf, v->buf, hdr_len); // copy pkt header

    const uint16_t plen = v->len - hdr_len + AEAD_LEN;
    const size_t ret =
        ptls_aead_encrypt(ctx->aead, &x->buf[hdr_len], &v->buf[hdr_len],
                          plen - AEAD_LEN, meta(v).hdr.nr, v->buf, hdr_len);
    if (likely(nr_pos)) {
        // encrypt the packet number
        uint16_t off = nr_pos + 4;
        if (off + AEAD_LEN > x->len)
            off = x->len - AEAD_LEN;
        ptls_cipher_init(ctx->pne, &x->buf[off]);
        ptls_cipher_encrypt(ctx->pne, &x->buf[nr_pos], &x->buf[nr_pos],
                            hdr_len - nr_pos);
#ifdef DEBUG_MARSHALL
        warn(DBG,
             "enc %s AEAD over [0..%u] in [%u..%u]; PNE over "
             "[%u..%u] w/off %u",
             aead_type(c, ctx->aead), hdr_len + plen - AEAD_LEN - 1,
             hdr_len + plen - AEAD_LEN, hdr_len + plen - 1, nr_pos, hdr_len - 1,
             off);
#endif
    }
#ifdef DEBUG_MARSHALL
    else
        warn(DBG, "enc %s AEAD over [0..%u] in [%u..%u]",
             aead_type(c, ctx->aead), hdr_len + plen - AEAD_LEN - 1,
             hdr_len + plen - AEAD_LEN, hdr_len + plen - 1);
#endif
    return hdr_len + (uint16_t)ret;
}


void make_rtry_tok(struct q_conn * const c)
{
    const ptls_cipher_suite_t * const cs = &CIPHER_SUITE;
    c->tok_len = cs->hash->digest_size;
    c->tok = calloc(c->tok_len, sizeof(uint8_t));
    ensure(c->tok, "cannot calloc");
    ptls_calc_hash(cs->hash, c->tok, &c->peer, sizeof(c->peer));
}


bool verify_rtry_tok(const struct q_conn * const c,
                     const struct w_iov * const v)
{
    const ptls_cipher_suite_t * const cs = &CIPHER_SUITE;
    uint8_t buf[PTLS_MAX_DIGEST_SIZE];
    ptls_calc_hash(cs->hash, buf, &c->peer, sizeof(c->peer));
    return memcmp(buf, meta(v).hdr.tok, cs->hash->digest_size) == 0;
}
