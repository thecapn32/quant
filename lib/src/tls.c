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
#include <inttypes.h>
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
#define htonll htobe64
#elif defined(HAVE_SYS_ENDIAN_H)
// e.g., FreeBSD
#include <sys/endian.h>
#define htonll htobe64
#else
#include <arpa/inet.h>
#endif

#include "conn.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"


struct tls_ticket {
    char * sni;
    char * alpn;
    uint8_t * ticket;
    size_t ticket_len;
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

static const ptls_iovec_t alpn[] = {{(uint8_t *)"hq-09", 5}};
static const size_t alpn_cnt = sizeof(alpn) / sizeof(alpn[0]);

#define TLS_EXT_TYPE_TRANSPORT_PARAMETERS 26

#define TP_INITIAL_MAX_STREAM_DATA 0x0000
#define TP_INITIAL_MAX_DATA 0x0001
#define TP_INITIAL_MAX_STREAM_ID_BIDI 0x0002
#define TP_IDLE_TIMEOUT 0x0003
#define TP_OMIT_CONNECTION_ID 0x0004
#define TP_MAX_PACKET_SIZE 0x0005
#define TP_STATELESS_RESET_TOKEN 0x0006
#define TP_ACK_DELAY_EXPONENT 0x0007
#define TP_INITIAL_MAX_STREAM_ID_UNI 0x0008

#define TP_MAX TP_INITIAL_MAX_STREAM_ID_UNI


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
            dec_tp(&c->tp_peer.max_strm_bidi, sizeof(uint32_t));
            warn(INF, "\tinitial_max_stream_id_bidi = %u",
                 c->tp_peer.max_strm_bidi);
            ensure(is_set(STRM_FL_DIR_UNI, c->tp_peer.max_strm_bidi) == false,
                   "got unidir sid %" PRIu64, c->tp_peer.max_strm_bidi);
            ensure(
                is_set(STRM_FL_INI_SRV, c->tp_peer.max_strm_bidi) != c->is_clnt,
                "illegal initiator for sid %" PRIu64, c->tp_peer.max_strm_bidi);
            break;

        case TP_INITIAL_MAX_STREAM_ID_UNI:
            dec_tp(&c->tp_peer.max_strm_uni, sizeof(uint32_t));
            warn(INF, "\tinitial_max_stream_id_uni = %u",
                 c->tp_peer.max_strm_uni);
            ensure(is_set(STRM_FL_DIR_UNI, c->tp_peer.max_strm_uni),
                   "got bidir sid %" PRIu64, c->tp_peer.max_strm_uni);
            ensure(
                is_set(STRM_FL_INI_SRV, c->tp_peer.max_strm_uni) != c->is_clnt,
                "illegal initiator for sid %" PRIu64, c->tp_peer.max_strm_uni);
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

        case TP_OMIT_CONNECTION_ID: {
            uint16_t dummy;
            dec_tp(&dummy, sizeof(dummy));
            warn(INF, "\tomit_connection_id = true");
            c->omit_cid = true;
            break;
        }

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


static void init_tp(struct q_conn * const c)
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

    // XXX ngtcp2 and picoquic cannot parse omit_connection_id as the last tp
    const struct q_conn * const other = get_conn_by_ipnp(&c->peer, 0);
    if (!other || other->id == c->id)
        enc_tp(c, TP_OMIT_CONNECTION_ID, i, 0); // i not used
    enc_tp(c, TP_IDLE_TIMEOUT, c->tp_local.idle_to, sizeof(uint16_t));
    enc_tp(c, TP_INITIAL_MAX_STREAM_ID_BIDI, c->tp_local.max_strm_bidi,
           sizeof(uint32_t));
    enc_tp(c, TP_INITIAL_MAX_STREAM_DATA, c->tp_local.max_strm_data,
           sizeof(uint32_t));
    enc_tp(c, TP_INITIAL_MAX_DATA, c->tp_local.max_data, sizeof(uint32_t));
    // XXX picoquic cannot parse tack_delay_exponent as the last tp
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
    i = enc(c->tls.tp_buf, len, i, &enc_len, 2, "%u");

    c->tls.tp_ext[0] = (ptls_raw_extension_t){
        TLS_EXT_TYPE_TRANSPORT_PARAMETERS,
        {c->tls.tp_buf, enc_len + enc_len_pos + sizeof(enc_len)}};
    c->tls.tp_ext[1] = (ptls_raw_extension_t){UINT16_MAX};
}


#define QUIC_LABL "QUIC "

static ptls_aead_context_t * init_hshk_secret(struct q_conn * const c
                                              __attribute__((unused)),
                                              ptls_cipher_suite_t * const cs,
                                              uint8_t * const sec, // NOLINT
                                              const char * const label,
                                              uint8_t is_enc)
{
    const ptls_iovec_t secret = {.base = sec, .len = cs->hash->digest_size};
    uint8_t output[PTLS_MAX_SECRET_SIZE];
    ensure(ptls_hkdf_expand_label(cs->hash, output, cs->hash->digest_size,
                                  secret, label, ptls_iovec_init(0, 0),
                                  QUIC_LABL) == 0,
           "ptls_hkdf_expand_label");
    // warn(CRT, "%s handshake secret",
    //      is_enc ? (c->is_clnt ? "clnt" : "serv")
    //             : (c->is_clnt ? "serv" : "clnt"));
    // hexdump(output, cs->hash->digest_size);
    return ptls_aead_new(cs->aead, cs->hash, is_enc, output, QUIC_LABL);
}


#define CLNT_LABL_HSHK "client hs"
#define SERV_LABL_HSHK "server hs"

void init_hshk_prot(struct q_conn * const c)
{
    static uint8_t qv1_salt[] = {0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e,
                                 0xca, 0x1e, 0x9d, 0x36, 0xf3, 0x7f, 0xb2,
                                 0xd4, 0x65, 0x18, 0xc3, 0x66, 0x39};

    const ptls_cipher_suite_t * const cs = &ptls_openssl_aes128gcmsha256;

    uint8_t sec[PTLS_MAX_SECRET_SIZE];
    const ptls_iovec_t salt = {.base = qv1_salt, .len = sizeof(qv1_salt)};

    uint64_t ncid = htonll(c->id);
    const ptls_iovec_t cid = {.base = (uint8_t *)&ncid, .len = sizeof(ncid)};
    ensure(ptls_hkdf_extract(cs->hash, sec, salt, cid) == 0,
           "ptls_hkdf_extract");
    // warn(CRT, "handshake secret");
    // hexdump(sec, PTLS_MAX_SECRET_SIZE);

    c->tls.in_clr = init_hshk_secret(
        c, cs, sec, c->is_clnt ? SERV_LABL_HSHK : CLNT_LABL_HSHK, 0);
    // warn(CRT, "%s iv", c->is_clnt ? "serv" : "clnt");
    // hexdump(c->tls.in_clr->static_iv, c->tls.in_clr->algo->iv_size);

    c->tls.out_clr = init_hshk_secret(
        c, cs, sec, c->is_clnt ? CLNT_LABL_HSHK : SERV_LABL_HSHK, 1);
    // warn(CRT, "%s iv", c->is_clnt ? "clnt" : "serv");
    // hexdump(c->tls.out_clr->static_iv, c->tls.out_clr->algo->iv_size);
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
    if (is_encrypt) {
        warn(INF, "creating new 0-RTT session ticket for %s %s",
             ptls_get_server_name(tls), ptls_get_negotiated_protocol(tls));
    } else {
        warn(INF, "verifying 0-RTT session ticket for %s %s",
             ptls_get_server_name(tls), ptls_get_negotiated_protocol(tls));
    }

    int ret;
    if ((ret = ptls_buffer_reserve(dst, src.len)) != 0)
        return ret;

    // TODO encrypt
    memcpy(dst->base + dst->off, src.base, src.len);
    dst->off += src.len;

    return 0;
}


static int save_ticket_cb(ptls_save_ticket_t * self __attribute__((unused)),
                          ptls_t * tls,
                          ptls_iovec_t src)
{
    warn(NTE, "saving 0-RTT tickets to %s", tickets.file_name);

    FILE * const fp = fopen(tickets.file_name, "wbe");
    ensure(fp, "could not open ticket file %s", tickets.file_name);

    // write git hash
    const uint32_t hash_len = sizeof(QUANT_COMMIT_HASH);
    ensure(fwrite(&hash_len, sizeof(hash_len), 1, fp), "fwrite");
    ensure(fwrite(QUANT_COMMIT_HASH, sizeof(QUANT_COMMIT_HASH), 1, fp),
           "fwrite");

    char * s = strdup(ptls_get_server_name(tls));
    char * a = strdup(ptls_get_negotiated_protocol(tls));
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

    t->ticket_len = src.len;
    t->ticket = calloc(1, t->ticket_len);
    ensure(t->ticket, "calloc");
    memcpy(t->ticket, src.base, src.len);

    // write all tickets
    // XXX this currently dumps the entire cache to file on each connection!
    splay_foreach (t, ticket_splay, &tickets) { // NOLINT
        warn(INF, "writing 0-RTT ticket for %s %s", t->sni, t->alpn);

        size_t len = strlen(t->sni) + 1;
        ensure(fwrite(&len, sizeof(len), 1, fp), "fwrite");
        ensure(fwrite(t->sni, sizeof(*t->sni), len, fp), "fwrite");

        len = strlen(t->alpn) + 1;
        ensure(fwrite(&len, sizeof(len), 1, fp), "fwrite");
        ensure(fwrite(t->alpn, sizeof(*t->alpn), len, fp), "fwrite");

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
    if (c->is_clnt)
        ensure(ptls_set_server_name(c->tls.t, c->peer_name, 0) == 0,
               "ptls_set_server_name");
    init_tp(c);
    if (!c->tls.in_clr)
        init_hshk_prot(c);

    c->tls.tls_hshake_prop = (ptls_handshake_properties_t){
        .additional_extensions = c->tls.tp_ext,
        .collect_extension = filter_tp,
        .collected_extensions = chk_tp,
        .client.negotiated_protocols.list = alpn,
        .client.negotiated_protocols.count = alpn_cnt,
        .client.max_early_data_size = &c->tls.max_early_data};

    // try to find an existing session ticket
    const struct tls_ticket which = {.sni = c->peer_name,
                                     .alpn = (char *)alpn[0].base};
    struct tls_ticket * const t = splay_find(ticket_splay, &tickets, &which);
    if (t) {
        c->tls.tls_hshake_prop.client.session_ticket =
            ptls_iovec_init(t->ticket, t->ticket_len);
        c->try_0rtt = 1;
    }
}


void free_tls(struct q_conn * const c)
{
    if (c->tls.in_0rtt)
        ptls_aead_free(c->tls.in_0rtt);
    if (c->tls.out_0rtt)
        ptls_aead_free(c->tls.out_0rtt);
    if (c->tls.in_1rtt)
        ptls_aead_free(c->tls.in_1rtt);
    if (c->tls.out_1rtt)
        ptls_aead_free(c->tls.out_1rtt);
    if (c->tls.in_clr)
        ptls_aead_free(c->tls.in_clr);
    if (c->tls.out_clr)
        ptls_aead_free(c->tls.out_clr);
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
            const ptls_cipher_suite_t * const cs,
            uint8_t * const sec,
            const char * const label,
            uint8_t is_enc,
            uint8_t is_early)
{
    ensure(ptls_export_secret(t, sec, cs->hash->digest_size, label,
                              ptls_iovec_init(0, 0), is_early) == 0,
           "ptls_export_secret");
    return ptls_aead_new(cs->aead, cs->hash, is_enc, sec, QUIC_LABL);
}


#define LABL_0RTT "EXPORTER-QUIC 0rtt"

void init_0rtt_prot(struct q_conn * const c)
{
    // this can be called multiple times due to version negotiation
    if (c->tls.in_0rtt)
        ptls_aead_free(c->tls.in_0rtt);
    if (c->tls.out_0rtt)
        ptls_aead_free(c->tls.out_0rtt);

    const ptls_cipher_suite_t * const cs = ptls_get_cipher(c->tls.t);
    uint8_t sec[PTLS_MAX_DIGEST_SIZE];
    c->tls.in_0rtt = init_secret(c->tls.t, cs, sec, LABL_0RTT, 0, 1);
    c->tls.out_0rtt = init_secret(c->tls.t, cs, sec, LABL_0RTT, 1, 1);
}


#define CLNT_LABL_1RTT "EXPORTER-QUIC client 1rtt"
#define SERV_LABL_1RTT "EXPORTER-QUIC server 1rtt"


static void __attribute__((nonnull)) init_1rtt_prot(struct q_conn * const c)
{
    const ptls_cipher_suite_t * const cs = ptls_get_cipher(c->tls.t);
    uint8_t sec[PTLS_MAX_DIGEST_SIZE];
    c->tls.in_1rtt = init_secret(
        c->tls.t, cs, sec, c->is_clnt ? SERV_LABL_1RTT : CLNT_LABL_1RTT, 0, 0);
    c->tls.out_1rtt = init_secret(
        c->tls.t, cs, sec, c->is_clnt ? CLNT_LABL_1RTT : SERV_LABL_1RTT, 1, 0);
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
        warn(DBG, "in %u, gen %u, ret %u, left %u", iv ? iv->len : 0, tb.off,
             ret, iv ? iv->len - in_len : 0);
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
    uint32_t hash_len;
    ensure(fread(&hash_len, sizeof(hash_len), 1, fp), "fread");
    uint8_t buf[8192];
    ensure(fread(buf, sizeof(uint8_t), hash_len, fp), "fread");
    if (hash_len != sizeof(QUANT_COMMIT_HASH) ||
        memcmp(buf, QUANT_COMMIT_HASH, hash_len) != 0) {
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

        ensure(fread(&len, sizeof(len), 1, fp), "fread");
        t->ticket_len = len;
        t->ticket = calloc(len, sizeof(*t->ticket));
        ensure(t->ticket, "calloc");
        ensure(fread(t->ticket, sizeof(*t->ticket), len, fp), "fread");

        splay_insert(ticket_splay, &tickets, t);
        warn(INF, "got 0-RTT ticket for %s %s", t->sni, t->alpn);
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
}


static ptls_aead_context_t * __attribute__((nonnull))
which_aead(const struct q_conn * const c,
           const struct w_iov * const v,
           const bool in)
{
    ptls_aead_context_t * aead = 0;
    const uint8_t flags = pkt_flags(v->buf);
    if (is_set(F_LONG_HDR, flags)) {
        if (pkt_type(flags) == F_LH_0RTT)
            aead = in ? c->tls.in_0rtt : c->tls.out_0rtt;
        else
            aead = in ? c->tls.in_clr : c->tls.out_clr;
    } else
        aead = in ? c->tls.in_1rtt : c->tls.out_1rtt;

    ensure(aead, "AEAD null");
    return aead;
}


#ifndef NDEBUG
#define aead_type(c, a)                                                        \
    (((a) == (c)->tls.in_1rtt || (a) == (c)->tls.out_1rtt)                     \
         ? "1-RTT"                                                             \
         : (((a) == (c)->tls.in_0rtt || (a) == (c)->tls.out_0rtt)              \
                ? "0-RTT"                                                      \
                : "cleartext"))
#endif


uint16_t dec_aead(struct q_conn * const c,
                  const struct w_iov * v,
                  const uint16_t hdr_len)
{
    ptls_aead_context_t * const aead = which_aead(c, v, true);
    const size_t len =
        ptls_aead_decrypt(aead, &v->buf[hdr_len], &v->buf[hdr_len],
                          v->len - hdr_len, meta(v).nr, v->buf, hdr_len);
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
    memcpy(x->buf, v->buf, hdr_len); // copy pkt header
    ptls_aead_context_t * const aead = which_aead(c, v, false);
    const size_t len =
        ptls_aead_encrypt(aead, &x->buf[hdr_len], &v->buf[hdr_len],
                          v->len - hdr_len, meta(v).nr, v->buf, hdr_len);
    warn(DBG, "added %lu-byte %s AEAD over [0..%u] in [%u..%u]",
         len + hdr_len - v->len, aead_type(c, aead), v->len - 1, v->len,
         len + hdr_len - 1);
    return hdr_len + (uint16_t)len;
}
