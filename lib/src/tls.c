// Copyright (c) 2016-2017, NetApp, Inc.
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

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/param.h>

// IWYU pragma: no_include <picotls/../picotls.h>
#include <picotls/minicrypto.h>
#include <picotls/openssl.h>

#include <warpcore/warpcore.h>

#include "cert.h"
#include "conn.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"


ptls_context_t tls_ctx = {0};

static ptls_minicrypto_secp256r1sha256_sign_certificate_t sign_cert = {0};
static ptls_iovec_t tls_certs = {0};
static ptls_openssl_verify_certificate_t verifier = {0};
static const ptls_iovec_t alpn[] = {{(uint8_t *)"hq-07", 5}};
static const size_t alpn_cnt = sizeof(alpn) / sizeof(alpn[0]);

#define TLS_EXT_TYPE_TRANSPORT_PARAMETERS 26

#define TP_INITIAL_MAX_STREAM_DATA 0x0000
#define TP_INITIAL_MAX_DATA 0x0001
#define TP_INITIAL_MAX_STREAM_ID 0x0002
#define TP_IDLE_TIMEOUT 0x0003
#define TP_OMIT_CONNECTION_ID 0x0004
#define TP_MAX_PACKET_SIZE 0x0005
#define TP_STATELESS_RESET_TOKEN 0x0006


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
        warn(INF, "using clnt-requested SNI %.*s", sni.len, sni.base);
        ensure(ptls_set_server_name(tls, (const char *)sni.base, sni.len) == 0,
               "ptls_set_server_name");
    }

    if (prot_cnt == 0) {
        warn(WRN, "clnt requested no ALPN");
        return 0;
    }

    size_t j;
    for (j = 0; j < alpn_cnt; j++)
        for (size_t i = 0; i < prot_cnt; i++)
            if (memcmp(prot[i].base, alpn[j].base,
                       MIN(prot[i].len, alpn[j].len)) == 0)
                goto done;

    if (j == prot_cnt) {
        warn(CRT, "no client-requested ALPN (incl. %.*s) supported, ignoring",
             prot[0].len, prot[0].base);
        return 0;
    }

done:
    warn(INF, "supporting client-requested ALPN %.*s", alpn[j].len,
         alpn[j].base);

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

    // parse server versions
    uint8_t n;
    dec(n, buf, len, i, 0, "%u");
    bool found = false;
    while (n > 0) {
        uint32_t vers;
        n -= sizeof(vers);
        dec(vers, buf, len, i, 0, "0x%08x");
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

    uint32_t vers;
    dec(vers, buf, len, i, 0, "0x%08x");

    uint32_t vers_initial;
    dec(vers_initial, buf, len, i, 0, "0x%08x");

    ensure(vers == c->vers, "vers 0x%08x found in tp", c->vers);
    ensure(vers_initial == c->vers_initial, "vers_initial 0x%08x found in tp",
           c->vers_initial);

    return i;
}


#define dec_tp(var, w)                                                         \
    do {                                                                       \
        uint16_t l;                                                            \
        dec(l, buf, len, i, 0, "%u");                                          \
        ensure(l == 0 || l == ((w) ? (w) : sizeof(var)), "invalid len %u", l); \
        if (l)                                                                 \
            dec((var), buf, len, i, (w) ? (w) : 0, "%u");                      \
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
    dec(tpl, buf, len, i, 0, "%u");
    ensure(tpl == len - i, "tp len %u is correct", tpl);
    len = i + tpl;

    while (i < len) {
        uint16_t tp;
        dec(tp, buf, len, i, 0, "%u");
        switch (tp) {
        case TP_INITIAL_MAX_STREAM_DATA:
            dec_tp(c->max_stream_data, sizeof(uint32_t));
            // we need to apply this parameter to stream 0
            struct q_stream * const s = get_stream(c, 0);
            s->out_off_max = c->max_stream_data;
            warn(INF, "str %u out_off_max = %u", s->id, s->out_off_max);
            break;

        case TP_INITIAL_MAX_DATA: {
            uint64_t max_data_kb = 0;
            dec_tp(max_data_kb, sizeof(uint32_t));
            c->max_data = max_data_kb << 10;
            break;
        }

        case TP_INITIAL_MAX_STREAM_ID:
            dec_tp(c->max_stream_id, 0);
            break;

        case TP_IDLE_TIMEOUT:
            dec_tp(c->idle_timeout, 0);
            ensure(c->idle_timeout <= 600, "valid idle timeout");
            break;

        case TP_MAX_PACKET_SIZE:
            dec_tp(c->max_packet_size, 0);
            ensure(c->max_packet_size >= 1200 && c->max_packet_size <= 65527,
                   "max_packet_size %u invalid", c->max_packet_size);
            break;

        case TP_OMIT_CONNECTION_ID: {
            uint16_t dummy;
            dec_tp(dummy, 0);
            c->omit_cid = true;
            break;
        }

        case TP_STATELESS_RESET_TOKEN:
            ensure(c->is_clnt, "am client");
            uint16_t l;
            dec(l, buf, len, i, 0, "%u");
            ensure(l == sizeof(c->stateless_reset_token), "valid len");
            memcpy(c->stateless_reset_token, &buf[i],
                   sizeof(c->stateless_reset_token));
            warn(DBG, "dec %u byte%s from [%u..%u] into stateless_reset_token ",
                 l, plural(l), i, i + l);
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
        enc((c)->tls.tp_buf, len, i, &param, 0, "%u");                         \
        const uint16_t bytes = (w);                                            \
        enc((c)->tls.tp_buf, len, i, &bytes, 0, "%u");                         \
        if (w)                                                                 \
            enc((c)->tls.tp_buf, len, i, &(var), bytes, "%u");                 \
    } while (0)


static void init_tp(struct q_conn * const c)
{
    uint16_t i = 0;
    const uint16_t len = sizeof(c->tls.tp_buf);

    if (c->is_clnt) {
        enc(c->tls.tp_buf, len, i, &c->vers, 0, "0x%08x");
        enc(c->tls.tp_buf, len, i, &c->vers_initial, 0, "0x%08x");
    } else {
        const uint16_t vl = ok_vers_len * sizeof(ok_vers[0]);
        enc(c->tls.tp_buf, len, i, &vl, 1, "%u");
        for (uint8_t n = 0; n < ok_vers_len; n++)
            enc(c->tls.tp_buf, len, i, &ok_vers[n], 0, "0x%08x");
    }

    // keep track of encoded length
    const uint16_t enc_len_pos = i;
    i += sizeof(uint16_t);

    // XXX ngtcp2 and picoquic cannot parse omit_connection_id as the last tp
    const struct q_conn * const other = get_conn_by_ipnp(&c->peer, 0);
    if (!other || other->id == c->id)
        enc_tp(c, TP_OMIT_CONNECTION_ID, i, 0); // i not used
    enc_tp(c, TP_IDLE_TIMEOUT, initial_idle_timeout,
           sizeof(initial_idle_timeout));
    enc_tp(c, TP_INITIAL_MAX_STREAM_ID, initial_max_stream_id,
           sizeof(initial_max_stream_id));
    enc_tp(c, TP_INITIAL_MAX_STREAM_DATA, initial_max_stream_data,
           sizeof(uint32_t));
    const uint32_t initial_max_data_kb = (uint32_t)(initial_max_data >> 10);
    enc_tp(c, TP_INITIAL_MAX_DATA, initial_max_data_kb,
           sizeof(initial_max_data_kb));
    enc_tp(c, TP_MAX_PACKET_SIZE, w_mtu(w_engine(c->sock)), sizeof(uint16_t));

    if (!c->is_clnt) {
        const uint16_t p = TP_STATELESS_RESET_TOKEN;
        enc(c->tls.tp_buf, len, i, &p, 0, "%u");
        const uint16_t w = sizeof(c->stateless_reset_token);
        enc(c->tls.tp_buf, len, i, &w, 0, "%u");
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
    enc(c->tls.tp_buf, len, i, &enc_len, 0, "%u");

    c->tls.tp_ext[0] = (ptls_raw_extension_t){
        TLS_EXT_TYPE_TRANSPORT_PARAMETERS,
        {c->tls.tp_buf, enc_len + enc_len_pos + sizeof(enc_len)}};
    c->tls.tp_ext[1] = (ptls_raw_extension_t){UINT16_MAX};
}


#define PTLS_CTXT_CLNT_LABL "tls13 QUIC client cleartext Secret"
#define PTLS_CTXT_SERV_LABL "tls13 QUIC server cleartext Secret"

static ptls_aead_context_t *
init_cleartext_secret(struct q_conn * const c __attribute__((unused)),
                      ptls_cipher_suite_t * const cs,
                      uint8_t * const sec, // NOLINT
                      const char * const label,
                      uint8_t is_enc)
{
    uint8_t lab[255];
    uint16_t i = 0;
    enc(lab, sizeof(lab), i, (const uint16_t *)&cs->hash->digest_size,
        sizeof(uint16_t), "%u");

    const uint8_t lab_len = (uint8_t)strlen(label);
    enc(lab, sizeof(lab), i, &lab_len, 0, "%u");

    memcpy((char *)&lab[i], label, lab_len + 1);
    i += lab_len + 1;

    const ptls_iovec_t inf = {.base = lab, .len = i};
    const ptls_iovec_t prk = {.base = sec, .len = cs->hash->digest_size};

    uint8_t secret[255];
    ensure(ptls_hkdf_expand(cs->hash, secret, cs->hash->digest_size, prk,
                            inf) == 0,
           "HKDF-Expand-Label");

    return ptls_aead_new(cs->aead, cs->hash, is_enc, secret);
}


void init_cleartext_prot(struct q_conn * const c)
{
    static uint8_t qv1_salt[] = {0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e,
                                 0xca, 0x1e, 0x9d, 0x36, 0xf3, 0x7f, 0xb2,
                                 0xd4, 0x65, 0x18, 0xc3, 0x66, 0x39};

    const ptls_cipher_suite_t * const cs = &ptls_openssl_aes128gcmsha256;

    uint8_t sec[PTLS_MAX_SECRET_SIZE];
    const ptls_iovec_t salt = {.base = qv1_salt, .len = sizeof(qv1_salt)};

    uint64_t ncid = htonll(c->id);
    const ptls_iovec_t cid = {.base = (uint8_t *)&ncid, .len = sizeof(ncid)};
    ensure(ptls_hkdf_extract(cs->hash, sec, salt, cid) == 0, "HKDF-Extract");

    c->tls.in_clr = init_cleartext_secret(
        c, cs, sec, c->is_clnt ? PTLS_CTXT_SERV_LABL : PTLS_CTXT_CLNT_LABL, 0);
    c->tls.out_clr = init_cleartext_secret(
        c, cs, sec, c->is_clnt ? PTLS_CTXT_CLNT_LABL : PTLS_CTXT_SERV_LABL, 1);
    ensure(c->tls.in_clr && c->tls.out_clr, "got cleartext secrets");
}


void init_tls(struct q_conn * const c)
{
    if (c->tls.t)
        // we are re-initializing during version negotiation
        ptls_free(c->tls.t);
    ensure((c->tls.t = ptls_new(&tls_ctx, !c->is_clnt)) != 0,
           "alloc TLS state");
    if (c->is_clnt)
        ensure(ptls_set_server_name(c->tls.t, c->peer_name,
                                    strlen(c->peer_name)) == 0,
               "ptls_set_server_name");
    init_tp(c);
    if (!c->tls.in_clr)
        init_cleartext_prot(c);

    c->tls.tls_hshake_prop = (ptls_handshake_properties_t){
        .additional_extensions = c->tls.tp_ext,
        .collect_extension = filter_tp,
        .collected_extensions = chk_tp,
        .client.negotiated_protocols.list = alpn,
        .client.negotiated_protocols.count = alpn_cnt};
}


void free_tls(struct q_conn * const c)
{
    ptls_aead_free(c->tls.in_kp0);
    ptls_aead_free(c->tls.out_kp0);
    ptls_aead_free(c->tls.in_clr);
    ptls_aead_free(c->tls.out_clr);
    ptls_free(c->tls.t);
}


static ptls_aead_context_t * __attribute__((nonnull))
init_1rtt_secret(ptls_t * const t,
                 const ptls_cipher_suite_t * const cs,
                 uint8_t * const sec,
                 const char * const label,
                 uint8_t is_enc)
{
    ensure(ptls_export_secret(t, sec, cs->hash->digest_size, label,
                              ptls_iovec_init(0, 0)) == 0,
           "ptls_export_secret");
    return ptls_aead_new(cs->aead, cs->hash, is_enc, sec);
}


#define PTLS_1RTT_CLNT_LABL "EXPORTER-QUIC client 1-RTT Secret"
#define PTLS_1RTT_SERV_LABL "EXPORTER-QUIC server 1-RTT Secret"

static void __attribute__((nonnull)) init_1rtt_prot(struct q_conn * const c)
{
    if (c->tls.in_kp0) {
        // tls_handshake() is called multiple times when generating CHs
        ptls_aead_free(c->tls.in_kp0);
        ptls_aead_free(c->tls.out_kp0);
    }

    const ptls_cipher_suite_t * const cs = ptls_get_cipher(c->tls.t);
    c->tls.in_kp0 = init_1rtt_secret(
        c->tls.t, cs, c->tls.in_sec,
        c->is_clnt ? PTLS_1RTT_SERV_LABL : PTLS_1RTT_CLNT_LABL, 0);
    c->tls.out_kp0 = init_1rtt_secret(
        c->tls.t, cs, c->tls.out_sec,
        c->is_clnt ? PTLS_1RTT_CLNT_LABL : PTLS_1RTT_SERV_LABL, 1);
    c->state = CONN_STAT_VERS_OK;
}


uint32_t tls_handshake(struct q_stream * const s)
{
    int ret = 0;
    struct w_iov * iv = sq_first(&s->in);

    if (!iv)
        s->c->state = CONN_STAT_VERS_SENT;

    do {
        // allocate a new w_iov for potential outbound handshake data
        struct w_iov * ov =
            q_alloc_iov(w_engine(s->c->sock), MAX_PKT_LEN, Q_OFFSET);
        ptls_buffer_t tb;
        ptls_buffer_init(&tb, ov->buf, ov->len);

        const uint16_t in_data_len = iv ? stream_data_len(iv) : 0;
        size_t in_len = in_data_len;
        ret = ptls_handshake(s->c->tls.t, &tb,
                             iv ? &iv->buf[meta(iv).stream_data_start] : 0,
                             &in_len, &s->c->tls.tls_hshake_prop);
        ov->len = (uint16_t)tb.off;
        warn(DBG, "in %u, gen %u into idx %u, ret %u", iv ? in_data_len : 0,
             ov->len, ov->idx, ret);
        ensure(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS, "TLS error: %u", ret);
        ensure(iv == 0 || in_data_len && in_data_len == in_len, "data left");

        if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && ov->len != 0)
            // enqueue for TX
            sq_insert_tail(&s->out, ov, next);
        else
            // we are done with the handshake, no need to TX after all
            q_free_iov(w_engine(s->c->sock), ov);

        if (ret == 0)
            init_1rtt_prot(s->c);

        iv = iv ? sq_next(iv, next) : 0;
    } while (iv);

    return (uint32_t)ret;
}


void init_tls_ctx(void)
{
    // warn(DBG, "TLS: key %u byte%s, cert %u byte%s", tls_key_len,
    //      plural(tls_key_len), tls_cert_len, plural(tls_cert_len));
    tls_ctx.random_bytes = ptls_minicrypto_random_bytes;

    // allow secp256r1 and x25519
    static ptls_key_exchange_algorithm_t * my_own_key_exchanges[] = {
        &ptls_minicrypto_secp256r1, &ptls_minicrypto_x25519, NULL};

    tls_ctx.key_exchanges = my_own_key_exchanges;
    tls_ctx.cipher_suites = ptls_minicrypto_cipher_suites;
    tls_ctx.on_client_hello = &cb;

    ensure(ptls_minicrypto_init_secp256r1sha256_sign_certificate(
               &sign_cert, ptls_iovec_init(tls_key, tls_key_len)) == 0,
           "ptls_minicrypto_init_secp256r1sha256_sign_certificate");
    tls_ctx.sign_certificate = &sign_cert.super;

    tls_certs = ptls_iovec_init(tls_cert, tls_cert_len);
    tls_ctx.certificates.list = &tls_certs;
    tls_ctx.certificates.count = 1;

    ensure(ptls_openssl_init_verify_certificate(&verifier, 0) == 0,
           "ptls_openssl_init_verify_certificate");
    tls_ctx.verify_certificate = &verifier.super;
}


uint16_t dec_aead(struct q_conn * const c,
                  const struct w_iov * v,
                  const uint16_t hdr_len)
{
    ptls_aead_context_t * aead = c->tls.in_kp0;
    const uint8_t flags = pkt_flags(v->buf);
    if (is_set(F_LONG_HDR, flags) && pkt_type(flags) >= F_LH_CLNT_INIT &&
        pkt_type(flags) <= F_LH_CLNT_CTXT)
        aead = c->tls.in_clr;

    const size_t len =
        ptls_aead_decrypt(aead, &v->buf[hdr_len], &v->buf[hdr_len],
                          v->len - hdr_len, meta(v).nr, v->buf, hdr_len);
    if (len == SIZE_MAX)
        return 0; // AEAD decrypt error
    warn(DBG, "verifying %lu-byte %s AEAD over [0..%u] in [%u..%u]",
         v->len - len - hdr_len, aead == c->tls.in_kp0 ? "1RTT" : "cleartext",
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
    const size_t len = ptls_aead_encrypt(
        c->state >= CONN_STAT_ESTB ? c->tls.out_kp0 : c->tls.out_clr,
        &x->buf[hdr_len], &v->buf[hdr_len], v->len - hdr_len, meta(v).nr,
        v->buf, hdr_len);
    warn(DBG, "added %lu-byte %s AEAD over [0..%u] in [%u..%u]",
         len + hdr_len - v->len,
         c->state >= CONN_STAT_ESTB ? "1RTT" : "cleartext", v->len - 1, v->len,
         len + hdr_len - 1);
    return hdr_len + (uint16_t)len;
}
