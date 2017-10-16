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

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

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

#define TLS_EXT_TYPE_TRANSPORT_PARAMETERS 26

#define TP_INITIAL_MAX_STREAM_DATA 0x0000
#define TP_INITIAL_MAX_DATA 0x0001
#define TP_INITIAL_MAX_STREAM_ID 0x0002
#define TP_IDLE_TIMEOUT 0x0003
// #define TP_OMIT_CONNECTION_ID 0x0004
// #define TP_MAX_PACKET_SIZE 0x0005
#define TP_STATELESS_RESET_TOKEN 0x0006


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


#define dec_tp(c, var)                                                         \
    do {                                                                       \
        uint16_t l;                                                            \
        dec(l, buf, len, i, 0, "%u");                                          \
        ensure(l == sizeof(var), "valid len");                                 \
        dec((var), buf, len, i, 0, "%u");                                      \
    } while (0)


static int chk_tp(ptls_t * tls __attribute__((unused)),
                  ptls_handshake_properties_t * properties,
                  ptls_raw_extension_t * slots)
{
    ensure(slots[0].type == TLS_EXT_TYPE_TRANSPORT_PARAMETERS, "have tp");
    ensure(slots[1].type == UINT16_MAX, "have end");

    // get connection based on properties pointer
    const struct q_conn * const c =
        (void *)((char *)properties - offsetof(struct q_conn, tls_hshake_prop));

    // set up parsing
    const uint8_t * const buf = slots[0].data.base;
    uint16_t len = (uint16_t)slots[0].data.len;
    uint16_t i = 0;

    if (is_clnt(c))
        i = chk_tp_clnt(c, buf, len, i);
    else
        i = chk_tp_serv(c, buf, len, i);

    uint16_t tpl;
    dec(tpl, buf, len, i, 0, "%u");
    ensure(tpl <= len - i, "tp len is reasonable");
    len = i + tpl;

    while (i < len) {
        uint16_t p;
        dec(p, buf, len, i, 0, "%u");
        switch (p) {
        case TP_INITIAL_MAX_STREAM_DATA: {
            uint32_t
                initial_max_stream_data; // TODO: do something with this info

            dec_tp(c, initial_max_stream_data);
            break;
        }

        case TP_INITIAL_MAX_DATA: {
            uint32_t initial_max_data; // TODO: do something with this info

            dec_tp(c, initial_max_data);
            break;
        }

        case TP_INITIAL_MAX_STREAM_ID: {
            uint32_t initial_max_stream_id; // TODO: do something with this info

            dec_tp(c, initial_max_stream_id);
            break;
        }

        case TP_IDLE_TIMEOUT: {
            uint16_t idle_timeout; // TODO: do something with this info

            dec_tp(c, idle_timeout);
            ensure(idle_timeout <= 600, "valid idle timeout");
            break;
        }

        case TP_STATELESS_RESET_TOKEN: {
            ensure(is_clnt(c), "am client");
            uint16_t l;
            dec(l, buf, len, i, 0, "%u");
            ensure(l == 16, "valid len");
            uint8_t
                stateless_reset_token[16]; // TODO: do something with this info
            memcpy(stateless_reset_token, &buf[i], 16);
            i += 16;
            break;
        }

        default:
            die("unsupported transport parameter 0x%04x", p);
        }
    }

    ensure(i == len, "out of parameters");

    return 0;
}


#define enc_tp(c, tp, var)                                                     \
    do {                                                                       \
        const uint16_t p = (tp);                                               \
        enc((c)->tp_buf, len, i, &p, 0, "%u");                                 \
        const uint16_t l = sizeof(var);                                        \
        enc((c)->tp_buf, len, i, &l, 0, "%u");                                 \
        enc((c)->tp_buf, len, i, &(var), 0, "%u");                             \
    } while (0)


static void init_tp(struct q_conn * const c)
{
    uint16_t i = 0;
    const uint16_t len = sizeof(c->tp_buf);

    if (is_clnt(c)) {
        enc(c->tp_buf, len, i, &c->vers, 0, "0x%08x");
        enc(c->tp_buf, len, i, &c->vers_initial, 0, "0x%08x");
        const uint16_t l = 30; // size of rest of parameters
        enc(c->tp_buf, len, i, &l, 2, "%u");
    } else {
        uint16_t l = ok_vers_len * sizeof(ok_vers[0]);
        enc(c->tp_buf, len, i, &l, 1, "%u");
        for (uint8_t n = 0; n < ok_vers_len; n++)
            enc(c->tp_buf, len, i, &ok_vers[n], 4, "0x%08x");
        l = 50; // size of rest of parameters
        enc(c->tp_buf, len, i, &l, 2, "%u");
    }

    enc_tp(c, TP_IDLE_TIMEOUT, c->idle_timeout);
    enc_tp(c, TP_INITIAL_MAX_DATA, c->initial_max_data);
    enc_tp(c, TP_INITIAL_MAX_STREAM_DATA, c->initial_max_stream_data);
    enc_tp(c, TP_INITIAL_MAX_STREAM_ID, c->initial_max_stream_id);

    if (is_serv(c)) {
        const uint16_t p = TP_STATELESS_RESET_TOKEN;
        enc(c->tp_buf, len, i, &p, 0, "%u");
        const uint16_t l = 16;
        enc(c->tp_buf, len, i, &l, 0, "%u");
        memcpy(&c->tp_buf[i], c->stateless_reset_token, 16);
        i += 16;
    }

    c->tp_ext[0] = (ptls_raw_extension_t){TLS_EXT_TYPE_TRANSPORT_PARAMETERS,
                                          {c->tp_buf, i}};
    c->tp_ext[1] = (ptls_raw_extension_t){UINT16_MAX};

    c->tls_hshake_prop =
        (ptls_handshake_properties_t){.additional_extensions = c->tp_ext,
                                      .collect_extension = filter_tp,
                                      .collected_extensions = chk_tp};
}


void init_tls(struct q_conn * const c)
{
    if (c->tls)
        // we are re-initializing during version negotiation
        ptls_free(c->tls);
    ensure((c->tls = ptls_new(&tls_ctx, is_serv(c))) != 0, "alloc TLS state");
    if (is_clnt(c))
        ensure(ptls_set_server_name(c->tls, c->peer_name,
                                    strlen(c->peer_name)) == 0,
               "ptls_set_server_name");
    init_tp(c);
}


static void __attribute__((nonnull))
conn_setup_1rtt_secret(struct q_conn * const c,
                       ptls_cipher_suite_t * const cipher,
                       ptls_aead_context_t ** aead,
                       uint8_t * const sec,
                       const char * const label,
                       uint8_t is_enc)
{
    int ret = ptls_export_secret(c->tls, sec, cipher->hash->digest_size, label,
                                 ptls_iovec_init(0, 0));
    ensure(ret == 0, "ptls_export_secret");
    *aead = ptls_aead_new(cipher->aead, cipher->hash, is_enc, sec);
    ensure(aead, "ptls_aead_new");
}


#define PTLS_CLNT_LABL "EXPORTER-QUIC client 1-RTT Secret"
#define PTLS_SERV_LABL "EXPORTER-QUIC server 1-RTT Secret"

static void __attribute__((nonnull)) conn_setup_1rtt(struct q_conn * const c)
{
    ptls_cipher_suite_t * const cipher = ptls_get_cipher(c->tls);
    conn_setup_1rtt_secret(c, cipher, &c->in_kp0, c->in_sec,
                           is_clnt(c) ? PTLS_SERV_LABL : PTLS_CLNT_LABL, 0);
    conn_setup_1rtt_secret(c, cipher, &c->out_kp0, c->out_sec,
                           is_clnt(c) ? PTLS_CLNT_LABL : PTLS_SERV_LABL, 1);

    c->state = CONN_STAT_VERS_OK;
    warn(DBG, "%s conn %" PRIx64 " now in state %u", conn_type(c), c->id,
         c->state);
}


uint32_t tls_handshake(struct q_stream * const s)
{
    // get pointer to any received handshake data
    // XXX there is an assumption here that we only have one inbound packet
    struct w_iov * const iv = sq_first(&s->i);
    size_t in_len = iv ? iv->len : 0;

    // allocate a new w_iov
    struct w_iov * ov =
        w_alloc_iov(w_engine(s->c->sock), MAX_PKT_LEN, Q_OFFSET);
    ptls_buffer_init(&meta(ov).tb, ov->buf, ov->len);
    const int ret = ptls_handshake(s->c->tls, &meta(ov).tb, iv ? iv->buf : 0,
                                   &in_len, &s->c->tls_hshake_prop);
    ov->len = (uint16_t)meta(ov).tb.off;
    warn(INF, "TLS handshake: recv %u, gen %u, in_len %lu, ret %u: %.*s",
         iv ? iv->len : 0, ov->len, in_len, ret, ov->len, ov->buf);
    ensure(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS, "TLS error: %u", ret);
    ensure(iv == 0 || iv->len && iv->len == in_len, "TLS data remaining");

    if (iv)
        // the assumption is that ptls_handshake has consumed all stream-0
        // data
        w_free(w_engine(s->c->sock), &s->i);
    else {
        s->c->state = CONN_STAT_VERS_SENT;
        // warn(DBG, "%s conn %" PRIx64 " now in state %u", conn_type(s->c),
        //      s->c->id, s->c->state);
    }

    if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && ov->len != 0)
        // enqueue for TX
        sq_insert_tail(&s->o, ov, next);
    else
        // we are done with the handshake, no need to TX after all
        w_free_iov(w_engine(s->c->sock), ov);

    if (ret == 0)
        conn_setup_1rtt(s->c);

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
