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
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <picotls.h> // IWYU pragma: keep
// IWYU pragma: no_include <picotls/../picotls.h>
#include <picotls/minicrypto.h>
#include <picotls/openssl.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#include <ev.h>
#pragma clang diagnostic pop

#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "cert.h"
#include "conn.h"
#include "diet.h"
#include "quic.h"
#include "stream.h"


// TODO: many of these globals should move to a per-engine struct


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
    // 0xff000004, // draft-ietf-quic-transport-04
    0xff000005, // draft-ietf-quic-transport-05
};

/// Length of the @p ok_vers array.
const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


struct pkt_meta * pm = 0;
struct ev_loop * loop = 0;
ptls_context_t tls_ctx = {0};

func_ptr api_func = 0;
void * api_arg = 0;

static const uint32_t nbufs = 1000; ///< Number of packet buffers to allocate.

static ptls_minicrypto_secp256r1sha256_sign_certificate_t sign_cert = {0};
static ptls_iovec_t tls_certs = {0};
static ptls_openssl_verify_certificate_t verifier = {0};


/// Run the event loop with the API function @p func and argument @p arg.
///
/// @param      func  The active API function.
/// @param      arg   The argument of the currently active API function.
///
#define loop_run(func, arg)                                                    \
    do {                                                                       \
        api_func = (func_ptr)(&(func));                                        \
        api_arg = (arg);                                                       \
        warn(info, #func "(" #arg ") entering event loop");                    \
        ev_run(loop, 0);                                                       \
    } while (0)


static struct q_conn * new_conn(struct w_engine * const w,
                                const uint64_t cid,
                                const struct sockaddr_in * const peer,
                                const char * const peer_name,
                                const uint16_t port)
{
    // TODO: check if connection still exists
    struct q_conn * const c = calloc(1, sizeof(*c));
    ensure(c, "could not calloc");

    if (peer)
        c->peer = *peer;
    c->id = cid;

    // initialize LD state
    // XXX: UsingTimeLossDetection not defined?
    c->ld_alarm.data = c;
    ev_init(&c->ld_alarm, ld_alarm);
    c->reorder_thresh = kReorderingThreshold;
    c->reorder_fract = HUGE_VAL;
    c->lg_sent = peer_name ? 8000 : 1000; // TODO: randomize initial pkt nr

    // initialize CC state
    c->cwnd = kInitialWindow;
    c->ssthresh = UINT64_MAX;

    c->flags = CONN_FLAG_EMBR | (peer_name ? CONN_FLAG_CLNT : 0);
    STAILQ_INIT(&c->sent_pkts);
    SPLAY_INIT(&c->streams);
    diet_init(&c->closed_streams);
    diet_init(&c->acked_pkts);
    diet_init(&c->recv);

    // initialize TLS state
    ensure((c->tls = ptls_new(&tls_ctx, peer_name == 0)) != 0,
           "alloc TLS state");
    if (peer_name)
        ensure(ptls_set_server_name(c->tls, peer_name, strlen(peer_name)) == 0,
               "ptls_set_server_name");

    // initialize socket and start an RX/TX watchers
    ev_async_init(&c->tx_w, tx);
    c->tx_w.data = c;
    ev_async_start(loop, &c->tx_w);
    c->sock = w_bind(w, htons(port), 0);
    ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);
    c->rx_w.data = c->sock;
    ev_io_start(loop, &c->rx_w);

    // add connection to global data structures
    SPLAY_INSERT(ipnp_splay, &conns_by_ipnp, c);
    SPLAY_INSERT(cid_splay, &conns_by_cid, c);

    warn(debug, "%s conn created", conn_type(c));
    return c;
}


void q_alloc(void * const w, struct w_iov_stailq * const q, const uint32_t len)
{
    w_alloc_len(w, q, len, Q_OFFSET);
}


void q_free(void * const w, struct w_iov_stailq * const q)
{
    w_free((struct w_engine *)w, q);
}


struct q_conn * q_connect(void * const q,
                          const struct sockaddr_in * const peer,
                          const char * const peer_name)
{
    // make new connection
    const uint64_t cid =
        ((((uint64_t)plat_random()) << 32) | ((uint64_t)plat_random()));
    warn(warn, "connecting embr clnt conn %" PRIx64, cid);
    struct q_conn * const c = new_conn(q, cid, peer, peer_name, 0);
    // c->vers = 0xbabababa; // XXX reserved version to trigger negotiation
    c->vers = ok_vers[0];
    c->next_sid = 1; // client initiates odd-numbered streams
    w_connect(c->sock,
              ((const struct sockaddr_in *)(const void *)peer)->sin_addr.s_addr,
              ((const struct sockaddr_in *)(const void *)peer)->sin_port);

    // allocate stream zero and start TLS handshake on stream 0
    struct q_stream * const s = new_stream(c, 0);
    tls_handshake(s);
    ev_async_send(loop, &c->tx_w);

    warn(warn, "waiting for connect to complete on %s conn %" PRIx64,
         conn_type(c), c->id);
    loop_run(q_connect, c);

    if (c->state != CONN_STAT_ESTB) {
        warn(warn, "%s conn %" PRIx64 " not connected, state 0x%02x",
             conn_type(c), cid, c->state);
        return 0;
    }

    warn(warn, "%s conn %" PRIx64 " connected", conn_type(c), cid);
    return c;
}


void q_write(struct q_stream * const s, struct w_iov_stailq * const q)
{
    const uint32_t qlen = w_iov_stailq_len(q);
    warn(warn, "writing %u byte%s on %s conn %" PRIx64 " str %u", qlen,
         plural(qlen), conn_type(s->c), s->c->id, s->id);

    STAILQ_CONCAT(&s->o, q);
    s->state = STRM_STATE_OPEN;

    // kick TX watcher
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_write, s);

    // return written data back to user stailq
    STAILQ_CONCAT(q, &s->r);

    warn(warn, "wrote %u byte%s on %s conn %" PRIx64 " str %u", qlen,
         plural(qlen), conn_type(s->c), s->c->id, s->id);

    ensure(w_iov_stailq_len(q) == qlen, "payload corrupted, %u != %u",
           w_iov_stailq_len(q), qlen);
}


struct q_stream * q_read(struct q_conn * const c, struct w_iov_stailq * const q)
{
    warn(warn, "reading on %s conn %" PRIx64, conn_type(c), c->id);
    struct q_stream * s = 0;

    while (s == 0) {
        SPLAY_FOREACH (s, stream, &c->streams) {
            if (s->id == 0)
                // don't deliver stream-zero data
                continue;
            if (!STAILQ_EMPTY(&s->i))
                // we found a stream with queued data
                break;
        }

        if (s == 0) {
            // no data queued on any non-zero stream, we need to wait
            warn(warn, "waiting for data on %s conn %" PRIx64, conn_type(c),
                 c->id);
            loop_run(q_read, c);
        }
    }

    // return data
    STAILQ_CONCAT(q, &s->i);
    warn(warn, "read %u byte%s on %s conn %" PRIx64 " str %u",
         w_iov_stailq_len(&s->i), plural(w_iov_stailq_len(&s->i)),
         conn_type(s->c), s->c->id, s->id);
    return s;
}


struct q_conn * q_bind(void * const q, const uint16_t port)
{
    // bind socket and create new embryonic server connection
    warn(warn, "binding serv socket on port %u", port);
    struct q_conn * const c = new_conn(q, 0, 0, 0, port);
    warn(warn, "bound %s socket on port %u", conn_type(c), port);
    return c;
}


struct q_conn * q_accept(struct q_conn * const c)
{
    if (c->state >= CONN_STAT_ESTB) {
        warn(warn, "got %s conn %" PRIx64, conn_type(c), c->id);
        return c;
    }

    warn(warn, "waiting for accept on %s conn", conn_type(c));
    loop_run(q_accept, c);

    if (c->id == 0) {
        warn(warn, "conn not accepted");
        // TODO free embryonic connection
        return 0;
    }

    warn(warn, "%s conn %" PRIx64 " connected", conn_type(c), c->id);
    return c;
}


struct q_stream * q_rsv_stream(struct q_conn * const c)
{

    const uint8_t odd = c->next_sid % 2; // NOTE: % in assert confuses printf
    ensure(is_clnt(c) && odd, "am %s, expected %s connection stream ID, got %u",
           conn_type(c), is_clnt(c) ? "odd" : "even", c->next_sid);
    return new_stream(c, c->next_sid);
}


void * q_init(const char * const ifname)
{
    // check versions
    // ensure(WARPCORE_VERSION_MAJOR == 0 && WARPCORE_VERSION_MINOR == 12,
    //        "%s version %s not compatible with %s version %s", quant_name,
    //        quant_version, warpcore_name, warpcore_version);

    // init connection structures
    SPLAY_INIT(&conns_by_ipnp);
    SPLAY_INIT(&conns_by_cid);

    // initialize warpcore on the given interface
    void * const w = w_init(ifname, 0, nbufs);
    pm = calloc(nbufs, sizeof(*pm));
    ensure(pm, "could not calloc");

    // initialize PRNG
    plat_initrandom();

    // initialize TLS context
    // warn(debug, "TLS: key %u byte%s, cert %u byte%s", tls_key_len,
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
    // XXX setting this makes the TLS handshake fail on the client?
    // tls_ctx.verify_certificate = &verifier.super;

    // initialize the event loop
    loop = ev_default_loop(0);

    warn(info, "%s %s with libev %u.%u ready", quant_name, quant_version,
         ev_version_major(), ev_version_minor());

    return w;
}


void q_close_stream(struct q_stream * const s)
{
    warn(warn, "closing str %u on %s conn %" PRIx64, s->id, conn_type(s->c),
         s->c->id);

    if (s->state == STRM_STATE_IDLE) {
        warn(warn, "%s conn %" PRIx64 " str %u already closed", conn_type(s->c),
             s->c->id, s->id);
        free_stream(s);
        return;
    }

    if (s->state <= STRM_STATE_OPEN) {
        warn(debug, "half-closing str %u on %s conn %" PRIx64, s->id,
             conn_type(s->c), s->c->id);
        s->state = STRM_STATE_HCLO;
    } else {
        warn(debug, "str %u on %s conn %" PRIx64 " already HCRM, now CLSD",
             s->id, conn_type(s->c), s->c->id);
        s->state = STRM_STATE_CLSD;
    }

    ev_async_send(loop, &s->c->tx_w);

    if (s->state != STRM_STATE_IDLE) {
        warn(warn, "waiting for close on %s conn %" PRIx64 " str %u",
             conn_type(s->c), s->c->id, s->id);
        loop_run(q_close_stream, s);
    }

    warn(warn, "%s conn %" PRIx64 " str %u closed", conn_type(s->c), s->c->id,
         s->id);
    free_stream(s);
}


void q_close(struct q_conn * const c)
{
    warn(warn, "closing %s conn %" PRIx64, conn_type(c), c->id);

    // close all streams
    struct q_stream *s, *tmp;
    for (s = SPLAY_MAX(stream, &c->streams); s; s = tmp) {
        tmp = SPLAY_PREV(stream, &c->streams, s);
        q_close_stream(s);
    }

    ev_io_stop(loop, &c->rx_w);
    ev_timer_stop(loop, &c->ld_alarm);

    diet_free(&c->closed_streams);
    diet_free(&c->acked_pkts);
    diet_free(&c->recv);
    ptls_free(c->tls);
    if (c->sock)
        w_close(c->sock);

    // remove connection from global lists
    SPLAY_REMOVE(ipnp_splay, &conns_by_ipnp, c);
    SPLAY_REMOVE(cid_splay, &conns_by_cid, c);

    warn(warn, "%s conn %" PRIx64 " closed", conn_type(c), c->id);
    free(c);
}


void q_cleanup(void * const q)
{
    // close all connections
    struct q_conn *c, *tmp;
    for (c = SPLAY_MIN(ipnp_splay, &conns_by_ipnp); c != 0; c = tmp) {
        tmp = SPLAY_NEXT(ipnp_splay, &conns_by_ipnp, c);
        q_close(c);
    }
    for (c = SPLAY_MIN(cid_splay, &conns_by_cid); c != 0; c = tmp) {
        tmp = SPLAY_NEXT(cid_splay, &conns_by_cid, c);
        q_close(c);
    }

    // stop the event loop
    ev_loop_destroy(loop);

    free(pm);
    w_cleanup(q);
}


uint64_t q_cid(const struct q_conn * const c)
{
    return c->id;
}


uint32_t q_sid(const struct q_stream * const s)
{
    return s->id;
}
