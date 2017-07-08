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
#include <pthread.h>
#include <signal.h>
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
#include "thread.h"


// TODO: many of these globals should move to a per-engine struct

struct sockaddr;
struct ev_loop;

/// Number of packet buffers to allocate.
static const uint32_t nbufs = 1000;
struct pkt_meta * pm = 0;
static ev_async loop_update_w;


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
    0xff000004 // draft-ietf-quic-transport-04
};

const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


static struct ev_loop * loop = 0;
static pthread_mutex_t loop_lock;

static pthread_t tid = {0};
ptls_context_t tls_ctx = {0};

static ptls_minicrypto_secp256r1sha256_sign_certificate_t sign_cert = {0};
static ptls_iovec_t tls_certs = {0};
static ptls_openssl_verify_certificate_t verifier = {0};


static struct q_conn * new_conn(struct w_engine * const w,
                                const char * const peer_name,
                                const uint16_t port)
{
    struct q_conn * c = get_conn(0, peer_name == 0);
    ensure(c == 0, "embryonic %s conn %" PRIx64 " already exists",
           peer_name ? "client" : "server", c->id);

    c = calloc(1, sizeof(*c));
    ensure(c, "could not calloc");

    // initialize LD state
    // XXX: UsingTimeLossDetection not defined?
    c->ld_alarm.data = c;
    ev_init(&c->ld_alarm, ld_alarm);
    c->reorder_thresh = kReorderingThreshold;
    c->reorder_fract = HUGE_VAL;

    // initialize CC state
    c->cwnd = kInitialWindow;
    c->ssthresh = UINT64_MAX;

    c->flags = (peer_name ? CONN_FLAG_CLNT : 0) | CONN_FLAG_EMBR;
    STAILQ_INIT(&c->sent_pkts);
    SPLAY_INIT(&c->streams);

    // initialize TLS state
    ensure((c->tls = ptls_new(&tls_ctx, peer_name == 0)) != 0,
           "alloc TLS state");
    if (peer_name)
        ensure(ptls_set_server_name(c->tls, peer_name, strlen(peer_name)) == 0,
               "ptls_set_server_name");

    // initialize synchronization helpers
    ensure(pthread_mutex_init(&c->lock, 0) == 0, "pthread_mutex_init");
    ensure(pthread_cond_init(&c->close_cv, 0) == 0, "pthread_cond_init");
    ensure(pthread_cond_init(&c->read_cv, 0) == 0, "pthread_cond_init");
    ensure(pthread_cond_init(&c->write_cv, 0) == 0, "pthread_cond_init");
    ensure(pthread_cond_init(&c->connect_cv, 0) == 0, "pthread_cond_init");
    ensure(pthread_cond_init(&c->accept_cv, 0) == 0, "pthread_cond_init");

    // initialize socket and start an RX/TX watchers
    ev_async_init(&c->tx_w, tx);
    c->tx_w.data = c;
    ev_async_start(loop, &c->tx_w);
    c->sock = w_bind(w, htons(port), 0);
    ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);
    c->rx_w.data = c->sock;
    ev_io_start(loop, &c->rx_w);

    // add connection to global data structure
    lock(&q_conns_lock);
    SPLAY_INSERT(conn, &q_conns, c);
    unlock(&q_conns_lock);

    warn(debug, "embryonic %s conn created", peer_name ? "client" : "server");
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
                          const struct sockaddr * const peer,
                          const socklen_t peer_len,
                          const char * const peer_name)
{
    // make new connection (connection ID must be > 0 for us)
    const uint64_t cid =
        ((((uint64_t)plat_random()) << 32) | ((uint64_t)plat_random()));
    struct q_conn * const c = new_conn(q, peer_name, 0);
    init_conn(c, cid, peer, peer_len);
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

    warn(warn, "waiting for connect to complete on conn %" PRIx64, c->id);
    lock(&c->lock);
    wait(&c->connect_cv, &c->lock);
    unlock(&c->lock);

    if (c->state != CONN_ESTB) {
        warn(warn, "conn %" PRIx64 " not connected", cid);
        return 0;
    }

    warn(warn, "conn %" PRIx64 " connected", cid);
    return c;
}


void q_write(struct q_conn * const c,
             struct q_stream * const s,
             struct w_iov_stailq * const q)
{
    const uint32_t qlen = w_iov_stailq_len(q);
    warn(warn, "waiting for %u-byte write to complete", qlen);
    lock(&c->lock);
    STAILQ_CONCAT(&s->o, q);
    s->state = STRM_OPEN;

    // kick TX watcher
    ev_async_send(loop, &c->tx_w);

    wait(&c->write_cv, &c->lock);

    // return written data back to user stailq
    STAILQ_CONCAT(q, &s->r);
    unlock(&c->lock);
    warn(warn, "write done");
    ensure(w_iov_stailq_len(q) == qlen, "payload corrupted");
}


struct q_stream * q_read(struct q_conn * const c, struct w_iov_stailq * const i)
{
    struct q_stream * s = 0;
    warn(warn, "waiting for data");
    lock(&c->lock);
    wait(&c->read_cv, &c->lock);
    unlock(&c->lock);

    SPLAY_FOREACH (s, stream, &c->streams)
        if (!STAILQ_EMPTY(&s->i)) {
#ifndef NDEBUG
            const uint32_t in_len = w_iov_stailq_len(&s->i);
            warn(info, "buffered %u byte%s on str %u", in_len, plural(in_len),
                 s->id);
#endif
            break;
        }
    if (s == 0)
        return 0;

    // return data
    STAILQ_CONCAT(i, &s->i);
    warn(warn, "read done");
    return s;
}


struct q_conn * q_bind(void * const q, const uint16_t port)
{
    // bind socket and create new embryonic server connection
    struct q_conn * const c = new_conn(q, 0, port);
    warn(warn, "bound %s socket on port %u",
         is_set(CONN_FLAG_CLNT, c->flags) ? "¯client" : "server", port);
    return c;
}


struct q_conn * q_accept(struct q_conn * const c)
{
    if (c->state >= CONN_ESTB) {
        warn(warn, "got conn %" PRIx64, c->id);
        return c;
    }

    warn(warn, "waiting for accept to complete embryonic server conn");
    ev_async_send(loop, &loop_update_w);
    lock(&c->lock);
    wait(&c->accept_cv, &c->lock);
    unlock(&c->lock);

    if (c->id == 0) {
        warn(warn, "conn not accepted");
        // TODO free embryonic connection
        return 0;
    }

    warn(warn, "conn %" PRIx64 " connected", c->id);
    return c;
}


struct q_stream * q_rsv_stream(struct q_conn * const c)
{

    const uint8_t odd = c->next_sid % 2; // NOTE: % in assert confuses printf
    ensure(is_set(CONN_FLAG_CLNT, c->flags) && odd,
           "am %s, expected %s connection stream ID, got %u",
           is_set(CONN_FLAG_CLNT, c->flags) ? "client" : "server",
           is_set(CONN_FLAG_CLNT, c->flags) ? "odd" : "even", c->next_sid);
    return new_stream(c, c->next_sid);
}


static void l_release(struct ev_loop * const l __attribute__((unused)))
{
    unlock(&loop_lock);
}


static void l_acquire(struct ev_loop * const l __attribute__((unused)))
{
    lock(&loop_lock);
}


void * q_init(const char * const ifname)
{
    // check versions
    // ensure(WARPCORE_VERSION_MAJOR == 0 && WARPCORE_VERSION_MINOR == 12,
    //        "%s version %s not compatible with %s version %s", quant_name,
    //        quant_version, warpcore_name, warpcore_version);

    // initialize warpcore on the given interface
    void * const w = w_init(ifname, 0, nbufs);
    pm = calloc(nbufs, sizeof(*pm));
    ensure(pm, "could not calloc");

    // initialize PRNG
    plat_initrandom();

    // initialize mutexes, etc.
    ensure(pthread_mutex_init(&q_conns_lock, 0) == 0, "pthread_mutex_init");

    // initialize TLS context
    warn(debug, "TLS: key %u byte%s, cert %u byte%s", tls_key_len,
         plural(tls_key_len), tls_cert_len, plural(tls_cert_len));
    tls_ctx.random_bytes = ptls_minicrypto_random_bytes;
    tls_ctx.key_exchanges = ptls_minicrypto_key_exchanges;
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

    // block those signals that we'll let the event loop handle
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTERM);
    ensure(pthread_sigmask(SIG_BLOCK, &set, 0) == 0, "pthread_sigmask");

    // initialize the event loop
    loop = ev_default_loop(0);
    ensure(pthread_mutex_init(&loop_lock, 0) == 0, "pthread_mutex_init");
    ev_set_userdata(loop, &loop_lock);
    ev_set_loop_release_cb(loop, l_release, l_acquire);
    ev_async_init(&loop_update_w, loop_update);
    ev_async_start(loop, &loop_update_w);

    // create the thread running ev_run
    ensure(pthread_create(&tid, 0, loop_run, loop) == 0, "pthread_create");

    warn(info, "threaded %s %s with libev %u.%u ready", quant_name,
         quant_version, ev_version_major(), ev_version_minor());

    return w;
}


static void __attribute__((nonnull)) do_close(struct q_conn * const c)
{
    warn(warn, "closing %s conn %" PRIx64,
         is_set(CONN_FLAG_CLNT, c->flags) ? "client" : "server", c->id);

    // start closing all streams
    lock(&c->lock);
    struct q_stream * s;
    SPLAY_FOREACH (s, stream, &c->streams) {
        warn(debug, "closing str %u on conn %" PRIx64, s->id, s->c->id);
        s->state = STRM_HCLO;
    }
    ev_async_send(loop, &c->tx_w);

    // wait until all streams are closed
    while (SPLAY_ROOT(&c->streams)) {
        wait(&c->close_cv, &c->lock);
    }

    struct q_stream * tmp;
    for (s = SPLAY_MIN(stream, &c->streams); s; s = tmp) {
        tmp = SPLAY_NEXT(stream, &c->streams, s);
        w_free(w_engine(c->sock), &s->o);
        w_free(w_engine(c->sock), &s->i);
        free(s);
    }

    ev_io_stop(loop, &c->rx_w);
    ev_timer_stop(loop, &c->ld_alarm);

    diet_free(&c->acked_pkts);
    diet_free(&c->recv);
    ptls_free(c->tls);
    if (c->sock)
        w_close(c->sock);
    unlock(&c->lock);

    ensure(pthread_cond_destroy(&c->close_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&c->read_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&c->write_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&c->connect_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&c->accept_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_mutex_destroy(&c->lock) == 0, "pthread_mutex_init");

    // remove connection from global list
    SPLAY_REMOVE(conn, &q_conns, c);

    free(c);
}


void q_close(struct q_conn * const c)
{
    // lock(&q_conns_lock);
    do_close(c);
    // unlock(&q_conns_lock);
}


void q_cleanup(void * const q)
{
    // wait for engine thread
    ensure(pthread_join(tid, 0) == 0, " pthread_join");

    // handle all signals in this thread again
    sigset_t set;
    sigfillset(&set);
    ensure(pthread_sigmask(SIG_UNBLOCK, &set, 0) == 0, "pthread_sigmask");

    // close all connections
    struct q_conn *c, *tmp;
    // lock(&q_conns_lock);
    for (c = SPLAY_MIN(conn, &q_conns); c != 0; c = tmp) {
        tmp = SPLAY_NEXT(conn, &q_conns, c);
        // do_close(c);
    }
    // unlock(&q_conns_lock);

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
