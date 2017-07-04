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

struct ev_loop;
struct sockaddr;


/// Number of packet buffers to allocate.
static const uint32_t nbufs = 1000;
struct pkt_meta * pm = 0;


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
    0xff000004 // draft-ietf-quic-transport-04
};

const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


struct ev_loop * loop = 0;

static ev_async tx_w = {0};
static pthread_t tid = {0};

ptls_context_t tls_ctx = {0};

static ptls_minicrypto_secp256r1sha256_sign_certificate_t sign_cert = {0};
static ptls_iovec_t tls_certs = {0};
static ptls_openssl_verify_certificate_t verifier = {0};


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
                          const socklen_t peer_len)
{
    // make new connection (connection ID must be > 0 for us)
    const uint64_t cid =
        ((((uint64_t)plat_random()) << 32) | ((uint64_t)plat_random()));
    struct q_conn * const c = new_conn(CONN_FLAG_CLNT);
    init_conn(c, cid, peer, peer_len);
    // c->vers = 0xbabababa; // XXX reserved version to trigger negotiation
    c->vers = ok_vers[0];
    c->next_sid = 1; // client initiates odd-numbered streams
    c->sock = w_bind(q, 0, 0);
    w_connect(c->sock,
              ((const struct sockaddr_in *)(const void *)peer)->sin_addr.s_addr,
              ((const struct sockaddr_in *)(const void *)peer)->sin_port);

    // initialize the RX watcher
    c->rx_w.data = c->sock;
    ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);

    // allocate stream zero (client case) and start TLS handshake on stream 0
    struct q_stream * const s = new_stream(c, 0);
    tls_handshake(s);

    // start watchers
    ev_io_start(loop, &c->rx_w);
    tx_w.data = c;
    ev_async_send(loop, &tx_w);

    warn(warn, "waiting for handshake to complete");
    lock(&c->lock);
    wait(&c->connect_cv, &c->lock);
    unlock(&c->lock);

    if (c->state != CONN_ESTB) {
        warn(info, "conn %" PRIx64 " not connected", cid);
        return 0;
    }

    warn(info, "conn %" PRIx64 " connected", cid);
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
    ev_io_start(loop, &c->rx_w);
    ev_async_send(loop, &tx_w);
    wait(&c->write_cv, &c->lock);

    // XXX instead of assuming all data was received, we need to do rtx handling
    STAILQ_INIT(&s->o);
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
    struct w_sock * const ws = w_bind(q, ntohs(port), 0);
    struct q_conn * const c = new_conn(0);

    // initialize and start an RX watcher
    c->rx_w.data = ws;
    ev_io_init(&c->rx_w, rx, w_fd(ws), EV_READ);
    ev_io_start(loop, &c->rx_w);
    ev_async_send(loop, &tx_w);

    return c;
}


struct q_conn * q_accept(struct q_conn * const c)
{
    warn(warn, "waiting for handshake to complete");
    lock(&c->lock);
    wait(&c->accept_cv, &c->lock);
    unlock(&c->lock);
    if (c->state >= CONN_ESTB) {
        warn(warn, "got conn %" PRIx64, c->id);
        return c;
    }
    return 0;
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


static void __attribute__((nonnull))
signal_cb(struct ev_loop * const l,
          ev_signal * const w __attribute__((unused)),
          int e __attribute__((unused)))
{
    ev_break(l, EVBREAK_ALL);
}


static void * __attribute__((nonnull)) l_run(void * const arg)
{
    // ensure(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0) == 0,
    //        "pthread_setcanceltype");

    // set up signal handler
    ev_signal sigint_w, sigquit_w, sigterm_w;
    ev_signal_init(&sigint_w, signal_cb, SIGINT);
    ev_signal_init(&sigquit_w, signal_cb, SIGQUIT);
    ev_signal_init(&sigterm_w, signal_cb, SIGTERM);
    ev_signal_start(loop, &sigint_w);
    ev_signal_start(loop, &sigquit_w);
    ev_signal_start(loop, &sigterm_w);

    // unblock only those signals that we'll handle in the event loop
    sigset_t set;
    sigfillset(&set);
    ensure(pthread_sigmask(SIG_BLOCK, &set, 0) == 0, "pthread_sigmask");
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTERM);
    ensure(pthread_sigmask(SIG_UNBLOCK, &set, 0) == 0, "pthread_sigmask");

    // start the event loop (will be stopped by signal_cb)
    struct ev_loop * l = (struct ev_loop *)arg;
    ev_run(l, 0);

    // stop signal watchers
    ev_signal_stop(loop, &sigint_w);
    ev_signal_stop(loop, &sigquit_w);
    ev_signal_stop(loop, &sigterm_w);

    // unblock the main thread, by signaling all possible conditions
    lock(&q_conns_lock);
    struct q_conn * c;
    SPLAY_FOREACH (c, conn, &q_conns) {
        // XXX do we also need to stop the watchers here?
        signal(&c->read_cv, &c->lock);
        signal(&c->write_cv, &c->lock);
        signal(&c->connect_cv, &c->lock);
        signal(&c->accept_cv, &c->lock);
    }
    unlock(&q_conns_lock);
    return 0; // implicit pthread_exit()
}


static void __attribute__((nonnull))
tx_cb(struct ev_loop * const l __attribute__((unused)),
      ev_async * const w,
      int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    if (c)
        tx(c);
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

    // initialize the event loop and async call handler
    loop = ev_default_loop(0);
    ev_async_init(&tx_w, tx_cb);
    ev_async_start(loop, &tx_w);

    // create the thread running ev_run
    ensure(pthread_create(&tid, 0, l_run, loop) == 0, "pthread_create");

    warn(info, "threaded %s %s with libev %u.%u ready", quant_name,
         quant_version, ev_version_major(), ev_version_minor());

    return w;
}


static void __attribute__((nonnull)) do_close(struct q_conn * const c)
{
    warn(warn, "closing %s conn %" PRIx64,
         is_set(CONN_FLAG_CLNT, c->flags) ? "client" : "server", c->id);
    lock(&c->lock);
    ev_io_stop(loop, &c->rx_w);
    ev_timer_stop(loop, &c->ld_alarm);
    struct q_stream *s, *tmp;
    for (s = SPLAY_MIN(stream, &c->streams); s; s = tmp) {
        tmp = SPLAY_NEXT(stream, &c->streams, s);
        w_free(w_engine(c->sock), &s->o);
        w_free(w_engine(c->sock), &s->i);
        free(s);
    }
    diet_free(&c->acked_pkts);
    diet_free(&c->recv);
    ptls_free(c->tls);
    if (c->sock)
        w_close(c->sock);
    unlock(&c->lock);

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
    lock(&q_conns_lock);
    do_close(c);
    unlock(&q_conns_lock);
}


void q_cleanup(void * const q)
{
    // wait for engine thread
    ensure(pthread_join(tid, 0) == 0, " pthread_join");

    // handle all signals in this thread again
    sigset_t set;
    sigfillset(&set);
    ensure(pthread_sigmask(SIG_UNBLOCK, &set, 0) == 0, "pthread_sigmask");

    // stop async call handler
    ev_async_stop(loop, &tx_w);

    // close all connections
    struct q_conn *c, *tmp;
    lock(&q_conns_lock);
    for (c = SPLAY_MIN(conn, &q_conns); c != 0; c = tmp) {
        tmp = SPLAY_NEXT(conn, &q_conns, c);
        do_close(c);
    }
    unlock(&q_conns_lock);

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
