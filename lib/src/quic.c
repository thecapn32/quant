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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <stddef.h> // IWYU pragma: keep

#include <picotls.h>
#include <picotls/minicrypto.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#include <ev.h>
#pragma clang diagnostic pop

#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "cert.h"
#include "conn.h"
#include "quic.h"
#include "stream.h"


// TODO: many of these globals should move to a per-engine struct

struct ev_loop;
struct sockaddr;


/// Number of packet buffers to allocate.
static const uint32_t nbufs = 100000;
struct pkt_meta * q_pkt_meta;


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
    0xff000004 // draft-ietf-quic-transport-04
};

const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


struct ev_loop * loop = 0;

static ev_async tx_w;
static pthread_t tid;
pthread_cond_t write_cv;
pthread_cond_t accept_cv;
pthread_cond_t connect_cv;

pthread_mutex_t lock;
pthread_cond_t read_cv;

uint64_t accept_queue;


ptls_context_t tls_ctx = {0};

static ptls_minicrypto_secp256r1sha256_sign_certificate_t sign_cert;
static ptls_iovec_t tls_certs;
static ptls_verify_certificate_t verifier;


void q_alloc(void * const w, struct w_iov_stailq * const q, const uint32_t len)
{
    w_alloc_len(w, q, len, Q_OFFSET);
}


void q_free(void * const w, struct w_iov_stailq * const q)
{
    w_free(w, q);
}


uint64_t q_connect(void * const q,
                   const struct sockaddr * const peer,
                   const socklen_t peer_len)
{
    // make new connection
    const uint64_t cid =
        (((uint64_t)plat_random()) << 32) | (uint64_t)plat_random();
    struct q_conn * const c = new_conn(cid, peer, peer_len, false);
    c->flags |= CONN_FLAG_CLNT;
    // c->vers = 0xbabababa; // XXX reserved version to trigger negotiation
    c->vers = ok_vers[0];
    c->sock = w_bind(q, 0, 0);
    w_connect(c->sock,
              ((const struct sockaddr_in *)(const void *)peer)->sin_addr.s_addr,
              ((const struct sockaddr_in *)(const void *)peer)->sin_port);

    // initialize the RX watcher
    c->rx_w.data = c->sock;
    ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);

    // allocate stream zero
    new_stream(c, 0);

    pthread_mutex_lock(&lock);
    ev_io_start(loop, &c->rx_w);
    tx_w.data = c;
    ev_async_send(loop, &tx_w);

    warn(warn, "waiting for handshake to complete");
    pthread_cond_wait(&connect_cv, &lock);
    pthread_mutex_unlock(&lock);

    if (c->state != CONN_ESTB) {
        warn(info, "conn %" PRIx64 " not connected", cid);
        return 0;
    }

    warn(info, "conn %" PRIx64 " connected", cid);
    return cid;
}


void q_write(const uint64_t cid,
             const uint32_t sid,
             struct w_iov_stailq * const q)
{
    struct q_conn * const c = get_conn(cid);
    ensure(c, "conn %" PRIx64 " does not exist", cid);
    struct q_stream * s = get_stream(c, sid);
    ensure(s, "str %u on conn %" PRIx64 " does not exist", sid, cid);

    pthread_mutex_lock(&lock);
    STAILQ_CONCAT(&s->o, q);
    ev_io_start(loop, &c->rx_w);
    ev_async_send(loop, &tx_w);
    warn(warn, "waiting for write to complete");
    pthread_cond_wait(&write_cv, &lock);

    // XXX instead of assuming all data was received, we need to do rtx handling
    STAILQ_INIT(&s->o);

    pthread_mutex_unlock(&lock);
    warn(warn, "write done");
}


void q_read(const uint64_t cid,
            uint32_t * const sid,
            struct w_iov_stailq * const i)
{
    *sid = 0;
    struct q_conn which = {.id = cid};
    struct q_conn * c = SPLAY_FIND(conn, &q_conns, &which);
    if (c == 0)
        return;

    // struct q_conn * const c = get_conn(cid);
    // ensure(c, "conn %" PRIx64 " does not exist", cid);

    pthread_mutex_lock(&lock);
    warn(warn, "waiting for data");
    pthread_cond_wait(&read_cv, &lock);
    pthread_mutex_unlock(&lock);

    struct q_stream * s;
    SPLAY_FOREACH(s, stream, &c->streams)
    if (!STAILQ_EMPTY(&s->i)) {
#ifndef NDEBUG
        const uint32_t in_len = w_iov_stailq_len(&s->i);
        warn(info, "buffered %u byte%s on str %u", in_len, plural(in_len),
             s->id);
#endif
        *sid = s->id;
        break;
    }
    if (*sid == 0)
        return;

    // *sid = 0;
    // hash_foreach_arg(&c->streams, &find_stream_with_data, sid);
    // if (*sid == 0)
    //     // no stream has new data, which can happen if the timeout fired
    //     return;

    // struct q_stream * s = get_stream(c, *sid);
    // ensure(s, "str %u on conn %" PRIx64 " does not exist", *sid, cid);

    if (STAILQ_EMPTY(&s->i)) {
        pthread_mutex_lock(&lock);
        warn(warn, "read waiting for data");
        pthread_cond_wait(&read_cv, &lock);
        pthread_mutex_unlock(&lock);
        warn(warn, "read done");
    }

    // return data
    STAILQ_CONCAT(i, &s->i);
}


uint64_t q_bind(void * const q, const uint16_t port)
{
    // bind socket
    struct w_sock * const ws = w_bind(q, ntohs(port), 0);

    // initialize an RX watcher
    ev_io rx_w = {.data = ws};
    ev_io_init(&rx_w, rx, w_fd(ws), EV_READ);
    pthread_mutex_lock(&lock);

    // start the RX watcher
    ev_io_start(loop, &rx_w);
    ev_async_send(loop, &tx_w);
    warn(warn, "waiting for new inbound conn");
    pthread_cond_wait(&accept_cv, &lock);
    ev_io_stop(loop, &rx_w);

    // take new connection from "accept queue"; will be zero if interrupted
    const uint64_t cid = accept_queue;
    if (cid) {
        accept_queue = 0;

        // store the RX watcher with the connection
        struct q_conn * const c = get_conn(cid);
        c->rx_w = rx_w;
        ev_io_start(loop, &c->rx_w);
        warn(warn, "got conn %" PRIx64, cid);
    }

    pthread_mutex_unlock(&lock);
    return cid;
}


uint32_t q_rsv_stream(const uint64_t cid)
{
    struct q_conn * const c = get_conn(cid);
    ensure(c, "conn %" PRIx64 " does not exist", cid);
    return new_stream(c, 0)->id;
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
    struct ev_loop * l = (struct ev_loop *)arg;
    ensure(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0) == 0,
           "pthread_setcanceltype");

    // set up signal handler
    static ev_signal sigint_w, sigquit_w, sigterm_w;
    ev_signal_init(&sigint_w, signal_cb, SIGINT);
    ev_signal_init(&sigquit_w, signal_cb, SIGQUIT);
    ev_signal_init(&sigterm_w, signal_cb, SIGTERM);
    ev_signal_start(loop, &sigint_w);
    ev_signal_start(loop, &sigquit_w);
    ev_signal_start(loop, &sigterm_w);

    // start the event loop (will be stopped by signal_cb)
    ev_run(l, 0);

    // notify the main thread, which may be blocked on these conditions
    pthread_mutex_lock(&lock);
    pthread_cond_signal(&read_cv);
    pthread_cond_signal(&write_cv);
    pthread_cond_signal(&connect_cv);
    pthread_cond_signal(&accept_cv);
    pthread_mutex_unlock(&lock);

    return 0;
}


static void __attribute__((nonnull))
tx_cb(struct ev_loop * const l __attribute__((unused)),
      ev_async * const w,
      int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    if (c)
        tx(c->sock, c);
}


void * q_init(const char * const ifname)
{
    // check versions
    ensure(WARPCORE_VERSION_MAJOR == 0 && WARPCORE_VERSION_MINOR == 9,
           "%s version %s not compatible with %s version %s", quant_name,
           quant_version, warpcore_name, warpcore_version);

    // initialize warpcore on the given interface
    void * const w = w_init(ifname, 0, nbufs);
    q_pkt_meta = calloc(nbufs, sizeof(*q_pkt_meta));
    ensure(q_pkt_meta, "could not calloc");

    // if the global quant state has been initialized before, return
    if (loop)
        return w;

    // initialize PRNG
    srandom((unsigned)time(0));

    // initialize TLS context
    tls_ctx.random_bytes = ptls_minicrypto_random_bytes;
    tls_ctx.key_exchanges = ptls_minicrypto_key_exchanges;
    tls_ctx.cipher_suites = ptls_minicrypto_cipher_suites;

    ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        &sign_cert, ptls_iovec_init(tls_key, tls_key_len));
    tls_ctx.sign_certificate = &sign_cert.super;

    tls_certs = ptls_iovec_init(tls_cert, tls_cert_len);
    tls_ctx.certificates.list = &tls_certs;
    tls_ctx.certificates.count = 1;

    // TODO: there doesn't yet seem to be a minicrypto version of this call:
    // ptls_openssl_init_verify_certificate(&verifier, 0);
    tls_ctx.verify_certificate = &verifier;

    // initialize synchronization helpers
    pthread_mutex_init(&lock, 0);
    pthread_cond_init(&read_cv, 0);
    pthread_cond_init(&write_cv, 0);
    pthread_cond_init(&connect_cv, 0);
    pthread_cond_init(&accept_cv, 0);

    // initialize the event loop and async call handler
    loop = ev_default_loop(0);
    ev_async_init(&tx_w, tx_cb);
    ev_async_start(loop, &tx_w);

    // create the thread running ev_run
    pthread_create(&tid, 0, l_run, loop);

    // block those signals that we'll let the event loop handle
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTERM);
    ensure(pthread_sigmask(SIG_BLOCK, &set, NULL) == 0, "pthread_sigmask");

    warn(info, "threaded %s %s with libev %u.%u ready", quant_name,
         quant_version, ev_version_major(), ev_version_minor());

    return w;
}


void q_close(const uint64_t cid)
{
    struct q_conn * const c = get_conn(cid);
    ensure(c, "conn %" PRIx64 " does not exist", cid);

    // TODO proper handling of close
    // w_close(c->sock);
    // hash_foreach(&c->streams, free);
    // hash_done(&c->streams);
    // hash_remove(&q_conns, &c->conn_node);
    // free(c);
}


void q_cleanup(void * const q)
{
    pthread_kill(tid, SIGTERM);
    ensure(pthread_join(tid, 0) == 0, "pthread_join");
    ensure(pthread_mutex_destroy(&lock) == 0, "pthread_mutex_init");
    ensure(pthread_cond_destroy(&read_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&write_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&connect_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&accept_cv) == 0, "pthread_cond_destroy");

    w_cleanup(q);
    struct q_conn *c, *tmp;
    for (c = SPLAY_MIN(conn, &q_conns); c != 0; c = tmp) {
        tmp = SPLAY_NEXT(conn, &q_conns, c);
        SPLAY_REMOVE(conn, &q_conns, c);
        free(c);
    }

    // hash_foreach(&q_conns, free);
    // hash_done(&q_conns);

    free(q_pkt_meta);
}
