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
#include <ev.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <time.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "fnv_1a.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"
#include "tommy.h"

struct ev_loop;

static void __attribute__((nonnull)) check_conn(void * obj);


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
    0xff000002 // draft-ietf-quic-transport-02
};

const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


struct ev_loop * loop;

static ev_async tx_w;
static pthread_t tid;
static pthread_cond_t write_cv;
static pthread_cond_t accept_cv;
static pthread_cond_t connect_cv;

pthread_mutex_t lock;
pthread_cond_t read_cv;

static uint64_t accept_queue;


static bool __attribute__((const)) vers_supported(const uint32_t v)
{
    // force version negotiation for values reserved for the purpose
    if ((v & 0x0f0f0f0f) == 0x0a0a0a0a)
        return false;

    for (uint8_t i = 0; i < ok_vers_len; i++)
        if (v == ok_vers[i])
            return true;

    // we're out of matching candidates
    warn(info, "no version in common with client");
    return false;
}


static uint32_t __attribute__((nonnull))
pick_from_server_vers(const void * const buf, const uint16_t len)
{
    const uint16_t pos = pkt_hdr_len(buf, len);
    for (uint8_t i = 0; i < ok_vers_len; i++)
        for (uint8_t j = 0; j < len - pos; j += sizeof(uint32_t)) {
            uint32_t vers = 0;
            uint16_t x = j + pos;
            dec(vers, buf, len, x, 0, "0x%08x");
            warn(debug, "server prio %ld = 0x%08x; our prio %u = 0x%08x",
                 j / sizeof(uint32_t), vers, i, ok_vers[i]);
            if (ok_vers[i] == vers)
                return vers;
        }

    // we're out of matching candidates
    warn(info, "no version in common with server");
    return 0;
}


static void __attribute__((nonnull)) stream_write(struct q_stream * const s,
                                                  const void * const data,
                                                  const uint16_t len)
{
    warn(debug, "writing %u byte%s on str %u: %.*s", len, plural(len), s->id,
         len, data);

    // allocate a w_iov
    struct w_iov_stailq o;
    w_alloc_cnt(w_engine(s->c->sock), &o, 1, Q_OFFSET);
    struct w_iov * const v = STAILQ_FIRST(&o);

    // copy data
    memcpy(v->buf, data, len);
    v->len = len;

    // enqueue for TX
    v->ip = ((struct sockaddr_in *)(void *)&s->c->peer)->sin_addr.s_addr;
    v->port = ((struct sockaddr_in *)(void *)&s->c->peer)->sin_port;
    STAILQ_INSERT_TAIL(&s->o, v, next);
}


static void __attribute__((nonnull))
ld_alarm_cb(struct ev_loop * l, ev_timer * w, int e);


static void tx(struct w_sock * const ws __attribute__((nonnull)),
               struct q_conn * const c __attribute__((nonnull)),
               struct q_stream * s)
{
    struct w_engine * const w = w_engine(ws);
    struct w_iov * v;

    // if (unlikely(s == 0)) {
    //     warn(debug, "allocating temp w_iov");
    //     s = get_stream(c, 0);
    //     w_alloc_cnt(w, &s->o, 1, Q_OFFSET);
    //     v = STAILQ_FIRST(&s->o);
    //     v->ip = ((struct sockaddr_in *)(void *)&c->peer)->sin_addr.s_addr;
    //     v->port = ((struct sockaddr_in *)(void *)&c->peer)->sin_port;
    //     v->len = 0;
    // }

    STAILQ_FOREACH (v, &s->o, next) {
        switch (c->state) {
        case CONN_CLSD:
            // initialize loss detection alarm callback
            ev_init(&c->ld_alarm, ld_alarm_cb);
        // fall through:

        case CONN_VERS_SENT:
            c->state = CONN_VERS_SENT;
            warn(info, "conn %" PRIx64 " now in CONN_VERS_SENT", c->id);
            break;

        case CONN_VERS_RECV:
        case CONN_ESTB:
        case CONN_FINW:
            break;

        default:
            die("TODO: state %u", c->state);
        }
        v->buf = (uint8_t *)v->buf - Q_OFFSET;
        v->len += Q_OFFSET;
        c->out++;
        v->len = enc_pkt(c, s, v->buf, v->len, w_iov_max_len(w, v));
        warn(notice, "sending pkt %" PRIu64, c->out);

        hexdump(v->buf, v->len);
    }

    w_tx(ws, &s->o);
    w_nic_tx(w);
    // STAILQ_CONCAT(c->sent_pkts, &s->o);

    // if (unlikely(s == 0)) {
    //     warn(debug, "freeing temp w_iov");
    //     w_free(w, &s->o);
    // }
}


static void __attribute__((nonnull))
ld_alarm_cb(struct ev_loop * const l __attribute__((unused)),
            ev_timer * const w,
            int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    warn(err, "loss detection alarm on conn %" PRIx64, c->id);

    // see OnLossDetectionAlarm pseudo code
    if (c->state < CONN_ESTB) {
        // handshake retransmission alarm
        // tx(c->sock, c, 0); // retransmit
        // c->handshake_count++;
    }
    //  else if (loss_time != 0):
    //    // Early retransmit or Time Loss Detection
    //    DetectLostPackets(largest_acked_packet)
    //  else if (tlp_count < kMaxTLPs):
    //    // Tail Loss Probe.
    //    SendOnePacket()
    //    tlp_count++
    //  else:
    //    // RTO.
    //    if (rto_count == 0)
    //      largest_sent_before_rto = largest_sent_packet
    //    SendTwoPackets()
    //    rto_count++

    set_ld_alarm(c);
}


static void __attribute__((nonnull))
rx(struct ev_loop * const l __attribute__((unused)),
   ev_io * const rx_w,
   int e __attribute__((unused)))
{
    struct w_sock * const ws = rx_w->data;
    w_nic_rx(w_engine(ws));
    struct w_iov_stailq i = STAILQ_HEAD_INITIALIZER(i);
    w_rx(ws, &i);

    while (!STAILQ_EMPTY(&i)) {
        struct w_iov * const v = STAILQ_FIRST(&i);
        STAILQ_REMOVE_HEAD(&i, next);

        hexdump(v->buf, v->len);
        ensure(v->len <= MAX_PKT_LEN,
               "received %u-byte packet, larger than MAX_PKT_LEN of %u", v->len,
               MAX_PKT_LEN);
        const uint16_t hdr_len = pkt_hdr_len(v->buf, v->len);
        ensure(v->len >= hdr_len,
               "%u-byte packet not large enough for %u-byte header", v->len,
               hdr_len);

        if (hdr_len + HASH_LEN < v->len) {
            // verify hash, if there seems to be one
            warn(debug, "verifying %u-byte hash at [%u..%u] over [0..%u]",
                 HASH_LEN, hdr_len, hdr_len + HASH_LEN - 1, v->len - 1);
            const uint128_t hash = fnv_1a(v->buf, v->len, hdr_len, HASH_LEN);
            if (memcmp(&((uint8_t *)v->buf)[hdr_len], &hash, HASH_LEN) != 0)
                die("hash mismatch");
        }

        // TODO: support short headers w/o cid
        const uint64_t cid = pkt_cid(v->buf, v->len);
        struct q_conn * c = get_conn(cid);
        if (c == 0) {
            // this is a packet for a new connection, create it
            const struct sockaddr_in peer = {.sin_family = AF_INET,
                                             .sin_port = v->port,
                                             .sin_addr = {.s_addr = v->ip}};
            socklen_t peer_len = sizeof(peer);
            c = new_conn(cid, (const struct sockaddr *)&peer, peer_len);
            accept_queue = cid;
        }
        struct q_stream * s = 0;

        const uint64_t nr = pkt_nr(v->buf, v->len);
        warn(notice, "received pkt %" PRIu64, nr);
        if (nr > c->in)
            c->in = nr;

        switch (c->state) {
        case CONN_CLSD:
        case CONN_VERS_RECV:
            // store the socket with the connection
            c->sock = ws;

            ensure(pkt_flags(v->buf) & F_LONG_HDR, "short header");
            c->state = CONN_VERS_RECV;
            warn(info, "conn %" PRIx64 " now in CONN_VERS_RECV", c->id);

            // respond to the initial version negotiation packet
            c->vers = pkt_vers(v->buf, v->len);
            if (vers_supported(c->vers)) {
                warn(debug, "supporting client-requested version 0x%08x",
                     c->vers);
                c->state = CONN_ESTB;
                warn(info, "conn %" PRIx64 " now in CONN_ESTB", c->id);
                dec_frames(c, v);

                // we should have received a ClientHello
                s = get_stream(c, 0);
                struct w_iov * const iv = STAILQ_FIRST(&s->i);
                ensure(strcmp(iv->buf, "ClientHello") == 0, "no ClientHello");

                // respond with ServerHello
                stream_write(s, "ServerHello", strlen("ServerHello"));
            } else
                warn(warn, "client-requested version 0x%08x not supported",
                     c->vers);
            tx(ws, c, s);
            break;

        case CONN_VERS_SENT:
            if (pkt_flags(v->buf) & F_LONG_HDR) {
                warn(info, "server didn't like our version 0x%08x", c->vers);
                ensure(c->vers == pkt_vers(v->buf, v->len),
                       "server did not echo our version back");
                c->vers = pick_from_server_vers(v->buf, v->len);
                if (c->vers)
                    warn(info, "retrying with version 0x%08x", c->vers);
                else {
                    warn(info, "no version in common with server, closing");
                    c->vers = 0;
                    c->state = CONN_FINW;
                    warn(info, "conn %" PRIx64 " now in CONN_FINW", c->id);
                }
                tx(ws, c, s);
            } else {
                warn(info, "server accepted version 0x%08x", c->vers);
                c->state = CONN_ESTB;
                warn(info, "conn %" PRIx64 " now in CONN_ESTB", c->id);
                dec_frames(c, v);

                // we should have received a ServerHello
                s = get_stream(c, 0);
                struct w_iov * const iv = STAILQ_FIRST(&s->i);
                ensure(strcmp(iv->buf, "ServerHello") == 0, "no ServerHello");

                // let's send some stream frames
                check_conn(c);
            }
            break;

        case CONN_ESTB:
            dec_frames(c, v);
            break;

        default:
            die("TODO: state %u", c->state);
        }

        if (c->state == CONN_ESTB) {
            // this is a new connection we just accepted
            pthread_mutex_lock(&lock);
            pthread_cond_signal(&accept_cv);
            pthread_mutex_unlock(&lock);
        }

        // if (c->out_ack >= c->out) {
        //     warn(info, "out %" PRIu64 ", out_ack %" PRIu64, c->out, c->out_ack);
        //     pthread_mutex_lock(&lock);
        //     pthread_cond_signal(&write_cv);
        //     pthread_mutex_unlock(&lock);
        // }

        // warn(info, "in %" PRIu64 ", in_ack %" PRIu64, c->in, c->in_ack);
        // if (c->in_ack < c->in) {
        //     warn(info, "sending ACK");
        //     tx(ws, c, s);
        // }
    }
}


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
    struct q_conn * const c = new_conn(cid, peer, peer_len);
    c->flags |= CONN_FLAG_CLNT;
    // c->vers = 0xbabababa; // XXX reserved version to trigger negotiation
    c->vers = ok_vers[0];
    c->sock = w_bind(q, (uint16_t)plat_random(), 0);
    w_connect(c->sock,
              ((const struct sockaddr_in *)(const void *)peer)->sin_addr.s_addr,
              ((const struct sockaddr_in *)(const void *)peer)->sin_port);

    // initialize the RX watcher
    c->rx_w.data = c->sock;
    ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);

    // prepare ClientHello
    struct q_stream * const s = new_stream(c, 0);
    stream_write(s, "ClientHello", strlen("ClientHello"));

    pthread_mutex_lock(&lock);
    ev_io_start(loop, &c->rx_w);
    ev_async_send(loop, &tx_w);

    warn(warn, "waiting for handshake to complete");
    pthread_cond_wait(&connect_cv, &lock);
    pthread_mutex_unlock(&lock);

    if (c->state != CONN_ESTB) {
        warn(info, "conn %" PRIx64 " not connected", cid);
        return 0;
    }
    return cid;
}


static void __attribute__((nonnull)) check_stream(void * arg, void * obj)
{
    struct q_conn * c = arg;
    struct q_stream * s = obj;
    if (!STAILQ_EMPTY(&s->o)) {
        warn(debug, "conn %" PRIx64 " str %u has %u byte%s pending data", c->id,
             s->id, w_iov_stailq_len(&s->o), plural(w_iov_stailq_len(&s->o)));
        tx(c->sock, c, s);
    }
}


static void __attribute__((nonnull)) check_conn(void * obj)
{
    struct q_conn * c = obj;
    hash_foreach_arg(&c->streams, &check_stream, c);
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

static void __attribute__((nonnull))
find_stream_with_data(void * arg, void * obj)
{
    uint32_t * sid = arg;
    struct q_stream * s = obj;
    if (!STAILQ_EMPTY(&s->i) && *sid == 0) {
        const uint32_t in_len = w_iov_stailq_len(&s->i);
        warn(info, "buffered %u byte%s on str %u", in_len, plural(in_len),
             s->id);
        *sid = s->id;
    }
}


void q_read(const uint64_t cid,
            uint32_t * const sid,
            struct w_iov_stailq * const i)
{
    struct q_conn * const c = get_conn(cid);
    ensure(c, "conn %" PRIx64 " does not exist", cid);

    pthread_mutex_lock(&lock);
    warn(warn, "waiting for data");
    pthread_cond_wait(&read_cv, &lock);
    pthread_mutex_unlock(&lock);

    *sid = 0;
    hash_foreach_arg(&c->streams, &find_stream_with_data, sid);
    if (*sid == 0)
        // no stream has new data, which can happen if the timeout fired
        return;

    struct q_stream * s = get_stream(c, *sid);
    ensure(s, "str %u on conn %" PRIx64 " does not exist", *sid, cid);

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
timeout_cb(struct ev_loop * const l,
           ev_timer * const w __attribute__((unused)),
           int e __attribute__((unused)))
{
    warn(warn, "timeout");
    ev_break(l, EVBREAK_ALL);
}


static void __attribute__((nonnull)) signal_cb(struct ev_loop * const l,
                                               ev_signal * const w,
                                               int e __attribute__((unused)))
{
    warn(err, "%s", strsignal(w->signum));
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

    // start the event loop (will be stopped by timeout_cb or signal_cb)
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
      ev_async * const w __attribute__((unused)),
      int e __attribute__((unused)))
{
    // check if we need to send any data
    hash_foreach(&q_conns, &check_conn);
}


void * q_init(const char * const ifname, const long timeout)
{
    // check versions
    ensure(WARPCORE_VERSION_MAJOR == 0 && WARPCORE_VERSION_MINOR == 5,
           "%s version %s not compatible with %s version %s", quant_name,
           quant_version, warpcore_name, warpcore_version);

    // initialize warpcore, the PRNG, and local state
    void * const w = w_init(ifname, 0);
    srandom((unsigned)time(0));
    hash_init(&q_conns);

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

    // during development, abort event loop after some time
    if (timeout) {
        static ev_timer to_w;
        warn(debug, "setting %ld sec timeout", timeout);
        ev_timer_init(&to_w, timeout_cb, timeout, 0);
        ev_timer_start(loop, &to_w);
    }

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
    // wait for the quant thread to end and destroy lock
    ensure(pthread_join(tid, 0) == 0, "pthread_join");
    ensure(pthread_mutex_destroy(&lock) == 0, "pthread_mutex_init");
    ensure(pthread_cond_destroy(&read_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&write_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&connect_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&accept_cv) == 0, "pthread_cond_destroy");

    w_cleanup(q);
    hash_foreach(&q_conns, free);
    hash_done(&q_conns);
}
