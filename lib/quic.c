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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <time.h>

#include <warpcore.h>

#include "conn.h"
#include "frame.h"
#include "pkt.h"
#include "quic_internal.h"
#include "stream.h"
#include "tommy.h"
#include "version.h"

struct ev_loop;


/// QUIC version supported by this implementation in order of preference.
const q_tag vers[] = {{.as_str = "Q025"}, // "Q025" is draft-hamilton
                      // {.as_str = "Q036"},
                      {.as_int = 0}};

const size_t vers_len = sizeof(vers);

static struct ev_loop * loop;
static ev_async tx_w;
static pthread_t tid;
static pthread_cond_t write_cv;
static pthread_cond_t accept_cv;

pthread_mutex_t lock;
pthread_cond_t read_cv;

static uint64_t accept_queue;


static uint8_t __attribute__((nonnull))
pick_vers(const struct q_cmn_hdr * const p)
{
    for (uint8_t i = 0; vers[i].as_int; i++)
        if (p->vers.as_int == vers[i].as_int)
            return i;

    // we're out of matching candidates, return index of final "zero" version
    warn(info, "no version in common with client");
    return vers_len / sizeof(vers[0]) - 1;
}


static uint8_t __attribute__((nonnull))
pick_server_vers(const struct q_cmn_hdr * const p)
{
    // first, check if the version in the public header is acceptable to us
    for (uint8_t i = 0; vers[i].as_int; i++) {
        warn(debug, "checking server vers %.4s against our prio %u = %.4s",
             p->vers.as_str, i, vers[i].as_str);
        if (vers[i].as_int == p->vers.as_int)
            return i;
    }

    // if that didn't work, then we need to check the numbers in the nonce
    // for (uint8_t i = 0; vers[i].as_int; i++)
    //     for (uint8_t j = 0; j < p->nonce_len; j += sizeof(uint32_t)) {
    //         q_tag v;
    //         memcpy(&v.as_int, &p->nonce[j], sizeof(v));
    //         warn(debug, "checking server vers prio %ld = %.4s against our
    //         prio "
    //                     "%u = %.4s",
    //              j / sizeof(uint32_t), v.as_str, i, vers[i].as_str);
    //         if (vers[i].as_int == v.as_int)
    //             return i;
    //     }

    // we're out of matching candidates, return index of final "zero" version
    warn(info, "no version in common with server");
    return vers_len / sizeof(vers[0]) - 1;
}


static void tx(struct q_conn * const c, struct q_stream * s)
{
    // warn(info, "entering %s for conn %" PRIu64, __func__, c->id);
    struct warpcore * const w = w_engine(c->sock);
    // struct w_iov_chain * o = 0;

    if (s == 0)
        s = new_stream(c, 1);

    struct w_iov * v;
    STAILQ_FOREACH (v, s->ov, next) {
        switch (c->state) {
        case CONN_CLSD:
        case CONN_VERS_SENT:
            c->state = CONN_VERS_SENT;
            warn(info, "conn %" PRIu64 " now in CONN_VERS_SENT", c->id);
            break;

        case CONN_VERS_RECV:
            // send a version-negotiation response from the server
            break;

        case CONN_FINW:
            break;

        default:
            die("TODO: state %u", c->state);
        }
        v->buf = (uint8_t *)v->buf - Q_OFFSET;
        v->len += Q_OFFSET;
        enc_pkt(c, v->buf, v->len, w_iov_max_len(w, v));
        c->out++;
        hexdump(v->buf, v->len);
    }

    w_tx(c->sock, s->ov);
    w_nic_tx(w);

    pthread_mutex_lock(&lock);
    pthread_cond_signal(&write_cv);
    pthread_mutex_unlock(&lock);
}


static void __attribute__((nonnull))
rx(struct ev_loop * const l __attribute__((unused)),
   ev_io * const w,
   int e __attribute__((unused)))
{
    // warn(info, "entering %s for desc %u", __func__, w->fd);
    w_nic_rx(w_engine(w->data));
    struct w_iov * v;
    STAILQ_FOREACH (v, w_rx(w->data), next) {
        ensure(v != 0, "no data received for this socket");
        ensure(v->len <= MAX_PKT_LEN,
               "received %u-byte packet, larger than MAX_PKT_LEN of %u", v->len,
               MAX_PKT_LEN);
        warn(debug, "received %u byte%s", v->len, plural(v->len));
        hexdump(v->buf, v->len);

        struct q_cmn_hdr p = {0};
        struct q_conn * c = 0;
        uint16_t i = dec_cmn_hdr(&p, v->buf, v->len, &c);

        if (c == 0) {
            // this is a packet for a new connection, create it
            ensure(p.flags & F_CID, "no conn ID in initial packet");
            const struct sockaddr_in peer = {.sin_family = AF_INET,
                                             .sin_port = v->port,
                                             .sin_addr = {.s_addr = v->ip}};
            socklen_t peer_len = sizeof(peer);
            c = new_conn(p.cid, (const struct sockaddr *)&peer, peer_len);
            c->in = p.nr;
            // if it gets created here, this is a server connection, so no need
            // to
            // change c->flags
            // XXX
            accept_queue = p.cid;
            pthread_mutex_lock(&lock);
            pthread_cond_signal(&accept_cv);
            pthread_mutex_unlock(&lock);
        }

        if (i <= v->len)
            // if there are bytes after the public header, we have frames
            // i +=
            dec_frames(c, &p, &((uint8_t *)(v->buf))[i], v->len - i);

        switch (c->state) {
        case CONN_CLSD:
            ensure(p.flags & F_VERS, "no version in initial packet");
            c->state = CONN_VERS_RECV;
            warn(info, "conn %" PRIu64 " now in CONN_VERS_RECV", c->id);

            // respond to the initial version negotiation packet
            c->vers = pick_vers(&p);
            if (vers[c->vers].as_int) {
                warn(debug, "supporting client-requested version %.4s with "
                            "preference %u ",
                     p.vers.as_str, c->vers);
                c->state = CONN_ESTB;
                warn(info, "conn %" PRIu64 " now in CONN_ESTB", c->id);
                return;
            }
            warn(warn, "client-requested version %.4s not supported",
                 p.vers.as_str);
            tx(c, 0);
            break;

        case CONN_VERS_SENT:
            if (p.flags & F_VERS) {
                warn(info, "server didn't like our version %.4s",
                     vers[c->vers].as_str);
                c->vers = pick_server_vers(&p);
                if (vers[c->vers].as_int)
                    warn(info, "retrying with version %.4s",
                         vers[c->vers].as_str);
                else {
                    warn(info, "no version in common with server, closing");
                    c->vers =
                        0; // send closing packet with our preferred version
                    c->state = CONN_FINW;
                    warn(info, "conn %" PRIu64 " now in CONN_FINW", c->id);
                }
            } else {
                warn(info, "server accepted version %.4s",
                     vers[c->vers].as_str);
                c->state = CONN_ESTB;
                warn(info, "conn %" PRIu64 " now in CONN_ESTB", c->id);
            }
            tx(c, 0);
            break;

        case CONN_ESTB:
            return; // TODO: respond with ACK

        default:
            die("TODO: state %u", c->state);
        }
    }
}


struct w_iov_chain * q_alloc(void * const w, const uint32_t len)
{
    return w_alloc_size(w, len, Q_OFFSET); /// XXX rethink QUIC header offset
}


void q_free(void * const w, struct w_iov_chain * const c)
{
    w_free(w, c);
}


uint64_t q_connect(void * const q,
                   const struct sockaddr * const peer,
                   const socklen_t peer_len)
{
    // make new connection
    const uint64_t id =
        (((uint64_t)plat_random()) << 32) | (uint64_t)plat_random();
    struct q_conn * const c = new_conn(id, peer, peer_len);
    c->flags |= CONN_FLAG_CLNT;

    c->sock = w_bind(q, (uint16_t)plat_random(), 0);
    w_connect(c->sock,
              ((const struct sockaddr_in *)(const void *)peer)->sin_addr.s_addr,
              ((const struct sockaddr_in *)(const void *)peer)->sin_port);

    // initialize the RX watcher
    c->rx_w = calloc(1, sizeof(*c->rx_w));
    c->rx_w->data = c->sock;
    ev_io_init(c->rx_w, rx, w_fd(c->sock), EV_READ);

    pthread_mutex_lock(&lock);
    ev_io_start(loop, c->rx_w);
    ev_async_send(loop, &tx_w);
    pthread_mutex_unlock(&lock);

    return id;
}


static void __attribute__((nonnull)) check_stream(void * arg, void * obj)
{
    struct q_conn * c = arg;
    struct q_stream * s = obj;
    if (!STAILQ_EMPTY(s->ov)) {
        // warn(info, "buffered %" PRIu64 " byte%s on stream %u on conn %"
        // PRIu64
        //            ": %s ",
        //      s->out_len, plural(s->out_len), s->id, c->id, s->out);
        tx(c, s);
    }
}


static void __attribute__((nonnull)) check_conn(void * obj)
{
    struct q_conn * c = obj;
    hash_foreach_arg(&c->streams, &check_stream, c);
}


void q_write(const uint64_t cid,
             const uint32_t sid,
             struct w_iov_chain * const chain)
{
    struct q_conn * const c = get_conn(cid);
    ensure(c, "conn %" PRIu64 " does not exist", cid);
    struct q_stream * s = get_stream(c, sid);
    ensure(s, "stream %u on conn %" PRIu64 " does not exist", sid, cid);

    pthread_mutex_lock(&lock);
    STAILQ_CONCAT(s->ov, chain);
    ev_io_start(loop, c->rx_w);
    ev_async_send(loop, &tx_w);
    warn(warn, "waiting for write to complete");
    pthread_cond_wait(&write_cv, &lock);

    // XXX instead of assuming all data was received, we need to do rtx handling
    STAILQ_INIT(s->ov);

    pthread_mutex_unlock(&lock);
    warn(warn, "write done");
}

static void __attribute__((nonnull))
find_stream_with_data(void * arg, void * obj)
{
    uint32_t * sid = arg;
    struct q_stream * s = obj;
    if (s->in_len && *sid == 0) {
        // warn(info, "buffered %" PRIu64 " byte%s on stream %u: %s ",
        // s->in_len,
        //      plural(s->in_len), s->id, s->in);
        *sid = s->id;
    }
}


size_t q_read(const uint64_t cid,
              uint32_t * const sid,
              void * const buf,
              const size_t len)
{
    struct q_conn * const c = get_conn(cid);
    ensure(c, "conn %" PRIu64 " does not exist", cid);

    pthread_mutex_lock(&lock);
    warn(warn, "waiting for data");
    pthread_cond_wait(&read_cv, &lock);
    pthread_mutex_unlock(&lock);

    *sid = 0;
    hash_foreach_arg(&c->streams, &find_stream_with_data, sid);
    if (*sid == 0)
        // No stream seems to have new data, which can happen if the timeout
        // fired. In that case, return 0.
        return 0;

    struct q_stream * s = get_stream(c, *sid);
    ensure(s, "stream %u on conn %" PRIu64 " does not exist", *sid, cid);

    if (s->in_len == 0) {
        pthread_mutex_lock(&lock);
        // not needed it seems
        // ev_io_start(loop, &c->rx_w);
        // ev_async_send(loop, &tx_w);
        warn(warn, "read waiting for data");
        pthread_cond_wait(&read_cv, &lock);
        pthread_mutex_unlock(&lock);
        warn(warn, "read done");
    }

    // append data
    const size_t data_len = MIN(len, s->in_len);
    memcpy(buf, s->in, data_len);
    warn(info, "%" PRIu64 " byte%s on stream %u on conn %" PRIu64 ": %s",
         s->in_len, plural(s->in_len), *sid, cid, (char *)buf);
    // TODO: proper buffer handling
    memmove(buf, &((uint8_t *)(buf))[data_len], data_len);
    s->in_len -= data_len;
    return data_len;
}


uint64_t q_bind(void * const q, const uint16_t port)
{
    // warn(debug, "enter");

    // bind socket
    struct w_sock * const s = w_bind(q, ntohs(port), 0);

    // allocate and initialize an RX watcher
    ev_io * rx_w = calloc(1, sizeof(*rx_w));
    rx_w->data = s;
    ev_io_init(rx_w, rx, w_fd(s), EV_READ);

    pthread_mutex_lock(&lock);

    // start the RX watcher
    ev_io_start(loop, rx_w);
    ev_async_send(loop, &tx_w); // XXX may not be needed
    warn(warn, "waiting for new inbound conn");
    pthread_cond_wait(&accept_cv, &lock);

    // take new connection from "accept queue"; will be zero if interrupted
    const uint64_t cid = accept_queue;
    if (cid) {
        accept_queue = 0;

        // store the RX watcher with the connection
        struct q_conn * const c = get_conn(cid);
        ensure(c, "conn %" PRIu64 " does not exist", cid);
        c->rx_w = rx_w;
        c->sock = s;
        warn(warn, "got conn %" PRIu64, cid);
    }

    pthread_mutex_unlock(&lock);
    return cid;
}


uint32_t q_rsv_stream(const uint64_t cid)
{
    struct q_conn * const c = get_conn(cid);
    ensure(c, "conn %" PRIu64 " does not exist", cid);
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
    // initialize warpcore, the PRNG, and local state
    void * const w = w_init(ifname, 0);
    srandom((unsigned)time(0));
    hash_init(&q_conns);

    // initialize synchronization helpers
    pthread_mutex_init(&lock, 0);
    pthread_cond_init(&read_cv, 0);
    pthread_cond_init(&write_cv, 0);
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
    // warn(debug, "enter");
    struct q_conn * const c = get_conn(cid);
    ensure(c, "conn %" PRIu64 " does not exist", cid);
    w_close(c->sock);
    hash_foreach(&c->streams, free);
    hash_done(&c->streams);
    hash_remove(&q_conns, &c->conn_node);
    free(c);
    // warn(debug, "leave");
}


void q_cleanup(void * const q)
{
    warn(debug, "enter");

    // wait for the quant thread to end and destroy lock
    ensure(pthread_join(tid, 0) == 0, "pthread_join");
    ensure(pthread_mutex_destroy(&lock) == 0, "pthread_mutex_init");
    ensure(pthread_cond_destroy(&read_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&write_cv) == 0, "pthread_cond_destroy");
    ensure(pthread_cond_destroy(&accept_cv) == 0, "pthread_cond_destroy");

    w_cleanup(q);
    hash_foreach(&q_conns, free);
    hash_done(&q_conns);
    warn(debug, "leave");
}
