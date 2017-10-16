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
#include <sys/types.h>

#include <ev.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"

struct ev_loop;


// TODO: many of these globals should move to a per-engine struct


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
    // 0xff000004, // draft-ietf-quic-transport-04
    0xff000005, // draft-ietf-quic-transport-05
    // 0xff000007, // draft-ietf-quic-transport-07
};

/// Length of the @p ok_vers array.
const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


struct pkt_meta * pm = 0;
struct ev_loop * loop = 0;

func_ptr api_func = 0;
void * api_arg = 0;

static const uint32_t nbufs = 1000; ///< Number of packet buffers to allocate.


/// Run the event loop with the API function @p func and argument @p arg.
///
/// @param      func  The active API function.
/// @param      arg   The argument of the currently active API function.
///
#define loop_run(func, arg)                                                    \
    do {                                                                       \
        ensure(api_func == 0 && api_arg == 0, "no API call active");           \
        api_func = (func_ptr)(&(func));                                        \
        api_arg = (arg);                                                       \
        warn(DBG, #func "(" #arg ") entering event loop");                     \
        ev_run(loop, 0);                                                       \
        api_func = 0;                                                          \
        api_arg = 0;                                                           \
    } while (0)


// TODO: for now, we just exit
static void __attribute__((noreturn))
idle_alarm(struct ev_loop * const l __attribute__((unused)),
           ev_timer * const w,
           int e __attribute__((unused)))
{
    warn(CRT, "idle timeout; exiting");

    // stop the event loop
    ev_loop_destroy(loop);

    free(pm);

    struct q_conn * const c = w->data;
    w_cleanup(w_engine(c->sock));
    exit(0);
}


static struct q_conn * new_conn(struct w_engine * const w,
                                const uint32_t vers,
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
    c->vers = c->vers_initial = vers;
    tls_ctx.random_bytes(c->stateless_reset_token,
                         sizeof(c->stateless_reset_token));

    // initialize LD state
    // XXX: UsingTimeLossDetection not defined?
    c->ld_alarm.data = c;
    ev_init(&c->ld_alarm, ld_alarm);
    c->reorder_thresh = kReorderingThreshold;
    c->reorder_fract = HUGE_VAL;
    c->lg_sent = peer_name ? 999 : 7999; // TODO: randomize initial pkt nr

    // initialize CC state
    c->cwnd = kInitialWindow;
    c->ssthresh = UINT64_MAX;

    c->flags = CONN_FLAG_EMBR;
    if (peer_name) {
        c->flags |= CONN_FLAG_CLNT;
        ensure(c->peer_name = strdup(peer_name), "could not du peer_name");
    }

    sq_init(&c->sent_pkts);
    splay_init(&c->streams);
    diet_init(&c->closed_streams);
    diet_init(&c->acked_pkts);
    diet_init(&c->recv);

    c->initial_max_stream_data = 1000001; // units of octets
    c->initial_max_data = 2000002;        // units of 1024 octets
    c->initial_max_stream_id = 3000003;   // as is
    c->idle_timeout = 595;                // units of seconds (max 600 seconds)

    // initialize TLS state
    init_tls(c);

    // initialize idle timeout
    c->idle_alarm.data = c;
    c->idle_alarm.repeat = kIdleTimeout;
    ev_init(&c->idle_alarm, idle_alarm);

    // initialize socket and start an RX/TX watchers
    ev_async_init(&c->tx_w, tx);
    c->tx_w.data = c;
    ev_async_start(loop, &c->tx_w);
    c->sock = w_bind(w, htons(port), 0);
    ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);
    c->rx_w.data = c->sock;
    ev_io_start(loop, &c->rx_w);

    // add connection to global data structures
    splay_insert(ipnp_splay, &conns_by_ipnp, c);
    splay_insert(cid_splay, &conns_by_cid, c);

    warn(DBG, "%s conn created", conn_type(c));
    return c;
}


void q_alloc(void * const w, struct w_iov_sq * const q, const uint32_t len)
{
    w_alloc_len(w, q, len, MAX_PKT_LEN - AEAD_LEN, Q_OFFSET);
}


void q_free(void * const w, struct w_iov_sq * const q)
{
    w_free((struct w_engine *)w, q);
}


struct q_conn * q_connect(void * const q,
                          const struct sockaddr_in * const peer,
                          const char * const peer_name)
{
    // make new connection
    uint64_t cid;
    tls_ctx.random_bytes(&cid, sizeof(cid));
    warn(WRN, "connecting embr clnt conn %" PRIx64 " to %s:%u", cid,
         inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
#ifndef NDBUG
    const uint vers = 0xbabababa; // XXX reserved version to trigger negotiation
#else
    const uint vers = ok_vers[0];
#endif
    struct q_conn * const c = new_conn(q, vers, cid, peer, peer_name, 0);

    c->next_sid = 1; // client initiates odd-numbered streams
    w_connect(c->sock, peer->sin_addr.s_addr, peer->sin_port);

    // allocate stream zero and start TLS handshake on stream 0
    struct q_stream * const s = new_stream(c, 0);
    tls_handshake(s);
    ev_async_send(loop, &c->tx_w);

    warn(WRN, "waiting for connect to complete on %s conn %" PRIx64 " to %s:%u",
         conn_type(c), c->id, inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
    loop_run(q_connect, c);

    if (c->state != CONN_STAT_VERS_OK) {
        warn(WRN, "%s conn %" PRIx64 " not connected, state 0x%02x",
             conn_type(c), cid, c->state);
        return 0;
    }

    c->state = CONN_STAT_ESTB;

    warn(WRN, "%s conn %" PRIx64 " connected", conn_type(c), cid);
    return c;
}


void q_write(struct q_stream * const s, struct w_iov_sq * const q)
{
    const uint32_t qlen = w_iov_sq_len(q);
    warn(WRN, "writing %u byte%s on %s conn %" PRIx64 " str %u", qlen,
         plural(qlen), conn_type(s->c), s->c->id, s->id);

    sq_concat(&s->o, q);
    s->state = STRM_STATE_OPEN;

    // kick TX watcher
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_write, s);

    // return written data back to user stailq
    sq_concat(q, &s->r);

    warn(WRN, "wrote %u byte%s on %s conn %" PRIx64 " str %u", qlen,
         plural(qlen), conn_type(s->c), s->c->id, s->id);

    ensure(w_iov_sq_len(q) == qlen, "payload corrupted, %u != %u",
           w_iov_sq_len(q), qlen);
}


struct q_stream * q_read(struct q_conn * const c, struct w_iov_sq * const q)
{
    warn(WRN, "reading on %s conn %" PRIx64, conn_type(c), c->id);
    struct q_stream * s = 0;

    while (c->state != CONN_STAT_IDLE && s == 0) {
        splay_foreach (s, stream, &c->streams) {
            if (s->id == 0)
                // don't deliver stream-zero data
                continue;
            if (!sq_empty(&s->i))
                // we found a stream with queued data
                break;
        }

        if (c->state != CONN_STAT_IDLE && s == 0) {
            // no data queued on any non-zero stream, we need to wait
            warn(WRN, "waiting for data on %s conn %" PRIx64, conn_type(c),
                 c->id);
            loop_run(q_read, c);
        }
    }

    if (s == 0)
        return 0;

    // return data
    sq_concat(q, &s->i);
    warn(WRN, "read %u byte%s on %s conn %" PRIx64 " str %u", w_iov_sq_len(q),
         plural(w_iov_sq_len(q)), conn_type(s->c), s->c->id, s->id);
    return s;
}


struct q_conn * q_bind(void * const q, const uint16_t port)
{
    // bind socket and create new embryonic server connection
    warn(WRN, "binding serv socket on port %u", port);
    struct q_conn * const c = new_conn(q, 0, 0, 0, 0, port);
    warn(WRN, "bound %s socket on port %u", conn_type(c), port);
    return c;
}


struct q_conn * q_accept(struct q_conn * const c)
{
    if (c->state >= CONN_STAT_ESTB) {
        warn(WRN, "got %s conn %" PRIx64, conn_type(c), c->id);
        return c;
    }

    warn(WRN, "waiting for accept on %s conn", conn_type(c));
    loop_run(q_accept, c);

    if (c->id == 0) {
        warn(WRN, "conn not accepted");
        // TODO free embryonic connection
        return 0;
    }
    c->state = CONN_STAT_ESTB;

    warn(WRN, "%s conn %" PRIx64 " connected to clnt %s:%u", conn_type(c),
         c->id, inet_ntoa(c->peer.sin_addr), ntohs(c->peer.sin_port));
    return c;
}


struct q_stream * q_rsv_stream(struct q_conn * const c)
{

    const uint8_t odd = c->next_sid % 2; // NOTE: % in assert confuses printf
    ensure(is_clnt(c) == odd || !is_clnt(c) && !odd,
           "am %s, expected %s connection stream ID, got %u", conn_type(c),
           is_clnt(c) ? "odd" : "even", c->next_sid);
    return new_stream(c, c->next_sid);
}


void * q_init(const char * const ifname)
{
    // check versions
    // ensure(WARPCORE_VERSION_MAJOR == 0 && WARPCORE_VERSION_MINOR == 12,
    //        "%s version %s not compatible with %s version %s", quant_name,
    //        quant_version, warpcore_name, warpcore_version);

    // init connection structures
    splay_init(&conns_by_ipnp);
    splay_init(&conns_by_cid);

    // initialize warpcore on the given interface
    void * const w = w_init(ifname, 0, nbufs);
    pm = calloc(nbufs, sizeof(*pm));
    ensure(pm, "could not calloc");

    // initialize PRNG
    plat_initrandom();

    // initialize TLS context
    init_tls_ctx();

    // initialize the event loop
    loop = ev_default_loop(0);

    warn(INF, "%s %s with libev %u.%u ready", quant_name, quant_version,
         ev_version_major(), ev_version_minor());
    warn(INF, "submit bug reports at https://github.com/NTAP/quant/issues");

    return w;
}


void q_close_stream(struct q_stream * const s)
{
    warn(WRN, "closing str %u on %s conn %" PRIx64, s->id, conn_type(s->c),
         s->c->id);

    if (s->state == STRM_STATE_IDLE) {
        warn(WRN, "%s conn %" PRIx64 " str %u already closed", conn_type(s->c),
             s->c->id, s->id);
        free_stream(s);
        return;
    }

    if (s->state <= STRM_STATE_OPEN) {
        warn(DBG, "half-closing str %u on %s conn %" PRIx64, s->id,
             conn_type(s->c), s->c->id);
        s->state = STRM_STATE_HCLO;
    } else {
        warn(DBG, "str %u on %s conn %" PRIx64 " already HCRM, now CLSD", s->id,
             conn_type(s->c), s->c->id);
        s->state = STRM_STATE_CLSD;
    }

    ev_async_send(loop, &s->c->tx_w);

    // if (s->state != STRM_STATE_IDLE) {
    //     warn(WRN, "waiting for close on %s conn %" PRIx64 " str %u",
    //          conn_type(s->c), s->c->id, s->id);
    //     loop_run(q_close_stream, s);
    // }

    // warn(WRN, "%s conn %" PRIx64 " str %u closed", conn_type(s->c), s->c->id,
    //      s->id);
    // free_stream(s);
}


void q_close(struct q_conn * const c)
{
    if (c->state < CONN_STAT_CLSD) {
        warn(WRN, "closing %s conn %" PRIx64, conn_type(c), c->id);

        // close all streams
        struct q_stream *s, *tmp;
        for (s = splay_max(stream, &c->streams); s; s = tmp) {
            tmp = splay_prev(stream, &c->streams, s);
            if (s->id != 0)
                q_close_stream(s);
        }

        c->state = CONN_STAT_CLSD;
        ev_async_send(loop, &c->tx_w);

        if (c->state != CONN_STAT_IDLE) {
            warn(WRN, "waiting for close on %s conn %" PRIx64, conn_type(c),
                 c->id);
            loop_run(q_close, c);
        }
    }

    ev_io_stop(loop, &c->rx_w);
    ev_timer_stop(loop, &c->ld_alarm);

    // just free stream 0 (no close handshake)
    struct q_stream * const s = splay_min(stream, &c->streams);
    if (s)
        free_stream(s);
    ensure(splay_empty(&c->streams), "streams remain, e.g., %u",
           splay_min(stream, &c->streams)->id);

    ptls_aead_free(c->in_kp0);
    ptls_aead_free(c->out_kp0);
    diet_free(&c->closed_streams);
    diet_free(&c->acked_pkts);
    diet_free(&c->recv);
    ptls_free(c->tls);
    if (c->sock)
        w_close(c->sock);

    // remove connection from global lists
    splay_remove(ipnp_splay, &conns_by_ipnp, c);
    splay_remove(cid_splay, &conns_by_cid, c);

    warn(WRN, "%s conn %" PRIx64 " closed", conn_type(c), c->id);
    free(c);
}


void q_cleanup(void * const q)
{
    // close all connections
    struct q_conn *c, *tmp;
    for (c = splay_min(cid_splay, &conns_by_cid); c != 0; c = tmp) {
        warn(WRN, "closing %s conn %" PRIx64, conn_type(c), c->id);
        tmp = splay_next(cid_splay, &conns_by_cid, c);
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
