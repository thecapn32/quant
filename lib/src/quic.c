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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <ev.h>
#include <picotls.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#ifdef HAVE_ASAN
#include <sanitizer/asan_interface.h>
#endif

#include "conn.h"
#include "diet.h"
#include "pkt.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"
#include "tls.h"

struct ev_loop;

SPLAY_GENERATE(pm_nr_splay, pkt_meta, nr_node, pm_nr_cmp)
SPLAY_GENERATE(pm_off_splay, pkt_meta, off_node, pm_off_cmp)

// TODO: many of these globals should move to a per-engine struct


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
#ifndef NDEBUG
    0xbabababa, // XXX reserved version to trigger negotiation
#endif
    0xff000009, // draft-ietf-quic-transport-09
};

/// Length of the @p ok_vers array.
const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


struct pkt_meta * pm = 0;
struct ev_loop * loop = 0;

func_ptr api_func = 0;
void * api_arg = 0;

struct q_conn * accept_queue = 0;

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


int pm_nr_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b)
{
    return (a->nr > b->nr) - (a->nr < b->nr);
}


int pm_off_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b)
{
    return (a->stream_off > b->stream_off) - (a->stream_off < b->stream_off);
}


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
    arc4random_buf(c->stateless_reset_token, sizeof(c->stateless_reset_token));

    if (peer_name) {
        c->is_clnt = true;
        ensure(c->peer_name = strdup(peer_name), "could not dup peer_name");
    }

    // initialize recovery state
    rec_init(c);

    splay_init(&c->streams);
    diet_init(&c->closed_streams);
    diet_init(&c->recv);

    // initialize idle timeout
    c->idle_alarm.data = c;
    c->idle_alarm.repeat = kIdleTimeout;
    ev_init(&c->idle_alarm, idle_alarm);

    // initialize ACK timeout
    c->ack_alarm.data = c;
    c->ack_alarm.repeat = kDelayedAckTimeout;
    ev_init(&c->ack_alarm, ack_alarm);

    c->tp_peer.ack_del_exp = c->tp_local.ack_del_exp = 3;
    c->tp_local.idle_to = kIdleTimeout;
    // XXX: check IDs if stream 0 is flow-controlled during handshake or not
    c->tp_local.max_data = 0x4000;
    c->tp_local.max_strm_data = 0x2000;
    c->tp_local.max_strm_bidi = c->is_clnt ? 1 : 4;
    c->tp_local.max_strm_uni = 0; // TODO: support unidir streams

    // initialize socket and start an RX/TX watchers
    ev_async_init(&c->tx_w, tx_w);
    c->tx_w.data = c;
    ev_async_start(loop, &c->tx_w);
    c->sock = w_bind(w, htons(port), 0);
    c->sport = w_get_sport(c->sock);
    ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);
    c->rx_w.data = c->sock;
    ev_io_start(loop, &c->rx_w);

    // add connection to global data structures
    splay_insert(ipnp_splay, &conns_by_ipnp, c);
    if (c->id)
        splay_insert(cid_splay, &conns_by_cid, c);

    warn(DBG, "%s conn " FMT_CID " on port %u created", conn_type(c), c->id,
         port);
    return c;
}


void q_alloc(void * const w, struct w_iov_sq * const q, const uint32_t len)
{
    w_alloc_len(w, q, len, MAX_PKT_LEN - AEAD_LEN - Q_OFFSET, Q_OFFSET);
    struct w_iov * v = 0;
    sq_foreach (v, q, next) {
        ASAN_UNPOISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        // warn(CRT, "q_alloc idx %u len %u", w_iov_idx(v), v->len);
    }
}


void q_free(struct w_iov_sq * const q)
{
    struct w_iov * v = sq_first(q);
    while (v) {
        struct w_iov * const next = sq_next(v, next);
        // warn(CRT, "q_free idx %u str %d", w_iov_idx(v),
        //      meta(v).stream ? meta(v).stream->id : -1);
        if (meta(v).stream)
            splay_remove(pm_nr_splay, &meta(v).stream->c->rec.sent_pkts,
                         &meta(v));
        meta(v) = (struct pkt_meta){0};
        ASAN_POISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        v = next;
    }
    w_free(q);
}


struct q_conn * q_connect(void * const q,
                          const struct sockaddr_in * const peer,
                          const char * const peer_name,
                          struct w_iov_sq * const early_data,
                          struct q_stream ** const early_data_stream)
{
    // make new connection
    uint64_t cid;
    arc4random_buf(&cid, sizeof(cid));
    const uint vers = ok_vers[0];
    struct q_conn * const c = new_conn(q, vers, cid, peer, peer_name, 0);

    // allocate stream zero and inti TLS
    struct q_stream * const s = new_stream(c, 0, true);
    init_tls(c);

    warn(WRN,
         "new %u-RTT %s conn " FMT_CID " to %s:%u, %u byte%s queued for TX",
         c->try_0rtt ? 0 : 1, conn_type(c), cid, inet_ntoa(peer->sin_addr),
         ntohs(peer->sin_port), w_iov_sq_len(early_data),
         plural(w_iov_sq_len(early_data)));

    ev_timer_again(loop, &c->idle_alarm);
    w_connect(c->sock, peer->sin_addr.s_addr, peer->sin_port);

    // start TLS handshake on stream 0
    tls_io(s, 0);

    if (early_data) {
        ensure(early_data_stream, "early data without stream pointer");
        if (s->c->try_0rtt)
            init_0rtt_prot(c);
        // queue up early data
        *early_data_stream = new_stream(c, c->next_sid, true);
        sq_concat(&(*early_data_stream)->out, early_data);
    }

    ev_async_send(loop, &c->tx_w);

    warn(DBG, "waiting for connect to complete on %s conn " FMT_CID " to %s:%u",
         conn_type(c), c->id, inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
    loop_run(q_connect, c);

    if (c->state != CONN_STAT_HSHK_DONE) {
        warn(WRN, "%s conn " FMT_CID " not connected, state 0x%02x",
             conn_type(c), c->id, c->state);
        return 0;
    }

    if (*early_data_stream && early_data && s->c->try_0rtt) {
        if (c->did_0rtt == false) {
            // 0-RTT data was not accepted by server, queue for regular
            // transmit
            warn(WRN, "0-RTT data rejected by server, re-queueing");
            (*early_data_stream)->out_off = 0;
            struct w_iov * v = 0;
            sq_foreach (v, &(*early_data_stream)->out, next) {
                meta(v).tx_len = meta(v).is_acked = 0;
                splay_remove(pm_nr_splay, &meta(v).stream->c->rec.sent_pkts,
                             &meta(v));
            }
        } else
            // hand early data back to app after 0-RTT
            sq_concat(early_data, &(*early_data_stream)->out);
    }

    conn_to_state(c, CONN_STAT_ESTB);

    warn(WRN, "%s conn " FMT_CID " connected%s, cipher %s", conn_type(c), c->id,
         c->did_0rtt ? " after 0-RTT" : "", c->tls.enc_1rtt->algo->name);
    return c;
}


void q_write(struct q_stream * const s, struct w_iov_sq * const q)
{
    const uint32_t qlen = w_iov_sq_len(q);
    const uint64_t qcnt = w_iov_sq_cnt(q);
    warn(WRN,
         "writing %u byte%s in %u buf%s on %s conn " FMT_CID " str " FMT_SID,
         qlen, plural(qlen), qcnt, plural(qcnt), conn_type(s->c), s->c->id,
         s->id);

    if (s->state >= STRM_STAT_HCLO) {
        warn(ERR, "%s conn " FMT_CID " str " FMT_SID " is in state %u",
             conn_type(s->c), s->c->id, s->id, s->state);
        return;
    }

    // add to stream
    sq_concat(&s->out, q);
    s->out_ack_cnt = 0;

    // remember the last iov in the queue
    struct w_iov * const prev_last = sq_last(&s->out, w_iov, next);

    // kick TX watcher
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_write, s);

    // the last packet in s->out may be a pure FIN - if so, don't return it
    struct w_iov * const last = sq_last(&s->out, w_iov, next);
    if (last && meta(last).stream_header_pos && stream_data_len(last) == 0) {
        ensure(sq_next(prev_last, next) == last, "queue messed up");
        sq_remove_after(&s->out, prev_last, next);
        sq_concat(q, &s->out);
        sq_insert_tail(&s->out, last, next);
    } else
        sq_concat(q, &s->out);
    s->out_ack_cnt = 0;

    warn(WRN, "wrote %u byte%s on %s conn " FMT_CID " str " FMT_SID, qlen,
         plural(qlen), conn_type(s->c), s->c->id, s->id);

    ensure(w_iov_sq_len(q) == qlen, "payload corrupted, %u != %u",
           w_iov_sq_len(q), qlen);
    ensure(w_iov_sq_cnt(q) == qcnt, "payload corrupted, %u != %u",
           w_iov_sq_cnt(q), qcnt);
}


struct q_stream * q_read(struct q_conn * const c, struct w_iov_sq * const q)
{
    if (c->state == CONN_STAT_CLSD)
        return 0;

    warn(WRN, "reading on %s conn " FMT_CID, conn_type(c), c->id);
    struct q_stream * s = 0;

    while (s == 0 && c->state != CONN_STAT_CLSD) {
        splay_foreach (s, stream, &c->streams) {
            if (s->state == STRM_STAT_CLSD)
                continue;

            if (!sq_empty(&s->in))
                // we found a stream with queued data
                break;
        }

        if (s == 0) {
            // no data queued on any non-zero stream, we need to wait
            warn(WRN, "waiting for data on any stream on %s conn " FMT_CID,
                 conn_type(c), c->id);
            loop_run(q_read, c);
        }
    }

    // return data
    if (s) {
        sq_concat(q, &s->in);
        warn(WRN, "read %u byte%s on %s conn " FMT_CID " str " FMT_SID,
             w_iov_sq_len(q), plural(w_iov_sq_len(q)), conn_type(s->c),
             s->c->id, s->id);
    }

    return s;
}


void q_readall_str(struct q_stream * const s, struct w_iov_sq * const q)
{
    warn(WRN, "reading all on %s conn " FMT_CID " str " FMT_SID,
         conn_type(s->c), s->c->id, s->id);

    while (s->state != STRM_STAT_HCRM && s->state != STRM_STAT_CLSD)
        loop_run(q_readall_str, s);

    // return data
    sq_concat(q, &s->in);
    warn(WRN, "read %u byte%s on %s conn " FMT_CID " str " FMT_SID,
         w_iov_sq_len(q), plural(w_iov_sq_len(q)), conn_type(s->c), s->c->id,
         s->id);
}


struct q_conn * q_bind(void * const q, const uint16_t port)
{
    // bind socket and create new embryonic server connection
    warn(INF, "binding serv socket on port %u", port);
    struct q_conn * const c = new_conn(q, 0, 0, 0, 0, port);
    warn(WRN, "bound %s socket on port %u", conn_type(c), port);
    return c;
}


struct q_conn * q_accept(void * const q __attribute__((unused)))
{
    warn(WRN, "waiting for accept on any serv conn");

    if (accept_queue && accept_queue->state >= CONN_STAT_HSHK_DONE) {
        warn(WRN, "got %s conn " FMT_CID, conn_type(accept_queue),
             accept_queue->id);
        return accept_queue;
    }

    accept_queue = 0;
    loop_run(q_accept, accept_queue);

    if (accept_queue == 0 || accept_queue->state != CONN_STAT_HSHK_DONE) {
        if (accept_queue)
            q_close(accept_queue);
        warn(ERR, "conn not accepted");
        return 0;
    }

    conn_to_state(accept_queue, CONN_STAT_ESTB);
    ev_timer_again(loop, &accept_queue->idle_alarm);

    warn(WRN, "%s conn " FMT_CID " connected to clnt %s:%u%s, cipher %s",
         conn_type(accept_queue), accept_queue->id,
         inet_ntoa(accept_queue->peer.sin_addr),
         ntohs(accept_queue->peer.sin_port),
         accept_queue->did_0rtt ? " after 0-RTT" : "",
         accept_queue->tls.enc_1rtt->algo->name);
    return accept_queue;
}


struct q_stream * q_rsv_stream(struct q_conn * const c)
{
    if (c->next_sid > c->tp_peer.max_strm_bidi) {
        // we hit the max stream limit, wait for MAX_STREAM_ID frame
        warn(WRN, "MAX_STREAM_ID increase needed (%u > %u)", c->next_sid,
             c->tp_peer.max_strm_bidi);
        loop_run(q_rsv_stream, c);
    }

    ensure(c->next_sid <= c->tp_peer.max_strm_bidi, "sid %u <= max %u",
           c->next_sid, c->tp_peer.max_strm_bidi);

    return new_stream(c, c->next_sid, true);
}


static void __attribute__((noreturn))
signal_cb(struct ev_loop * l,
          ev_signal * w,
          int revents __attribute__((unused)))
{
    ev_break(l, EVBREAK_ALL);
    w_cleanup(w->data);
    exit(0);
}


void * q_init(const char * const ifname,
              const char * const cert,
              const char * const key,
              const char * const cache)
{
    // check versions
    // ensure(WARPCORE_VERSION_MAJOR == 0 && WARPCORE_VERSION_MINOR == 12,
    //        "%s version %s not compatible with %s version %s", quant_name,
    //        quant_version, warpcore_name, warpcore_version);

    // init connection structures
    splay_init(&conns_by_ipnp);
    splay_init(&conns_by_cid);

    // initialize warpcore on the given interface
    struct w_engine * const w = w_init(ifname, 0, nbufs);
    pm = calloc(nbufs + 1, sizeof(*pm));
    ensure(pm, "could not calloc");
    ASAN_POISON_MEMORY_REGION(pm, (nbufs + 1) * sizeof(*pm));

    warn(INF, "%s/%s %s/%s with libev %u.%u ready", quant_name, w->backend_name,
         quant_version, QUANT_COMMIT_HASH_ABBREV_STR, ev_version_major(),
         ev_version_minor());
    warn(INF, "submit bug reports at https://github.com/NTAP/quant/issues");

    // initialize TLS context
    init_tls_ctx(cert, key, cache);

    // initialize the event loop
    loop = ev_default_loop(0);

    // libev seems to need this inside docker to handle Ctrl-C?
    static ev_signal signal_w;
    signal_w.data = w;
    ev_signal_init(&signal_w, signal_cb, SIGINT);
    ev_signal_start(loop, &signal_w);

    return w;
}


void q_close_stream(struct q_stream * const s)
{
    if (s->state == STRM_STAT_HCLO || s->state == STRM_STAT_CLSD)
        return;

    warn(WRN, "closing str " FMT_SID " state %u on %s conn " FMT_CID, s->id,
         s->state, conn_type(s->c), s->c->id);
    strm_to_state(s,
                  s->state == STRM_STAT_HCRM ? STRM_STAT_CLSD : STRM_STAT_HCLO);
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_close_stream, s);
}


void q_close(struct q_conn * const c)
{
    if (c->state > CONN_STAT_IDLE && c->state < CONN_STAT_CLNG) {
        warn(WRN, "closing %s conn " FMT_CID, conn_type(c), c->id);

        // close all streams
        struct q_stream * s;
        splay_foreach (s, stream, &c->streams)
            if (s->id != 0)
                q_close_stream(s);

        // send connection close frame
        conn_to_state(c, CONN_STAT_CLNG);
        ev_async_send(loop, &c->tx_w);
        loop_run(q_close, c);
    }

    // we're done
    ev_io_stop(loop, &c->rx_w);
    ev_timer_stop(loop, &c->rec.ld_alarm);
    ev_timer_stop(loop, &c->closing_alarm);
    ev_timer_stop(loop, &c->idle_alarm);
    ev_timer_stop(loop, &c->ack_alarm);

    struct q_stream *s, *ns;
    for (s = splay_min(stream, &c->streams); s; s = ns) {
        ns = splay_next(stream, &c->streams, s);
        free_stream(s);
    }

    struct pkt_meta *p, *np;
    for (p = splay_min(pm_nr_splay, &c->rec.sent_pkts); p; p = np) {
        np = splay_next(pm_nr_splay, &c->rec.sent_pkts, p);
        q_free_iov(c, w_iov(w_engine(c->sock), pm_idx(p)));
    }

    diet_free(&c->closed_streams);
    diet_free(&c->recv);
    free(c->peer_name);
    free_tls(c);
    if (c->err_reason)
        free(c->err_reason);

    // remove connection from global lists
    splay_remove(ipnp_splay, &conns_by_ipnp, c);
    splay_remove(cid_splay, &conns_by_cid, c);

    if (c->sock)
        w_close(c->sock);

    warn(WRN, "%s conn " FMT_CID " closed", conn_type(c), c->id);
    free(c);
}


void q_cleanup(void * const q)
{
    // close all connections
    struct q_conn *c, *tmp;
    for (c = splay_min(cid_splay, &conns_by_cid); c != 0; c = tmp) {
        warn(WRN, "closing %s conn " FMT_CID, conn_type(c), c->id);
        tmp = splay_next(cid_splay, &conns_by_cid, c);
        q_close(c);
    }
    for (c = splay_min(ipnp_splay, &conns_by_ipnp); c != 0; c = tmp) {
        warn(WRN, "closing %s conn " FMT_CID, conn_type(c), c->id);
        tmp = splay_next(ipnp_splay, &conns_by_ipnp, c);
        q_close(c);
    }

    // stop the event loop
    ev_loop_destroy(loop);

    cleanup_tls_ctx();

    for (uint32_t i = 0; i <= nbufs; i++) {
        ASAN_UNPOISON_MEMORY_REGION(&pm[i], sizeof(pm[i]));
        if (pm[i].nr)
            warn(DBG, "buffer %u still in use for pkt %" PRIu64, i, pm[i].nr);
    }

    free(pm);
    w_cleanup(q);
}


uint64_t q_cid(const struct q_conn * const c)
{
    return c->id;
}


uint64_t q_sid(const struct q_stream * const s)
{
    return s->id;
}


bool q_is_str_closed(struct q_stream * const s)
{
    return s->state == STRM_STAT_CLSD;
}
