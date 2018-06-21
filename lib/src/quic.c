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
#include <sys/types.h>

#include <ev.h>
#include <picotls.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#ifdef HAVE_ASAN
#include <sanitizer/asan_interface.h>
#endif

#include "conn.h"
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
    0xff00000c, // draft-ietf-quic-transport-12
};

/// Length of the @p ok_vers array.
const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


struct pkt_meta * pm = 0;
struct ev_loop * loop = 0;

func_ptr api_func = 0;
void *api_conn = 0, *api_strm = 0;

struct q_conn * accept_queue = 0;

static const uint32_t nbufs = 1000; ///< Number of packet buffers to allocate.

static ev_timer accept_alarm;


/// Run the event loop for the API function @p func with connection @p conn and
/// (optionally, if non-zero) stream @p strm.
///
/// @param      func  The API function to run the event loop for.
/// @param      conn  The connection to run the event loop for.
/// @param      strm  The stream to run the event loop for.
///
#define loop_run(func, conn, strm)                                             \
    do {                                                                       \
        ensure(api_func == 0, "other API call active");                        \
        api_func = (func_ptr)(&(func));                                        \
        api_conn = (conn);                                                     \
        api_strm = (strm);                                                     \
        warn(DBG, #func "(" #conn ", " #strm ") entering event loop");         \
        ev_run(loop, 0);                                                       \
        api_func = 0;                                                          \
        api_conn = api_strm = 0;                                               \
    } while (0)


int pm_nr_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b)
{
    return (a->hdr.nr > b->hdr.nr) - (a->hdr.nr < b->hdr.nr);
}


int pm_off_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b)
{
    return (a->stream_off > b->stream_off) - (a->stream_off < b->stream_off);
}


void q_alloc(struct w_engine * const w,
             struct w_iov_sq * const q,
             const uint32_t len)
{
    w_alloc_len(w, q, len, MAX_PKT_LEN - AEAD_LEN - Q_OFFSET, Q_OFFSET);
    struct w_iov * v = 0;
    sq_foreach (v, q, next) {
        ASAN_UNPOISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        // warn(CRT, "q_alloc idx %u len %u", w_iov_idx(v), v->len);
    }
}


void free_iov_sq(struct w_iov_sq * const q, struct q_conn * const c)
{
    struct w_iov * v = sq_first(q);
    while (v) {
        struct w_iov * const next = sq_next(v, next);
        // warn(CRT, "q_free idx %u strm %d %" PRIu64, w_iov_idx(v),
        //      meta(v).stream ? meta(v).stream->id : -1, meta(v).hdr.nr);
        if (c)
            splay_remove(pm_nr_splay, &c->rec.sent_pkts, &meta(v));
        meta(v) = (struct pkt_meta){0};
        ASAN_POISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        v = next;
    }
    w_free(q);
}


void q_free(struct w_iov_sq * const q)
{
    free_iov_sq(q, 0);
}


static void __attribute__((nonnull))
do_write(struct q_stream * const s, struct w_iov_sq * const q, const bool fin)
{
    s->out_ack_cnt = 0;

    if (fin)
        strm_to_state(s, s->state == STRM_STAT_HCRM ? STRM_STAT_CLSD
                                                    : STRM_STAT_HCLO);

    // remember the last iov in the queue
    struct w_iov * const prev_last = sq_last(&s->out, w_iov, next);

    // kick TX watcher
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_write, s->c, s);

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
}


struct q_conn * q_connect(struct w_engine * const w,
                          const struct sockaddr_in * const peer,
                          const char * const peer_name,
                          struct w_iov_sq * const early_data,
                          struct q_stream ** const early_data_stream,
                          const bool fin,
                          const uint64_t idle_timeout)
{
    // make new connection
    const uint vers = ok_vers[0];
    struct q_conn * const c =
        new_conn(w, vers, 0, 0, peer, peer_name, 0, idle_timeout);

    // allocate stream zero and init TLS
    struct q_stream * const s = new_stream(c, 0, true);
    init_tls(c);
    init_tp(c);

    warn(WRN, "new %u-RTT %s conn %s to %s:%u, %u byte%s queued for TX",
         c->try_0rtt ? 0 : 1, conn_type(c), scid2str(c),
         inet_ntoa(peer->sin_addr), ntohs(peer->sin_port),
         early_data ? w_iov_sq_len(early_data) : 0,
         plural(early_data ? w_iov_sq_len(early_data) : 0));

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
        if (fin)
            strm_to_state(*early_data_stream,
                          (*early_data_stream)->state == STRM_STAT_HCRM
                              ? STRM_STAT_CLSD
                              : STRM_STAT_HCLO);
    }

    ev_async_send(loop, &c->tx_w);

    warn(DBG, "waiting for connect to complete on %s conn %s to %s:%u",
         conn_type(c), scid2str(c), inet_ntoa(peer->sin_addr),
         ntohs(peer->sin_port));
    loop_run(q_connect, c, 0);

    if (c->state != CONN_STAT_ESTB) {
        warn(WRN, "%s conn %s not connected", conn_type(c), scid2str(c));
        return 0;
    }

    if (early_data && *early_data_stream) {
        if (c->did_0rtt == false ||
            is_fully_acked(*early_data_stream) == false) {
            warn(DBG, "%s on strm " FMT_SID,
                 c->did_0rtt ? "0-RTT data not fully ACK'ed yet"
                             : "TX early data after 1-RTT handshake",
                 (*early_data_stream)->id);
            do_write(*early_data_stream, early_data, fin);
        } else
            // hand early data back to app after 0-RTT
            sq_concat(early_data, &(*early_data_stream)->out);
    }

    warn(WRN, "%s conn %s connected%s, cipher %s", conn_type(c), scid2str(c),
         c->did_0rtt ? " after 0-RTT" : "",
         c->tls.out_pp.one_rtt[0].aead->algo->name);
    return c;
}


void q_write(struct q_stream * const s,
             struct w_iov_sq * const q,
             const bool fin)
{
    const uint32_t qlen = w_iov_sq_len(q);
    const uint64_t qcnt = w_iov_sq_cnt(q);
    warn(WRN, "writing %u byte%s in %u buf%s on %s conn %s strm " FMT_SID " %s",
         qlen, plural(qlen), qcnt, plural(qcnt), conn_type(s->c),
         scid2str(s->c), s->id, fin ? "and closing" : "");

    if (s->state >= STRM_STAT_HCLO) {
        warn(ERR, "%s conn %s strm " FMT_SID " is in state %u", conn_type(s->c),
             scid2str(s->c), s->id, s->state);
        return;
    }

    // add to stream
    sq_concat(&s->out, q);
    do_write(s, q, fin);

    warn(WRN, "wrote %u byte%s on %s conn %s strm " FMT_SID " %s", qlen,
         plural(qlen), conn_type(s->c), scid2str(s->c), s->id,
         fin ? "and closed" : "");

    ensure(w_iov_sq_len(q) == qlen, "payload corrupted, %u != %u",
           w_iov_sq_len(q), qlen);
    ensure(w_iov_sq_cnt(q) == qcnt, "payload corrupted, %u != %u",
           w_iov_sq_cnt(q), qcnt);
}


struct q_stream *
q_read(struct q_conn * const c, struct w_iov_sq * const q, const bool block)
{
    if (c->state == CONN_STAT_CLSD)
        return 0;

    warn(WRN, "%sblocking read on %s conn %s", block ? "" : "non-",
         conn_type(c), scid2str(c));
    struct q_stream * s = 0;

    while (s == 0 && c->state <= CONN_STAT_ESTB) {
        splay_foreach (s, stream, &c->streams) {
            if (s->state == STRM_STAT_CLSD)
                continue;

            if (!sq_empty(&s->in))
                // we found a stream with queued data
                break;
        }

        if (s == 0) {
            // no data queued on any non-zero stream
            if (block == false)
                // don't wait
                break;

            // wait for new data
            warn(WRN, "waiting for data on any stream on %s conn %s",
                 conn_type(c), scid2str(c));
            loop_run(q_read, c, 0);
        }
    }

    // return data
    if (s) {
        sq_concat(q, &s->in);
        warn(WRN, "read %u byte%s on %s conn %s strm " FMT_SID, w_iov_sq_len(q),
             plural(w_iov_sq_len(q)), conn_type(s->c), scid2str(s->c), s->id);
    }

    return s;
}


void q_readall_str(struct q_stream * const s, struct w_iov_sq * const q)
{
    warn(WRN, "reading all on %s conn %s strm " FMT_SID, conn_type(s->c),
         scid2str(s->c), s->id);

    while (s->c->state <= CONN_STAT_ESTB && s->state != STRM_STAT_HCRM &&
           s->state != STRM_STAT_CLSD)
        loop_run(q_readall_str, s->c, s);

    // return data
    sq_concat(q, &s->in);
    warn(WRN, "read %u byte%s on %s conn %s strm " FMT_SID, w_iov_sq_len(q),
         plural(w_iov_sq_len(q)), conn_type(s->c), scid2str(s->c), s->id);
}


struct q_conn * q_bind(struct w_engine * const w, const uint16_t port)
{
    // bind socket and create new embryonic server connection
    warn(DBG, "binding serv socket on port %u", port);
    struct q_conn * const c = new_conn(w, 0, 0, 0, 0, 0, port, 0);
    warn(WRN, "bound %s socket on port %u", conn_type(c), port);
    return c;
}


static void __attribute__((nonnull))
cancel_accept(struct ev_loop * const l __attribute__((unused)),
              ev_timer * const w __attribute__((unused)),
              int e __attribute__((unused)))
{
    warn(DBG, "canceling q_accept()");
    ev_timer_stop(loop, &accept_alarm);
    accept_queue = 0;
    maybe_api_return(q_accept, accept_queue, 0);
}


struct q_conn * q_accept(struct w_engine * const w __attribute__((unused)),
                         const uint64_t timeout)
{
    warn(WRN, "waiting for conn on any serv sock (timeout %" PRIu64 " sec)",
         timeout);

    if (accept_queue && accept_queue->state >= CONN_STAT_ESTB) {
        warn(WRN, "got %s conn %s", conn_type(accept_queue),
             scid2str(accept_queue));
        return accept_queue;
    }

    if (timeout) {
        if (ev_is_active(&accept_alarm))
            ev_timer_stop(loop, &accept_alarm);
        ev_timer_init(&accept_alarm, cancel_accept, timeout, 0);
        ev_timer_start(loop, &accept_alarm);
    }

    accept_queue = 0;
    loop_run(q_accept, accept_queue, 0);

    if (accept_queue == 0 || accept_queue->state != CONN_STAT_ESTB) {
        if (accept_queue)
            q_close(accept_queue);
        warn(ERR, "conn not accepted");
        return 0;
    }

    ev_timer_again(loop, &accept_queue->idle_alarm);

    warn(WRN, "%s conn %s connected to clnt %s:%u%s, cipher %s",
         conn_type(accept_queue), scid2str(accept_queue),
         inet_ntoa(accept_queue->peer.sin_addr),
         ntohs(accept_queue->peer.sin_port),
         accept_queue->did_0rtt ? " after 0-RTT" : "",
         accept_queue->tls.out_pp.one_rtt[0].aead->algo->name);

    struct q_conn * const ret = accept_queue;
    accept_queue = 0;

    return ret;
}


struct q_stream * q_rsv_stream(struct q_conn * const c)
{
    if (c->next_sid > c->tp_peer.max_strm_bidi) {
        // we hit the max stream limit, wait for MAX_STREAM_ID frame
        warn(WRN, "MAX_STREAM_ID increase needed (%u > %u)", c->next_sid,
             c->tp_peer.max_strm_bidi);
        loop_run(q_rsv_stream, c, 0);
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


struct w_engine * q_init(const char * const ifname,
                         const char * const cert,
                         const char * const key,
                         const char * const cache,
                         const char * const tls_log,
                         const bool verify_certs)
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
    init_tls_ctx(cert, key, cache, tls_log, verify_certs);

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

    warn(WRN, "closing strm " FMT_SID " state %u on %s conn %s", s->id,
         s->state, conn_type(s->c), scid2str(s->c));
    strm_to_state(s,
                  s->state == STRM_STAT_HCRM ? STRM_STAT_CLSD : STRM_STAT_HCLO);
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_close_stream, s->c, s);
}


void q_close(struct q_conn * const c)
{
    if (c->state > CONN_STAT_IDLE && c->state < CONN_STAT_CLNG) {
        warn(WRN, "closing %s conn %s on port %u", conn_type(c), scid2str(c),
             ntohs(c->sport));

        // close all streams
        struct q_stream * s;
        splay_foreach (s, stream, &c->streams)
            if (s->id != 0)
                q_close_stream(s);

        // send connection close frame
        conn_to_state(c, CONN_STAT_CLNG);
        ev_async_send(loop, &c->tx_w);
        loop_run(q_close, c, 0);
    }

    // we're done
    free_conn(c);
}


void q_cleanup(struct w_engine * const w)
{
    // close all connections
    while (!splay_empty(&conns_by_cid)) {
        struct q_cid_map * const cm = splay_min(cid_splay, &conns_by_cid);
        warn(DBG, "closing %s conn %s", conn_type(cm->c), cid2str(&cm->cid));
        q_close(cm->c);
    }
    while (!splay_empty(&conns_by_ipnp)) {
        struct q_conn * const c = splay_min(ipnp_splay, &conns_by_ipnp);
        warn(DBG, "closing %s conn %s", conn_type(c), scid2str(c));
        q_close(c);
    }

    // stop the event loop
    ev_loop_destroy(loop);

    cleanup_tls_ctx();

    // free 0-RTT reordering cache
    while (!splay_empty(&zrtt_ooo_by_cid)) {
        struct zrtt_ooo * const zo =
            splay_min(zrtt_ooo_splay, &zrtt_ooo_by_cid);
        splay_remove(zrtt_ooo_splay, &zrtt_ooo_by_cid, zo);
        free(zo);
    }

    for (uint32_t i = 0; i <= nbufs; i++) {
        ASAN_UNPOISON_MEMORY_REGION(&pm[i], sizeof(pm[i]));
        if (pm[i].hdr.nr)
            warn(DBG, "buffer %u still in use for pkt %" PRIu64, i,
                 pm[i].hdr.nr);
    }

    free(pm);
    w_cleanup(w);
}


char * q_cid(const struct q_conn * const c)
{
    return scid2str(c);
}


uint64_t q_sid(const struct q_stream * const s)
{
    return s->id;
}


bool q_is_str_closed(struct q_stream * const s)
{
    return s->state == STRM_STAT_CLSD;
}
