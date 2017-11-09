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
#include <sanitizer/asan_interface.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <ev.h>
#include <picotls.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

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
    0xff000007, // draft-ietf-quic-transport-07
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


int pm_nr_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b)
{
    return (a->nr > b->nr) - (a->nr < b->nr);
}


int pm_off_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b)
{
    return (a->in_off > b->in_off) - (a->in_off < b->in_off);
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
    tls_ctx.random_bytes(c->stateless_reset_token,
                         sizeof(c->stateless_reset_token));

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

    // initialize socket and start an RX/TX watchers
    ev_async_init(&c->tx_w, tx_w);
    c->tx_w.data = c;
    ev_async_start(loop, &c->tx_w);
    c->sock = w_bind(w, htons(port), 0);
    ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);
    c->rx_w.data = c->sock;
    ev_io_start(loop, &c->rx_w);

    // add connection to global data structures
    splay_insert(ipnp_splay, &conns_by_ipnp, c);
    if (c->id)
        splay_insert(cid_splay, &conns_by_cid, c);

    warn(DBG, "%s conn %" PRIx64 " created", conn_type(c), c->id);
    return c;
}


void q_alloc(void * const w, struct w_iov_sq * const q, const uint32_t len)
{
    w_alloc_len(w, q, len, MAX_PKT_LEN - AEAD_LEN, Q_OFFSET);
    struct w_iov * v;
    sq_foreach (v, q, next) {
        ASAN_UNPOISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        // warn(DBG, "q_alloc idx %u", v->idx);
    }
}


void q_free(void * const w, struct w_iov_sq * const q)
{
    struct w_iov * v;
    sq_foreach (v, q, next) {
        meta(v) = (struct pkt_meta){0};
        ASAN_POISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        // warn(DBG, "q_free idx %u", v->idx);
    }
    w_free((struct w_engine *)w, q);
}


struct q_conn * q_connect(void * const q,
                          const struct sockaddr_in * const peer,
                          const char * const peer_name)
{
    // make new connection
    uint64_t cid;
    tls_ctx.random_bytes(&cid, sizeof(cid));
    const uint vers = ok_vers[0];
    struct q_conn * const c = new_conn(q, vers, cid, peer, peer_name, 0);
    warn(WRN, "connecting %s conn %" PRIx64 " to %s:%u w/SNI %s", conn_type(c),
         cid, inet_ntoa(peer->sin_addr), ntohs(peer->sin_port), peer_name);

    c->next_sid = 1; // client initiates odd-numbered streams
    ev_timer_again(loop, &c->idle_alarm);
    w_connect(c->sock, peer->sin_addr.s_addr, peer->sin_port);

    // allocate stream zero and start TLS handshake on stream 0
    struct q_stream * const s = new_stream(c, 0);
    init_tls(c);
    tls_handshake(s);
    ev_async_send(loop, &c->tx_w);

    warn(WRN, "waiting for connect to complete on %s conn %" PRIx64 " to %s:%u",
         conn_type(c), c->id, inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
    loop_run(q_connect, c);

    if (c->state != CONN_STAT_VERS_OK) {
        warn(WRN, "%s conn %" PRIx64 " not connected, state 0x%02x",
             conn_type(c), c->id, c->state);
        return 0;
    }

    c->state = CONN_STAT_ESTB;

    warn(WRN, "%s conn %" PRIx64 " connected", conn_type(c), c->id);
    return c;
}


void q_write(struct q_stream * const s, struct w_iov_sq * const q)
{
    const uint32_t qlen = w_iov_sq_len(q);
    const uint64_t qcnt = w_iov_sq_cnt(q);
    warn(WRN,
         "writing %u byte%s in %" PRIu64 " buf%s on %s conn %" PRIx64 " str %u",
         qlen, plural(qlen), qcnt, plural(qcnt), conn_type(s->c), s->c->id,
         s->id);

    if (s->state >= STRM_STAT_HCLO) {
        warn(ERR, "%s conn %" PRIx64 " str %u is in state %u", conn_type(s->c),
             s->c->id, s->id, s->state);
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

    warn(WRN, "wrote %u byte%s on %s conn %" PRIx64 " str %u", qlen,
         plural(qlen), conn_type(s->c), s->c->id, s->id);

    ensure(w_iov_sq_len(q) == qlen, "payload corrupted, %u != %u",
           w_iov_sq_len(q), qlen);
    ensure(w_iov_sq_cnt(q) == qcnt, "payload corrupted, %u != %u",
           w_iov_sq_cnt(q), qcnt);
}


struct q_stream * q_read(struct q_conn * const c, struct w_iov_sq * const q)
{
    warn(WRN, "reading on %s conn %" PRIx64, conn_type(c), c->id);
    struct q_stream * s = 0;

    while (s == 0) {
        splay_foreach (s, stream, &c->streams)
            if (!sq_empty(&s->in))
                // we found a stream with queued data
                break;

        if (s == 0) {
            // no data queued on any non-zero stream, we need to wait
            warn(WRN, "waiting for data on any stream on %s conn %" PRIx64,
                 conn_type(c), c->id);
            loop_run(q_read, c);
        }
    }

    // return data
    sq_concat(q, &s->in);
    warn(WRN, "read %u byte%s on %s conn %" PRIx64 " str %u", w_iov_sq_len(q),
         plural(w_iov_sq_len(q)), conn_type(s->c), s->c->id, s->id);
    return s;
}


void q_readall_str(struct q_stream * const s, struct w_iov_sq * const q)
{
    warn(WRN, "reading all on %s conn %" PRIx64 " str %u", conn_type(s->c),
         s->c->id, s->id);

    while (s->state != STRM_STAT_HCRM && s->state != STRM_STAT_CLSD)
        loop_run(q_readall_str, s);

    // return data
    sq_concat(q, &s->in);
    warn(WRN, "read %u byte%s on %s conn %" PRIx64 " str %u", w_iov_sq_len(q),
         plural(w_iov_sq_len(q)), conn_type(s->c), s->c->id, s->id);
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
    ev_timer_again(loop, &c->idle_alarm);

    warn(WRN, "%s conn %" PRIx64 " connected to clnt %s:%u", conn_type(c),
         c->id, inet_ntoa(c->peer.sin_addr), ntohs(c->peer.sin_port));
    return c;
}


struct q_stream * q_rsv_stream(struct q_conn * const c)
{

    const uint8_t odd = c->next_sid % 2; // NOTE: % in assert confuses printf
    ensure(c->is_clnt == odd || !c->is_clnt && !odd,
           "am %s, expected %s connection stream ID, got %u", conn_type(c),
           c->is_clnt ? "odd" : "even", c->next_sid);
    ensure(c->next_sid <= c->max_stream_id, "sid %u <= max %u", c->next_sid,
           c->max_stream_id);
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
    ASAN_POISON_MEMORY_REGION(pm, nbufs * sizeof(*pm));

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
    if (s->state == STRM_STAT_HCLO || s->state == STRM_STAT_CLSD)
        return;

    warn(WRN, "closing str %u state %u on %s conn %" PRIx64, s->id, s->state,
         conn_type(s->c), s->c->id);
    s->state = s->state == STRM_STAT_HCRM ? STRM_STAT_CLSD : STRM_STAT_HCLO;
    warn(WRN, "new state %u", s->state);
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_close_stream, s);
}


void q_close(struct q_conn * const c)
{
    if (c->state == CONN_STAT_CLSD)
        return;

    warn(WRN, "closing %s conn %" PRIx64, conn_type(c), c->id);

    // close all streams
    struct q_stream * s;
    splay_foreach (s, stream, &c->streams)
        if (s->id != 0)
            q_close_stream(s);

    // wait until everything is ACKed
    while (rtxable_pkts_outstanding(c) != 0) {
        warn(CRT, "waiting for ACKs");
        ev_async_send(loop, &c->tx_w);
        loop_run(q_close, c);
    }

    // send connection close frame
    c->state = CONN_STAT_CLSD;
    ev_async_send(loop, &c->tx_w);
    loop_run(q_close, c);

    // we're done
    ev_io_stop(loop, &c->rx_w);
    ev_timer_stop(loop, &c->rec.ld_alarm);

    struct q_stream * nxt;
    for (s = splay_min(stream, &c->streams); s; s = nxt) {
        nxt = splay_next(stream, &c->streams, s);
        free_stream(s);
    }

    diet_free(&c->closed_streams);
    diet_free(&c->recv);
    free(c->peer_name);
    if (c->sock)
        w_close(c->sock);
    free_tls(c);

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
    for (c = splay_min(ipnp_splay, &conns_by_ipnp); c != 0; c = tmp) {
        warn(WRN, "closing %s conn %" PRIx64, conn_type(c), c->id);
        tmp = splay_next(ipnp_splay, &conns_by_ipnp, c);
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


bool q_is_str_closed(struct q_stream * const s)
{
    return s->state == STRM_STAT_CLSD;
}
