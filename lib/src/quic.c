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

#if !defined(NDEBUG) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "conn.h"
#include "pkt.h"
#include "pn.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"


struct ev_loop;

SPLAY_GENERATE(pm_off_splay, pkt_meta, off_node, pm_off_cmp)

// TODO: many of these globals should move to a per-engine struct


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
#if !defined(NDEBUG) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    0xbabababa, // XXX reserved version to trigger negotiation
#endif
    0xff00000d, // draft-ietf-quic-transport-13
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


#if !defined(NDEBUG) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) &&  \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
int corpus_pkt_dir, corpus_frm_dir;
#endif


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


int pm_off_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b)
{
    return (a->stream_off > b->stream_off) - (a->stream_off < b->stream_off);
}


static void __attribute__((nonnull)) sq_unpoison(struct w_iov_sq * const q)
{
    struct w_iov * v = 0;
    sq_foreach (v, q, next) {
        ASAN_UNPOISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        // warn(CRT, "q_alloc idx %u len %u", w_iov_idx(v), v->len);
    }
}


// static void __attribute__((nonnull)) q_alloc_cnt(struct w_engine * const w,
//                                                  struct w_iov_sq * const q,
//                                                  const uint32_t cnt)
// {
//     w_alloc_cnt(w, q, cnt, MAX_PKT_LEN - AEAD_LEN - Q_OFFSET, Q_OFFSET);
//     sq_unpoison(q);
// }


void q_alloc(struct w_engine * const w,
             struct w_iov_sq * const q,
             const uint32_t len)
{
    w_alloc_len(w, q, len, MAX_PKT_LEN - AEAD_LEN - Q_OFFSET, Q_OFFSET);
    sq_unpoison(q);
}


void q_free(struct w_iov_sq * const q)
{
    struct w_iov * v = sq_first(q);
    while (v) {
        sq_remove_head(q, next);
        struct w_iov * const next = sq_next(v, next);
        q_free_iov(v);
        v = next;
    }
}


static void __attribute__((nonnull))
do_write(struct q_stream * const s, struct w_iov_sq * const q, const bool fin)
{
    s->out_ack_cnt = 0;

    if (fin)
        strm_to_state(s, s->state == strm_hcrm ? strm_clsd : strm_hclo);

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

    // init TLS
    init_tls(c);
    init_tp(c);

    warn(WRN, "new %u-RTT %s conn %s to %s:%u, %u byte%s queued for TX",
         c->try_0rtt ? 0 : 1, conn_type(c), scid2str(c),
         inet_ntoa(peer->sin_addr), ntohs(peer->sin_port),
         early_data ? w_iov_sq_len(early_data) : 0,
         plural(early_data ? w_iov_sq_len(early_data) : 0));

    ev_timer_again(loop, &c->idle_alarm);
    w_connect(c->sock, peer->sin_addr.s_addr, peer->sin_port);

    // start TLS handshake
    tls_io(get_stream(c, crpt_strm_id(0)), 0);

    if (early_data) {
        ensure(early_data_stream, "early data without stream pointer");
        // if (c->try_0rtt)
        //     init_0rtt_prot(c);
        // queue up early data
        *early_data_stream = new_stream(c, c->next_sid, true);
        sq_concat(&(*early_data_stream)->out, early_data);
        if (fin)
            strm_to_state(*early_data_stream,
                          (*early_data_stream)->state == strm_hcrm ? strm_clsd
                                                                   : strm_hclo);
    }

    ev_async_send(loop, &c->tx_w);

    warn(DBG, "waiting for connect to complete on %s conn %s to %s:%u",
         conn_type(c), scid2str(c), inet_ntoa(peer->sin_addr),
         ntohs(peer->sin_port));
    conn_to_state(c, conn_opng);
    loop_run(q_connect, c, 0);

    if (c->state != conn_estb) {
        warn(WRN, "%s conn %s not connected", conn_type(c), scid2str(c));
        return 0;
    }

    // if (early_data && *early_data_stream) {
    //     if (c->did_0rtt == false ||
    //         is_fully_acked(*early_data_stream) == false) {
    //         warn(DBG, "%s on strm " FMT_SID,
    //              c->did_0rtt ? "0-RTT data not fully ACK'ed yet"
    //                          : "TX early data after 1-RTT handshake",
    //              (*early_data_stream)->id);
    //         do_write(*early_data_stream, early_data, fin);
    //     } else
    //         // hand early data back to app after 0-RTT
    //         sq_concat(early_data, &(*early_data_stream)->out);
    // }

    warn(WRN, "%s conn %s connected%s, cipher %s", conn_type(c), scid2str(c),
         c->did_0rtt ? " after 0-RTT" : "",
         c->pn_data.out_1rtt.aead->algo->name);
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

    if (s->state >= strm_hclo) {
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
    if (c->state == conn_clsd)
        return 0;

    warn(WRN, "%sblocking read on %s conn %s", block ? "" : "non-",
         conn_type(c), scid2str(c));
    struct q_stream * s = 0;

    while (s == 0 && c->state == conn_estb) {
        splay_foreach (s, stream, &c->streams) {
            if (s->state == strm_clsd)
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

    while (s->c->state == conn_estb && s->state != strm_hcrm &&
           s->state != strm_clsd)
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

    if (accept_queue && accept_queue->state == conn_estb) {
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

    if (accept_queue == 0 || accept_queue->state != conn_estb) {
        if (accept_queue)
            q_close(accept_queue);
        warn(ERR, "conn not accepted");
        return 0;
    }

    ev_timer_again(loop, &accept_queue->idle_alarm);

    warn(WRN, "%s conn %s accepted from clnt %s:%u%s, cipher %s",
         conn_type(accept_queue), scid2str(accept_queue),
         inet_ntoa(accept_queue->peer.sin_addr),
         ntohs(accept_queue->peer.sin_port),
         accept_queue->did_0rtt ? " after 0-RTT" : "",
         accept_queue->pn_data.out_1rtt.aead->algo->name);

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


#if !defined(NDEBUG) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
static int __attribute__((nonnull))
mk_or_open_dir(const char * const path, mode_t mode)
{
    int fd = mkdir(path, mode);
    if (fd == -1 && errno == EEXIST)
        fd = open(path, O_RDONLY | O_CLOEXEC);
    ensure(fd != -1, "mk_or_open_dir %s", path);
    return fd;
}
#endif


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

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // libev seems to need this inside docker to handle Ctrl-C?
    static ev_signal signal_w;
    signal_w.data = w;
    ev_signal_init(&signal_w, signal_cb, SIGINT);
    ev_signal_start(loop, &signal_w);
#endif

#if !defined(NDEBUG) && !defined(NO_FUZZER_CORPUS_COLLECTION)
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    warn(CRT, "%s compiled for fuzzing - will not communicate", quant_name);
#else
    // create the directories for exporting fuzzer corpus data
    warn(NTE, "debug build, storing fuzzer corpus data");
    corpus_pkt_dir = mk_or_open_dir("corpus_pkt", 0755);
    corpus_frm_dir = mk_or_open_dir("corpus_frm", 0755);
#endif
#endif

    return w;
}


void q_close_stream(struct q_stream * const s)
{
    if (s->state == strm_hclo || s->state == strm_clsd)
        return;

    warn(WRN, "closing strm " FMT_SID " state %u on %s conn %s", s->id,
         s->state, conn_type(s->c), scid2str(s->c));
    strm_to_state(s, s->state == strm_hcrm ? strm_clsd : strm_hclo);
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_close_stream, s->c, s);
}


void q_close(struct q_conn * const c)
{
    if (c->state != conn_idle && c->state != conn_clsg &&
        c->state != conn_drng && c->state != conn_clsd) {
        warn(WRN, "closing %s conn %s on port %u", conn_type(c), scid2str(c),
             ntohs(c->sport));

        // close all streams
        struct q_stream * s;
        splay_foreach (s, stream, &c->streams)
            if (s->id >= 0)
                q_close_stream(s);

        if (c->state == conn_opng)
            conn_to_state(c, conn_clsd);
        else {
            // send connection close frame
            enter_closing(c);
            ev_async_send(loop, &c->tx_w);
            loop_run(q_close, c, 0);
        }
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

    free_tls_ctx();

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

#if !defined(NDEBUG) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) &&  \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
    close(corpus_pkt_dir);
    close(corpus_frm_dir);
#endif
}


char * q_cid(const struct q_conn * const c)
{
    return scid2str(c);
}


uint64_t q_sid(const struct q_stream * const s)
{
    return (uint64_t)s->id;
}


bool q_is_str_closed(struct q_stream * const s)
{
    return s->state == strm_clsd;
}


#if !defined(NDEBUG) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) &&  \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
void write_to_corpus(const int dir, const void * const data, const size_t len)
{
    char file[MAXPATHLEN], rand[16];
    arc4random_buf(rand, sizeof(rand));
    strncpy(file, hex2str(rand, sizeof(rand)), MAXPATHLEN);
    const int fd =
        openat(dir, file, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
    ensure(fd != -1, "cannot open");
    ensure(write(fd, data, len) != -1, "cannot write %s", file);
    close(fd);
}
#endif
