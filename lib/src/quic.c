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

#if !defined(NDEBUG) && !defined(FUZZING)
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "conn.h"
#include "diet.h"
#include "pkt.h"
#include "pn.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"


struct ev_loop;

SPLAY_GENERATE(ooo_by_off, pkt_meta, off_node, ooo_by_off_cmp)

// TODO: many of these globals should move to a per-engine struct


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
#ifndef NDEBUG
    0xbabababa, // XXX reserved version to trigger negotiation
#endif
    0x00001234, // reserved version for inclusion in vneg response
    0xff000010, // draft-ietf-quic-transport-16
    0xff00000f, // draft-ietf-quic-transport-15
};

/// Length of the @p ok_vers array.
const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


struct pkt_meta * pm = 0;
struct ev_loop * loop = 0;

func_ptr api_func = 0;
void *api_conn = 0, *api_strm = 0;

struct q_conn_sl accept_queue = sl_head_initializer(accept_queue);

static const uint32_t nbufs = 100000; ///< Number of packet buffers to allocate.

static ev_timer api_alarm;


#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
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
        EV_VERIFY(loop);                                                       \
        ensure(api_func == 0, "other API call active");                        \
        api_func = (func_ptr)(&(func));                                        \
        api_conn = (conn);                                                     \
        api_strm = (strm);                                                     \
        /* warn(DBG, #func "(" #conn ", " #strm ") entering event loop"); */   \
        ev_run(loop, 0);                                                       \
        api_func = 0;                                                          \
        api_conn = api_strm = 0;                                               \
    } while (0)


void pm_free(struct pkt_meta * const m)
{
    if (m->pn && splay_find(pm_by_nr, &m->pn->sent_pkts, m)) {
        ensure(splay_remove(pm_by_nr, &m->pn->sent_pkts, m), "node removed");
        diet_insert(&m->pn->acked, m->hdr.nr, ev_now(loop));
    }

    if (m->is_rtx)
        return;

    struct pkt_meta * rm = sl_first(&m->rtx);
    while (rm) {
        // warn(CRT, "free rtx iov idx %u nr %" PRIu64, pm_idx(rm), rm->hdr.nr);
        ensure(rm->is_rtx, "is an RTX");
        sl_remove_head(&m->rtx, rtx_next);
        struct pkt_meta * const next_rm = sl_next(rm, rtx_next);
        ensure(splay_remove(pm_by_nr, &rm->pn->sent_pkts, rm), "node removed");
        diet_insert(&rm->pn->acked, rm->hdr.nr, ev_now(loop));
        w_free_iov(w_iov(rm->pn->c->w, pm_idx(rm)));
        memset(rm, 0, sizeof(*rm));
        ASAN_POISON_MEMORY_REGION(rm, sizeof(*rm));
        rm = next_rm;
    }
}


void alloc_off(struct w_engine * const w,
               struct w_iov_sq * const q,
               const uint32_t len,
               const uint16_t off)
{
    w_alloc_len(w, q, len, MAX_PKT_LEN - AEAD_LEN - off, off);
    struct w_iov * v = 0;
    sq_foreach (v, q, next) {
        ASAN_UNPOISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        meta(v).stream_data_start = off;
        // warn(CRT, "q_alloc idx %u len %u", w_iov_idx(v), v->len);
    }
}


void q_alloc(struct w_engine * const w,
             struct w_iov_sq * const q,
             const size_t len)
{
    ensure(len <= UINT32_MAX, "len %u too long", len);
    alloc_off(w, q, (uint32_t)len, OFFSET_ESTB);
}


void q_free(struct w_iov_sq * const q)
{
    struct w_iov * v = sq_first(q);
    while (v) {
        sq_remove_head(q, next);
        struct w_iov * const next = sq_next(v, next);
        free_iov(v);
        v = next;
    }
}


static void __attribute__((nonnull))
do_write(struct q_stream * const s, struct w_iov_sq * const q, const bool fin)
{
    if (fin)
        strm_to_state(s, s->state == strm_hcrm ? strm_clsd : strm_hclo);

    // remember the last iov in the queue
    struct w_iov * const prev_last = sq_last(&s->out, w_iov, next);

    // kick TX watcher
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_write, s->c, s);

    // the last packet in s->out may be a pure FIN - if so, don't return it
    struct w_iov * const last = sq_last(&s->out, w_iov, next);
    if (last && meta(last).stream_header_pos &&
        meta(last).stream_data_len == 0) {
        ensure(sq_next(prev_last, next) == last, "queue messed up");
        sq_remove_after(&s->out, prev_last, next);
        sq_concat(q, &s->out);
        sq_insert_tail(&s->out, last, next);
    } else
        sq_concat(q, &s->out);
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
         c->try_0rtt ? 0 : 1, conn_type(c), cid2str(c->scid),
         inet_ntoa(peer->sin_addr), ntohs(peer->sin_port),
         early_data ? w_iov_sq_len(early_data) : 0,
         plural(early_data ? w_iov_sq_len(early_data) : 0));

    ev_timer_again(loop, &c->idle_alarm);
    w_connect(c->sock, peer->sin_addr.s_addr, peer->sin_port);

    // start TLS handshake
    tls_io(get_stream(c, crpt_strm_id(0)), 0);

    if (early_data) {
        ensure(early_data_stream, "early data without stream pointer");
        // queue up early data
        *early_data_stream = new_stream(c, c->next_sid_bidi);
        concat_out(*early_data_stream, early_data);
        if (fin)
            strm_to_state(*early_data_stream,
                          (*early_data_stream)->state == strm_hcrm ? strm_clsd
                                                                   : strm_hclo);
    }

    ev_async_send(loop, &c->tx_w);

    warn(DBG, "waiting for connect to complete on %s conn %s to %s:%u",
         conn_type(c), cid2str(c->scid), inet_ntoa(peer->sin_addr),
         ntohs(peer->sin_port));
    conn_to_state(c, conn_opng);
    loop_run(q_connect, c, 0);

    if (c->state != conn_estb) {
        warn(WRN, "%s conn %s not connected", conn_type(c), cid2str(c->scid));
        return 0;
    }

    warn(WRN, "%s conn %s connected%s, cipher %s", conn_type(c),
         cid2str(c->scid), c->did_0rtt ? " after 0-RTT" : "",
         c->pn_data.out_1rtt[c->pn_data.out_kyph].aead->algo->name);

    if (c->try_0rtt == true && c->did_0rtt == false) {
        // 0-RTT failed, RTX early data straight away
        reset_stream(*early_data_stream, false);
        ev_async_send(loop, &c->tx_w);
    }

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
         cid2str(s->c->scid), s->id, fin ? "and closing" : "");

    if (s->state >= strm_hclo) {
        warn(ERR, "%s conn %s strm " FMT_SID " is in state %s", conn_type(s->c),
             cid2str(s->c->scid), s->id, strm_state_str[s->state]);
        return;
    }

    // add to stream
    concat_out(s, q);
    do_write(s, q, fin);

    warn(WRN, "wrote %u byte%s on %s conn %s strm " FMT_SID " %s", qlen,
         plural(qlen), conn_type(s->c), cid2str(s->c->scid), s->id,
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
         conn_type(c), cid2str(c->scid));

    struct q_stream * s = 0;
    // cppcheck-suppress knownConditionTrueFalse
    while (s == 0 && c->state == conn_estb) {
        splay_foreach (s, streams_by_id, &c->streams_by_id) {
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
                 conn_type(c), cid2str(c->scid));
            loop_run(q_read, c, 0);
        }
    }

    // return data
    if (s) {
        sq_concat(q, &s->in);
        warn(WRN, "read %u byte%s on %s conn %s strm " FMT_SID, w_iov_sq_len(q),
             plural(w_iov_sq_len(q)), conn_type(s->c), cid2str(s->c->scid),
             s->id);
    }

    return s;
}


void q_readall_str(struct q_stream * const s, struct w_iov_sq * const q)
{
    while (s->c->state == conn_estb && s->state != strm_hcrm &&
           s->state != strm_clsd) {
        warn(WRN, "reading all on %s conn %s strm " FMT_SID, conn_type(s->c),
             cid2str(s->c->scid), s->id);
        loop_run(q_readall_str, s->c, s);
    }

    // return data
    sq_concat(q, &s->in);
    warn(WRN, "read %u byte%s on %s conn %s strm " FMT_SID, w_iov_sq_len(q),
         plural(w_iov_sq_len(q)), conn_type(s->c), cid2str(s->c->scid), s->id);
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
cancel_api_call(struct ev_loop * const l __attribute__((unused)),
                ev_timer * const w __attribute__((unused)),
                int e __attribute__((unused)))
{
    warn(DBG, "canceling API call");
    ev_timer_stop(loop, &api_alarm);
    maybe_api_return(q_accept, 0, 0);
    maybe_api_return(q_rx_ready, 0, 0);
}


struct q_conn * q_accept(const uint64_t timeout)
{
    if (sl_first(&accept_queue)) {
        struct q_conn * const c = sl_first(&accept_queue);
        sl_remove_head(&accept_queue, node_aq);
        warn(WRN, "accepting queued %s conn %s", conn_type(c),
             cid2str(c->scid));
        return c;
    }

    warn(WRN, "waiting for conn on any serv sock (timeout %" PRIu64 " sec)",
         timeout);

    if (timeout) {
        if (ev_is_active(&api_alarm))
            ev_timer_stop(loop, &api_alarm);
        ev_timer_init(&api_alarm, cancel_api_call, timeout, 0);
        ev_timer_start(loop, &api_alarm);
    }

    loop_run(q_accept, 0, 0);

    if (sl_empty(&accept_queue)) {
        warn(ERR, "conn not accepted");
        return 0;
    }

    struct q_conn * const c = sl_first(&accept_queue);
    sl_remove_head(&accept_queue, node_aq);
    ev_timer_again(loop, &c->idle_alarm);

    warn(WRN, "%s conn %s accepted from clnt %s:%u%s, cipher %s", conn_type(c),
         cid2str(c->scid), inet_ntoa(c->peer.sin_addr), ntohs(c->peer.sin_port),
         c->did_0rtt ? " after 0-RTT" : "",
         c->pn_data.in_1rtt[c->pn_data.in_kyph].aead->algo->name);

    return c;
}


struct q_stream * q_rsv_stream(struct q_conn * const c, const bool bidi)
{
    int64_t * const next_sid = bidi ? &c->next_sid_bidi : &c->next_sid_uni;
    int64_t * const max_streams =
        bidi ? &c->tp_out.max_bidi_streams : &c->tp_out.max_uni_streams;

    if (*next_sid >> 2 > *max_streams - 1) {
        // we hit the max stream limit, wait for MAX_STREAM_ID frame
        warn(WRN, "MAX_STREAM_ID increase needed for %s (%u > %u)",
             bidi ? "bidi" : "unidir", *next_sid >> 2, *max_streams);
        loop_run(q_rsv_stream, c, 0);
    }

    ensure(*next_sid >> 2 < *max_streams, "sid %u < max %u", *next_sid >> 2,
           *max_streams);

    return new_stream(c, *next_sid);
}


#ifndef FUZZING
static void __attribute__((noreturn))
signal_cb(struct ev_loop * l,
          ev_signal * w,
          int revents __attribute__((unused)))
{
    ev_break(l, EVBREAK_ALL);
    w_cleanup(w->data);
    exit(0);
}
#endif


#if !defined(NDEBUG) && !defined(FUZZING)
static int __attribute__((nonnull))
mk_or_open_dir(const char * const path, mode_t mode)
{
    int fd = mkdir(path, mode);
    ensure(fd == 0 || fd == -1 && errno == EEXIST, "mkdir %s", path);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    ensure(fd != -1, "open %s", path);
    return fd;
}
#endif


struct w_engine * q_init(const char * const ifname,
                         const char * const cert,
                         const char * const key,
                         const char * const cache,
                         const char * const tls_log,
                         const bool verify_certs,
                         const uint64_t tls_upd_amnt)
{
    // check versions
    // ensure(WARPCORE_VERSION_MAJOR == 0 && WARPCORE_VERSION_MINOR == 12,
    //        "%s version %s not compatible with %s version %s", quant_name,
    //        quant_version, warpcore_name, warpcore_version);

    // init connection structures
    splay_init(&conns_by_ipnp);
    splay_init(&conns_by_id);

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
    init_tls_ctx(cert, key, cache, tls_log, verify_certs, tls_upd_amnt);

    // initialize the event loop
    loop = ev_default_loop(0);

#ifndef FUZZING
    // libev seems to need this inside docker to handle Ctrl-C?
    /// but the fuzzer doesn't like it
    static ev_signal signal_w;
    signal_w.data = w;
    ev_signal_init(&signal_w, signal_cb, SIGINT);
    ev_signal_start(loop, &signal_w);
#endif

#if !defined(NDEBUG) && !defined(NO_FUZZER_CORPUS_COLLECTION)
#ifdef FUZZING
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

    warn(WRN, "closing strm " FMT_SID " state %s on %s conn %s", s->id,
         strm_state_str[s->state], conn_type(s->c), cid2str(s->c->scid));
    strm_to_state(s, s->state == strm_hcrm ? strm_clsd : strm_hclo);
    s->tx_fin = true;
    ev_async_send(loop, &s->c->tx_w);
    loop_run(q_close_stream, s->c, s);
}


void q_close(struct q_conn * const c)
{
    warn(WRN, "closing %s conn %s on port %u", conn_type(c), cid2str(c->scid),
         ntohs(c->sport));

    if (c->state == conn_idle || c->state == conn_clsd ||
        (!c->is_clnt && c->holds_sock))
        // we don't need to do the closing dance in these cases
        goto done;

    if (c->state != conn_drng) {
        conn_to_state(c, conn_qlse);
        ev_async_send(loop, &c->tx_w);
    }

    loop_run(q_close, c, 0);

done:
    free_conn(c);
}


void q_cleanup(struct w_engine * const w)
{
    // close all connections
    while (!splay_empty(&conns_by_id)) {
        struct cid_map * const cm = splay_min(conns_by_id, &conns_by_id);
        warn(DBG, "closing %s conn %s", conn_type(cm->c), cid2str(&cm->cid));
        q_close(cm->c);
    }

    // stop the event loop
    ev_loop_destroy(loop);

    free_tls_ctx();

    // free 0-RTT reordering cache
    while (!splay_empty(&ooo_0rtt_by_cid)) {
        struct ooo_0rtt * const zo =
            splay_min(ooo_0rtt_by_cid, &ooo_0rtt_by_cid);
        ensure(splay_remove(ooo_0rtt_by_cid, &ooo_0rtt_by_cid, zo),
               "node removed");
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

#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
    close(corpus_pkt_dir);
    close(corpus_frm_dir);
#endif
}


char * q_cid(struct q_conn * const c)
{
    return cid2str(c->scid);
}


uint64_t q_sid(const struct q_stream * const s)
{
    return (uint64_t)s->id;
}


bool q_is_str_closed(struct q_stream * const s)
{
    return s->state == strm_clsd;
}


#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
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


struct q_conn * q_rx_ready(const uint64_t timeout)
{
    if (sl_empty(&c_ready)) {
        if (timeout) {
            if (ev_is_active(&api_alarm))
                ev_timer_stop(loop, &api_alarm);
            ev_timer_init(&api_alarm, cancel_api_call, timeout, 0);
            ev_timer_start(loop, &api_alarm);
        }
        loop_run(q_rx_ready, 0, 0);
    }

    struct q_conn * const c = sl_first(&c_ready);
    if (c) {
        sl_remove_head(&c_ready, node_rx_ext);
        c->have_new_data = c->in_c_ready = false;
        warn(WRN, "%s conn %s ready to rx", conn_type(c), cid2str(c->scid));
    }
    return c;
}
