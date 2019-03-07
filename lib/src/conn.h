// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
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

#pragma once

#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <ev.h>
#include <khash.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "diet.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "tls.h"


#define cid2str(i)                                                             \
    __extension__({                                                            \
        static char _str[2 * (MAX_CID_LEN + sizeof((i)->seq)) + 1] = "0";      \
        if (i)                                                                 \
            snprintf(_str, sizeof(_str), "%" PRIu64 ":%.*s", (i)->seq,         \
                     2 * (i)->len, hex2str((i)->id, (i)->len));                \
        (i) ? _str : "?";                                                      \
    })


KHASH_MAP_INIT_INT64(streams_by_id, struct q_stream *)
KHASH_MAP_INIT_INT64(conns_by_ipnp, struct q_conn *)


static inline khint_t __attribute__((always_inline, nonnull))
hash_cid(const struct cid * const id)
{
    return fnv1a_32(id->id, id->len);
}


static inline int __attribute__((always_inline, nonnull))
cid_cmp(const struct cid * const a, const struct cid * const b)
{
    return memcmp(&a->len, &b->len, MIN(a->len, b->len) + sizeof(a->len));
}


static inline int __attribute__((always_inline, nonnull))
kh_cid_cmp(const struct cid * const a, const struct cid * const b)
{
    return cid_cmp(a, b) == 0;
}


KHASH_INIT(conns_by_id, struct cid *, struct q_conn *, 1, hash_cid, kh_cid_cmp)


static inline khint_t __attribute__((always_inline, nonnull))
hash_srt(const uint8_t * const srt)
{
    return fnv1a_32(srt, SRT_LEN);
}


static inline int __attribute__((always_inline, nonnull))
kh_srt_cmp(const uint8_t * const a, const uint8_t * const b)
{
    return memcmp(a, b, SRT_LEN) == 0;
}


KHASH_INIT(conns_by_srt, uint8_t *, struct q_conn *, 1, hash_srt, kh_srt_cmp)


extern khash_t(conns_by_ipnp) * conns_by_ipnp;
extern khash_t(conns_by_id) * conns_by_id;
extern khash_t(conns_by_srt) * conns_by_srt;


struct pref_addr {
    struct sockaddr_storage addr4;
    struct sockaddr_storage addr6;
    struct cid cid;
};


struct transport_params {
    uint64_t max_strm_data_uni;
    uint64_t max_strm_data_bidi_local;
    uint64_t max_strm_data_bidi_remote;
    uint64_t max_data;
    int64_t max_streams_uni;
    int64_t max_streams_bidi;
    uint64_t idle_to;
    uint64_t max_ack_del;
    uint64_t max_pkt;
    uint8_t ack_del_exp;
    bool disable_migration;
    uint8_t _unused[6];
    struct pref_addr pref_addr;
    struct cid orig_cid;
};


sl_head(q_conn_sl, q_conn);


#define CONN_STATE(k, v) k = v
#define CONN_STATES                                                            \
    CONN_STATE(conn_clsd, 0), CONN_STATE(conn_idle, 1),                        \
        CONN_STATE(conn_opng, 2), CONN_STATE(conn_estb, 3),                    \
        CONN_STATE(conn_qlse, 4), CONN_STATE(conn_clsg, 5),                    \
        CONN_STATE(conn_drng, 6),


/// Define connection states.
/// \dotfile conn-states.dot "Connection state diagram."
typedef enum { CONN_STATES } conn_state_t;

extern const char * const conn_state_str[];

#define MAX_TOK_LEN 512
#define MAX_ERR_REASON_LEN 64 // keep < 256, since err_reason_len is uint8_t


splay_head(cids_by_seq, cid);

KHASH_INIT(cids_by_id, struct cid *, struct cid *, 1, hash_cid, kh_cid_cmp)


/// A QUIC connection.
struct q_conn {
    sl_entry(q_conn) node_rx_int; ///< For maintaining the internal RX queue.
    sl_entry(q_conn) node_rx_ext; ///< For maintaining the external RX queue.
    sl_entry(q_conn) node_aq;     ///< For maintaining the accept queue.

    struct cids_by_seq dcids_by_seq;   ///< Destination CID hash by sequence.
    struct cids_by_seq scids_by_seq;   ///< Source CID hash by sequence.
    khash_t(cids_by_id) * scids_by_id; ///< Source CID hash by ID.
    struct cid * dcid;                 ///< Active destination CID.
    struct cid * scid;                 ///< Active source CID.

    uint32_t holds_sock : 1;       ///< Connection manages a warpcore socket.
    uint32_t is_clnt : 1;          ///< We are the client on this connection.
    uint32_t had_rx : 1;           ///< We had an RX event on this connection.
    uint32_t needs_tx : 1;         ///< We have a pending TX on this connection.
    uint32_t tx_max_data : 1;      ///< Sent a MAX_DATA frame.
    uint32_t blocked : 1;          ///< We are receive-window-blocked.
    uint32_t sid_blocked_bidi : 1; ///< We are out of bidi stream IDs.
    uint32_t sid_blocked_uni : 1;  ///< We are out of unidir stream IDs.
    uint32_t tx_max_sid_bidi : 1;  ///< Send MAX_STREAM_ID frame for bidi.
    uint32_t tx_max_sid_uni : 1;   ///< Send MAX_STREAM_ID frame for unidir.
    uint32_t try_0rtt : 1;         ///< Try 0-RTT handshake.
    uint32_t did_0rtt : 1;         ///< 0-RTT handshake succeeded;
    uint32_t tx_path_resp : 1;     ///< Send PATH_RESPONSE.
    uint32_t tx_path_chlg : 1;     ///< Send PATH_CHALLENGE.
    uint32_t tx_ncid : 1;          ///< Send NEW_CONNECTION_ID.
    uint32_t tx_rtry : 1;          ///< We need to send a RETRY.
    uint32_t have_new_data : 1;    ///< New stream data was enqueued.
    uint32_t in_c_ready : 1;       ///< Connection is listed in c_ready.
    uint32_t needs_accept : 1;     ///< Need to call q_accept() for connection.
    uint32_t tx_retire_cid : 1;    ///< Send RETIRE_CONNECTION_ID.
    uint32_t do_migration : 1;     ///< Perform a CID migration when possible.
    uint32_t key_flips_enabled : 1; ///< Are TLS key updates enabled?
    uint32_t do_key_flip : 1;       ///< Perform a TLS key update.
    uint32_t spinbit_enabled : 1;   ///< Is the spinbit enabled?
    uint32_t next_spin : 1;         ///< Spin value to set on next packet sent.
    uint32_t no_wnd : 1;            ///< TX is stalled by lack of window.
    uint32_t : 6;

    conn_state_t state; ///< State of the connection.

    struct w_engine * w; ///< Underlying warpcore engine.

    uint32_t vers;         ///< QUIC version in use for this connection.
    uint32_t vers_initial; ///< QUIC version first negotiated.

    struct pn_hshk_space pn_init, pn_hshk;
    struct pn_data_space pn_data;

    int64_t next_sid_bidi; ///< Next unidir stream ID to use on q_rsv_stream().
    int64_t next_sid_uni;  ///< Next bidi stream ID to use on q_rsv_stream().

    int64_t cnt_bidi; ///< Number of unidir stream IDs in use.
    int64_t cnt_uni;  ///< Number of bidi stream IDs in use.

    struct transport_params tp_in;  ///< Transport parameters for RX.
    struct transport_params tp_out; ///< Transport parameters for TX.

    uint64_t in_data_str;  ///< Current inbound aggregate stream data.
    uint64_t out_data_str; ///< Current outbound aggregate stream data.

    uint64_t path_val_win; ///< Window for path validation.
    uint64_t in_data;      ///< Current inbound connection data.
    uint64_t out_data;     ///< Current outbound connection data.

    ev_timer idle_alarm;
    ev_timer closing_alarm;
    ev_timer key_flip_alarm;
    ev_timer ack_alarm;

    struct sockaddr_storage peer;      ///< Address of our peer.
    struct sockaddr_storage migr_peer; ///< Peer's desired migration address.
    char * peer_name;

    struct q_stream * cstreams[ep_data + 1]; ///< Crypto "streams".
    khash_t(streams_by_id) * streams_by_id;  ///< Regular streams.
    struct diet closed_streams;
    sl_head(, q_stream) need_ctrl;

    struct w_sock * sock;     ///< File descriptor (socket) for the connection.
    struct w_sockopt sockopt; ///< Socket options.

    epoch_t min_rx_epoch;

    ev_io rx_w;    ///< RX watcher.
    ev_async tx_w; ///< TX watcher.

    struct recovery rec; ///< Loss recovery state.
    struct tls tls;      ///< TLS state.

    uint64_t path_chlg_in;
    uint64_t path_resp_out;

    uint64_t path_chlg_out;
    uint64_t path_resp_in;

    uint64_t max_cid_seq_out;

    struct cid odcid; ///< Original destination CID of first Initial.

    struct w_iov_sq txq;

    uint16_t err_code;
    uint8_t err_frm;
    uint8_t err_reason_len;
    char err_reason[MAX_ERR_REASON_LEN];

    uint16_t tok_len;
    uint8_t tok[MAX_TOK_LEN + 2]; // some stacks send ungodly large tokens
                                  // XXX +2 for alignment
};


extern struct q_conn_sl c_ready;


#if !defined(NDEBUG) && !defined(FUZZING)
#define conn_to_state(c, s)                                                    \
    do {                                                                       \
        if ((c)->scid)                                                         \
            warn(DBG, "%s%s conn %s state %s -> " RED "%s" NRM,                \
                 (c)->state == (s) ? RED BLD "useless transition: " NRM : "",  \
                 conn_type(c), cid2str((c)->scid), conn_state_str[(c)->state], \
                 conn_state_str[(s)]);                                         \
        (c)->state = (s);                                                      \
    } while (0)
#else
#define conn_to_state(c, s) (c)->state = (s)
#endif

struct ev_loop;

extern bool __attribute__((const)) vers_supported(const uint32_t v);

extern void __attribute__((nonnull))
tx_w(struct ev_loop * const l, ev_async * const w, int e);

extern void __attribute__((nonnull))
tx(struct q_conn * const c, const uint32_t limit);

extern void __attribute__((nonnull)) err_close(struct q_conn * const c,
                                               const uint16_t code,
                                               const uint8_t frm,
                                               const char * const fmt,
                                               ...);

extern void __attribute__((nonnull)) enter_closing(struct q_conn * const c);

extern struct q_conn * new_conn(struct w_engine * const w,
                                const uint32_t vers,
                                const struct cid * const dcid,
                                const struct cid * const scid,
                                const struct sockaddr * const peer,
                                const char * const peer_name,
                                const uint16_t port,
                                const struct q_conn_conf * const cc);

extern void __attribute__((nonnull)) free_conn(struct q_conn * const c);

extern void __attribute__((nonnull))
add_scid(struct q_conn * const c, struct cid * const id);

extern void __attribute__((nonnull))
add_dcid(struct q_conn * const c, const struct cid * const id);

extern void __attribute__((nonnull))
do_conn_fc(struct q_conn * const c, const uint16_t len);

extern void __attribute__((nonnull))
free_scid(struct q_conn * const c, struct cid * const id);

extern void __attribute__((nonnull))
free_dcid(struct q_conn * const c, struct cid * const id);

extern void __attribute__((nonnull(1)))
update_conn_conf(struct q_conn * const c, const struct q_conn_conf * const cc);

extern struct q_conn * __attribute__((nonnull))
get_conn_by_srt(uint8_t * const srt);

extern void __attribute__((nonnull))
conns_by_srt_ins(struct q_conn * const c, uint8_t * const srt);

extern void __attribute__((nonnull))
rx(struct ev_loop * const l, ev_io * const rx_w, int _e);


#ifdef FUZZING
extern void __attribute__((nonnull)) rx_pkts(struct w_iov_sq * const x,
                                             struct q_conn_sl * const crx,
                                             const struct w_sock * const ws);
#endif

static inline struct pn_space * __attribute__((always_inline, nonnull))
pn_for_epoch(struct q_conn * const c, const epoch_t e)
{
    switch (e) {
    case ep_init:
        return &c->pn_init.pn;
    case ep_hshk:
        return &c->pn_hshk.pn;
    case ep_0rtt:
    case ep_data:
        return &c->pn_data.pn;
    }
    die("unhandled epoch %u", e);
}


SPLAY_PROTOTYPE(cids_by_seq, cid, node_seq, cids_by_seq_cmp)


struct ooo_0rtt {
    splay_entry(ooo_0rtt) node;
    struct cid cid;   ///< CID of 0-RTT pkt
    struct w_iov * v; ///< the buffer containing the 0-RTT pkt
    ev_tstamp t;      ///< Insertion time
};


extern splay_head(ooo_0rtt_by_cid, ooo_0rtt) ooo_0rtt_by_cid;


static inline int __attribute__((always_inline, nonnull))
ooo_0rtt_by_cid_cmp(const struct ooo_0rtt * const a,
                    const struct ooo_0rtt * const b)
{
    return cid_cmp(&a->cid, &b->cid);
}


SPLAY_PROTOTYPE(ooo_0rtt_by_cid, ooo_0rtt, node, ooo_0rtt_by_cid_cmp)


static inline __attribute__((always_inline, nonnull)) const char *
conn_type(const struct q_conn * const c)
{
    return c->is_clnt ? "clnt" : "serv";
}


static inline __attribute__((always_inline, const)) bool
is_force_vneg_vers(const uint32_t vers)
{
    return (vers & 0x0f0f0f0f) == 0x0a0a0a0a;
}


static inline __attribute__((always_inline, const)) bool
is_rsvd_vers(const uint32_t vers)
{
    return (vers & 0xffff0000) == 0x00000000;
}


static inline __attribute__((always_inline, const)) bool
is_zero(const ev_tstamp t)
{
    return fpclassify(t) == FP_ZERO;
}


static inline __attribute__((always_inline, const)) bool
is_inf(const ev_tstamp t)
{
    return fpclassify(t) == FP_INFINITE;
}


static inline bool __attribute__((nonnull, always_inline))
has_pval_wnd(const struct q_conn * const c, const uint16_t len)
{
    if (unlikely(c->out_data + len >= c->path_val_win)) {
        warn(DBG,
             "%s conn %s path val lim reached: %" PRIu64 " + %u >= %" PRIu64,
             conn_type(c), cid2str(c->scid), c->out_data, len, c->path_val_win);
        return false;
    }

    return true;
}


static inline bool __attribute__((nonnull, always_inline))
has_wnd(const struct q_conn * const c, const uint16_t len)
{
    if (unlikely(c->blocked)) {
        warn(DBG, "%s conn %s is blocked", conn_type(c), cid2str(c->scid));
        return false;
    }

    if (unlikely(c->rec.in_flight + len >= c->rec.cwnd)) {
        warn(DBG,
             "%s conn %s cwnd lim reached: in_flight %" PRIu64
             " + %u >= %" PRIu64,
             conn_type(c), cid2str(c->scid), c->rec.in_flight, len,
             c->rec.cwnd);
        return false;
    }

    return has_pval_wnd(c, len);
}


static inline uint16_t get_sport(const struct w_sock * const sock)
{
    return ((const struct sockaddr_in *)(const void *)w_get_addr(sock, true))
        ->sin_port;
}
