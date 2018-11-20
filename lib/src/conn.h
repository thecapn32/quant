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

#pragma once

#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include <ev.h>
#include <picotls.h>
#include <warpcore/warpcore.h>

#include "diet.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "tls.h"


extern splay_head(conns_by_ipnp, q_conn) conns_by_ipnp;
extern splay_head(conns_by_id, cid_map) conns_by_id;


struct transport_params {
    uint64_t max_strm_data_uni;
    uint64_t max_strm_data_bidi_local;
    uint64_t max_strm_data_bidi_remote;
    uint64_t max_data;
    uint64_t new_max_data;
    int64_t max_uni_streams; // this is count, not a max ID
    int64_t new_max_uni_streams;
    int64_t max_bidi_streams; // this is count, not a max ID
    int64_t new_max_bidi_streams;
    uint16_t max_pkt;
    uint16_t idle_to;
    uint8_t ack_del_exp;
    uint8_t max_ack_del;
    bool disable_migration;
    uint8_t _unused;
    struct cid orig_cid;
};


struct cid_map {
    splay_entry(cid_map) node;
    struct cid cid;    ///< Connection ID
    struct q_conn * c; ///< Connection
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
#define MAX_ERR_REASON_LEN 128 // keep < 256, since err_reason_len is uint8_t


splay_head(cids_by_seq, cid);
splay_head(cids_by_id, cid);


/// A QUIC connection.
struct q_conn {
    splay_entry(q_conn) node_ipnp;
    sl_entry(q_conn) node_rx_int; ///< For maintaining the internal RX queue.
    sl_entry(q_conn) node_rx_ext; ///< For maintaining the external RX queue.
    sl_entry(q_conn) node_aq;     ///< For maintaining the accept queue.

    struct cids_by_seq dcids_by_seq; ///< Destination CID hash by sequence.
    struct cids_by_seq scids_by_seq; ///< Source CID hash by sequence.
    struct cids_by_id scids_by_id;   ///< Source CID hash by ID.
    struct cid * dcid;               ///< Active destination CID.
    struct cid * scid;               ///< Active source CID.

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
    uint32_t tx_retire_cid : 1;    ///< Send RETIRE_CONNECTION_ID.
    uint32_t do_migration : 1;     ///< Perform a CID migration when possible.

#ifndef SPINBIT
    uint32_t : 12;
#else
    uint32_t next_spin : 1; ///< Spin value to set on next packet sent.
    uint32_t : 11;
#endif

    uint16_t sport; ///< Local port (in network byte-order).
    uint16_t tok_len;

    conn_state_t state; ///< State of the connection.

    uint16_t err_code;
    uint8_t err_frm;
    uint8_t err_reason_len;
    char err_reason[MAX_ERR_REASON_LEN];

    struct w_engine * w; ///< Underlying warpcore engine.

    uint32_t vers;         ///< QUIC version in use for this connection.
    uint32_t vers_initial; ///< QUIC version first negotiated.

    struct pn_hshk_space pn_init, pn_hshk;
    struct pn_data_space pn_data;

    int64_t next_sid_bidi; ///< Next unidir stream ID to use on q_rsv_stream().
    int64_t next_sid_uni;  ///< Next bidi stream ID to use on q_rsv_stream().

    int64_t lg_sid_bidi; ///< Largest unidir stream ID in use.
    int64_t lg_sid_uni;  ///< Largest bidi stream ID in use.

    struct transport_params tp_in;  ///< Transport parameters for RX.
    struct transport_params tp_out; ///< Transport parameters for TX.

    uint64_t in_data;
    uint64_t out_data;

    ev_timer idle_alarm;
    ev_timer closing_alarm;
    ev_timer migration_alarm;

    struct sockaddr_in peer; ///< Address of our peer.
    char * peer_name;

    // TODO we might want to maintain pointers to the crypto streams here
    splay_head(streams_by_id, q_stream) streams_by_id;
    struct diet closed_streams;

    struct w_sock * sock; ///< File descriptor (socket) for the connection.
    ev_io rx_w;           ///< RX watcher.
    ev_async tx_w;        ///< TX watcher.

    struct recovery rec; ///< Loss recovery state.
    struct tls tls;      ///< TLS state.

    uint64_t path_chlg_in;
    uint64_t path_resp_out;

    uint64_t path_chlg_out;
    uint64_t path_resp_in;

    uint64_t max_cid_seq_out;
    uint64_t max_cid_seq_in;

    struct cid odcid; ///< Original destination CID of first Initial.

    struct w_iov_sq txq;

    uint8_t tok[MAX_TOK_LEN]; // some stacks send ungodly large tokens
};


extern struct q_conn_sl c_ready;


#define cid2str(i)                                                             \
    __extension__({                                                            \
        static char _str[2 * (MAX_CID_LEN + sizeof((i)->seq)) + 1] = "0";      \
        if (i)                                                                 \
            snprintf(_str, sizeof(_str), "%" PRIu64 ":%s", (i)->seq,           \
                     hex2str((i)->id, (i)->len));                              \
        (i) ? _str : "?";                                                      \
    })


#if !defined(NDEBUG) && !defined(FUZZING)
#define conn_to_state(c, s)                                                    \
    do {                                                                       \
        warn(DBG, "conn %s state %s -> " RED "%s" NRM, cid2str((c)->scid),     \
             conn_state_str[(c)->state], conn_state_str[(s)]);                 \
        if (likely((c)->state != (s)))                                         \
            (c)->state = (s);                                                  \
        else                                                                   \
            warn(ERR, "useless transition %u %u!", (c)->state, (s));           \
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

extern void __attribute__((nonnull))
tx_ack(struct q_conn * const c, const epoch_t e);

extern void __attribute__((nonnull))
rx(struct ev_loop * const l, ev_io * const rx_w, int e);

extern void * __attribute__((nonnull)) loop_run(void * const arg);

extern void __attribute__((nonnull))
loop_update(struct ev_loop * const l, ev_async * const w, int e);

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
                                const struct sockaddr_in * const peer,
                                const char * const peer_name,
                                const uint16_t port,
                                const uint64_t idle_to);

extern void __attribute__((nonnull)) free_conn(struct q_conn * const c);

extern void __attribute__((nonnull))
update_act_scid(struct q_conn * const c, const struct cid * const id);

extern void __attribute__((nonnull))
add_scid(struct q_conn * const c, const struct cid * const id);

extern void __attribute__((nonnull))
add_dcid(struct q_conn * const c, const struct cid * const id);

extern void __attribute__((nonnull)) do_conn_fc(struct q_conn * const c);

extern void __attribute__((nonnull))
free_scid(struct q_conn * const c, struct cid * const id);

extern void __attribute__((nonnull))
free_dcid(struct q_conn * const c, struct cid * const id);

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
    case ep_0rtt:
        return &c->pn_data.pn;
    case ep_hshk:
        return &c->pn_hshk.pn;
    case ep_data:
        return &c->pn_data.pn;
    }
}


static inline epoch_t __attribute__((always_inline, nonnull))
epoch_in(const struct q_conn * const c)
{
    const size_t epoch = ptls_get_read_epoch(c->tls.t);
    switch (epoch) {
    case 0:
        return ep_init;
    case 1:
        return ep_0rtt;
    case 2:
        return ep_hshk;
    case 3:
        return ep_data;
    default:
        die("unhandled epoch %u", epoch);
    }
}


static inline bool __attribute__((nonnull, always_inline))
has_wnd(const struct q_conn * const c)
{
    return !c->blocked && (c->rec.in_flight + w_mtu(c->w) < c->rec.cwnd);
}


static inline bool __attribute__((nonnull, always_inline))
conn_needs_ctrl(const struct q_conn * const c)
{
    return epoch_in(c) == ep_data &&
           (c->tx_max_data || c->tx_max_sid_bidi || c->tx_path_resp ||
            c->tx_path_chlg || c->tx_ncid || c->tx_retire_cid || c->blocked);
}


static inline int __attribute__((always_inline, nonnull))
cid_cmp(const struct cid * const a, const struct cid * const b)
{
    const int r =
        memcmp(&a->len, &b->len, MIN(a->len, b->len) + sizeof(a->len));
    // warn(ERR, "%d = cmp %s len %u and %s len %u", r, cid2str(a), a->len,
    //      cid2str(b), b->len);
    ensure(a->len && b->len, "len 0");
    // compare len and id
    return r;
}


static inline int __attribute__((always_inline, nonnull))
conns_by_id_cmp(const struct cid_map * const a, const struct cid_map * const b)
{
    return cid_cmp(&a->cid, &b->cid);
}


extern int __attribute__((nonnull))
conns_by_ipnp_cmp(const struct q_conn * const a, const struct q_conn * const b);


SPLAY_PROTOTYPE(conns_by_ipnp, q_conn, node_ipnp, conns_by_ipnp_cmp)
SPLAY_PROTOTYPE(conns_by_id, cid_map, node, conns_by_id_cmp)
SPLAY_PROTOTYPE(cids_by_seq, cid, node_seq, cids_by_seq_cmp)
SPLAY_PROTOTYPE(cids_by_id, cid, node_id, cid_cmp)


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
is_force_neg_vers(const uint32_t vers)
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
