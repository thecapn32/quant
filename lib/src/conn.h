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

#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include <ev.h>
#include <warpcore/warpcore.h>

#include "diet.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "tls.h"


extern splay_head(ipnp_splay, q_conn) conns_by_ipnp;
extern splay_head(cid_splay, q_cid_map) conns_by_cid;


struct transport_params {
    uint64_t max_strm_data_uni;
    uint64_t max_strm_data_bidi_local;
    uint64_t max_strm_data_bidi_remote;
    uint64_t max_data;
    int64_t max_strm_uni;
    int64_t max_strm_bidi;
    uint16_t max_pkt;
    uint16_t idle_to;
    uint8_t ack_del_exp;
    uint8_t _unused[3];
};


struct q_cid_map {
    splay_entry(q_cid_map) node;
    struct cid cid;    ///< Connection ID
    struct q_conn * c; ///< Connection
};

sl_head(q_conn_sl, q_conn);


#define CONN_STATE(k, v) k = v
#define CONN_STATES                                                            \
    CONN_STATE(conn_clsd, 0), CONN_STATE(conn_idle, 1),                        \
        CONN_STATE(conn_opng, 2), CONN_STATE(conn_estb, 3),                    \
        CONN_STATE(conn_clsg, 4), CONN_STATE(conn_drng, 51),                   \
        CONN_STATE(conn_tx_rtry, 203)

/// Define connection states.
/// \dotfile conn-states.dot "Connection state diagram."
typedef enum { CONN_STATES } conn_state_t;

extern const char * const conn_state_str[];


/// A QUIC connection.
struct q_conn {
    splay_entry(q_conn) node_ipnp;
    sl_entry(q_conn) next;

    sq_head(dcid_head, cid) dcid; ///< Destination connection IDs
    sq_head(scid_head, cid) scid; ///< Source connection IDs

    uint16_t holds_sock : 1; ///< Connection manages a warpcore socket.
    uint16_t is_clnt : 1;    ///< We are the client on this connection.
    uint16_t had_rx : 1;     ///< We had an RX event on this connection.
    uint16_t needs_tx : 1;   ///< We have a pending TX on this connection.
    uint16_t use_time_loss_det : 1; ///< UsingTimeLossDetection()
    uint16_t tx_max_data : 1;       ///< Sent a MAX_DATA frame.
    uint16_t blocked : 1;           ///< We are receive-window-blocked.
    uint16_t stream_id_blocked : 1; ///< We are out of stream IDs.
    uint16_t tx_max_stream_id : 1;  ///< Send MAX_STREAM_ID frame.
    uint16_t try_0rtt : 1;          ///< Try 0-RTT handshake.
    uint16_t did_0rtt : 1;          ///< 0-RTT handshake succeeded;
    uint16_t tx_path_resp : 1;      ///< Send PATH_RESPONSE.
    uint16_t tx_path_chlg : 1;      ///< Send PATH_CHALLENGE.
    uint16_t tx_ncid : 1;           ///< Send NEW_CONNECTION_ID.
    uint16_t tx_rtry : 1;           ///< We need to send a RETRY.
    uint16_t : 1;

    uint16_t sport; ///< Local port (in network byte-order).

    conn_state_t state; ///< State of the connection.

    struct w_engine * w; ///< Underlying warpcore engine.

    char * err_reason;
    uint16_t err_code;
    uint8_t err_frm;

    uint8_t _unused;

    uint32_t vers;         ///< QUIC version in use for this connection.
    uint32_t vers_initial; ///< QUIC version first negotiated.

    uint8_t _unused2[4];

    struct pn_hshk_space pn_init, pn_hshk;
    struct pn_data_space pn_data;

    int64_t next_sid; ///< Next stream ID to use on q_rsv_stream().

    struct transport_params tp_peer;
    struct transport_params tp_local;

    uint64_t in_data;
    uint64_t out_data;

    ev_timer idle_alarm;
    ev_timer closing_alarm;
    ev_timer ack_alarm;

    struct sockaddr_in peer; ///< Address of our peer.
    char * peer_name;

    splay_head(stream, q_stream) streams;
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

    uint64_t ncid_seq_out;
};


static inline __attribute__((always_inline, nonnull)) struct pn_space *
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


extern int __attribute__((nonnull))
ipnp_splay_cmp(const struct q_conn * const a, const struct q_conn * const b);

extern int __attribute__((nonnull))
cid_splay_cmp(const struct q_cid_map * const a,
              const struct q_cid_map * const b);

SPLAY_PROTOTYPE(ipnp_splay, q_conn, node_ipnp, ipnp_splay_cmp)
SPLAY_PROTOTYPE(cid_splay, q_cid_map, node, cid_splay_cmp)


struct zrtt_ooo {
    splay_entry(zrtt_ooo) node;
    struct cid cid;   ///< CID of 0-RTT pkt
    struct w_iov * v; ///< the buffer containing the 0-RTT pkt
    ev_tstamp t;      ///< Insertion time
};


extern splay_head(zrtt_ooo_splay, zrtt_ooo) zrtt_ooo_by_cid;

extern int __attribute__((nonnull))
zrtt_ooo_cmp(const struct zrtt_ooo * const a, const struct zrtt_ooo * const b);

SPLAY_PROTOTYPE(zrtt_ooo_splay, zrtt_ooo, node, zrtt_ooo_cmp)


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
is_zero(const ev_tstamp t)
{
    return fpclassify(t) == FP_ZERO;
}


static inline __attribute__((always_inline, const)) bool
is_inf(const ev_tstamp t)
{
    return fpclassify(t) == FP_INFINITE;
}


#define cid2str(i) hex2str((i)->id, (i)->len)


#define act_scid(c) sq_first(&(c)->scid)
#define act_dcid(c) sq_first(&(c)->dcid)


#define scid2str(c) act_scid(c) ? cid2str(act_scid(c)) : "0"
#define dcid2str(c) act_dcid(c) ? cid2str(act_dcid(c)) : "0"


#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

#define conn_to_state(c, s)                                                    \
    do {                                                                       \
        warn(DBG, "conn %s state %s -> " RED "%s" NRM, scid2str(c),            \
             conn_state_str[(c)->state], conn_state_str[(s)]);                 \
        if (likely((c)->state != (s))) {                                       \
            (c)->state = (s);                                                  \
            ensure(((c)->is_clnt && (c)->state < 200) ||                       \
                       (!(c)->is_clnt &&                                       \
                        ((c)->state < 100 || (c)->state >= 200)),              \
                   "%s and state is %s", conn_type(c),                         \
                   conn_state_str[(c)->state]);                                \
            if ((c)->state == conn_clsg)                                       \
                enter_closing(c);                                              \
        } else                                                                 \
            warn(ERR, "useless transition %u %u!", (c)->state, (s));           \
    } while (0)

#else

#define conn_to_state(c, s) (c)->state = (s)

#endif

struct ev_loop;

extern void __attribute__((nonnull))
tx_w(struct ev_loop * const l, ev_async * const w, int e);

extern void __attribute__((nonnull))
tx(struct q_conn * const c, const bool rtx, const uint32_t limit);

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

extern void __attribute__((nonnull))
ack_alarm(struct ev_loop * const l, ev_timer * const w, int e);

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
add_scid(struct q_conn * const c, const struct cid * const id);

extern void __attribute__((nonnull))
add_dcid(struct q_conn * const c, const struct cid * const id);


#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
extern void __attribute__((nonnull)) rx_pkts(struct w_iov_sq * const i,
                                             struct q_conn_sl * const crx,
                                             const struct w_sock * const ws);
#endif
