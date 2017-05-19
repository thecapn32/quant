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

#pragma once

#include <ev.h>
#include <stdint.h>
#include <sys/socket.h>

#include <warpcore/warpcore.h>

#include "tommy.h"


// All open QUIC connections.
extern hash q_conns;


/// A QUIC connection.
struct q_conn {
    node conn_node;

    uint64_t id; ///< Connection ID

    uint32_t vers; ///< QUIC version in use for this connection.
    uint32_t next_sid;
    uint8_t flags;
    uint8_t state; ///< State of the connection.

    uint8_t _unused[2];
    socklen_t peer_len;   ///< Length of @p peer.
    struct sockaddr peer; ///< Address of our peer.
    hash streams;
    struct w_sock * sock; ///< File descriptor (socket) for the connection.
    ev_io rx_w;           ///< RX watcher.

    uint64_t lg_recv;       ///< Largest packet number received
    uint64_t lg_recv_acked; ///< Largest packet which we ACKed

    // LD state
    ev_timer ld_alarm; ///< Loss detection alarm.
    uint8_t handshake_cnt;
    uint8_t tlp_cnt;
    uint8_t rto_cnt;
    uint8_t _unused2[5];
    double reorder_fract;
    uint64_t lg_sent_before_rto;
    ev_tstamp srtt;
    ev_tstamp rttvar;
    uint64_t reorder_thresh;
    ev_tstamp loss_t;
    struct w_iov_stailq sent_pkts;
    uint64_t lg_sent;  ///< Largest packet number sent
    uint64_t lg_acked; ///< Largest packet number for which an ACK was received
    ev_tstamp latest_rtt;

    // CC state
    uint64_t cwnd;
    uint64_t in_flight;
    uint64_t rec_end;
    uint64_t ssthresh;
    ev_tstamp last_sent_t;
};

#define CONN_CLSD 0
#define CONN_VERS_SENT 1
#define CONN_VERS_RECV 2
#define CONN_ESTB 3
#define CONN_FINW 99 // TODO: renumber

#define CONN_FLAG_CLNT 0x01


struct q_stream;
struct ev_loop;

extern struct q_conn * get_conn(const uint64_t id);

extern ev_tstamp __attribute__((nonnull))
time_to_send(const struct q_conn * const c, const uint16_t len);

extern void __attribute__((nonnull)) detect_lost_pkts(struct q_conn * const c);

extern struct q_conn * __attribute__((nonnull))
new_conn(const uint64_t id,
         const struct sockaddr * const peer,
         const socklen_t peer_len);

extern void __attribute__((nonnull))
tx(struct w_sock * const ws, struct q_conn * const c, struct q_stream * s);

extern void __attribute__((nonnull))
rx(struct ev_loop * const l, ev_io * const rx_w, int e);

extern void __attribute__((nonnull)) set_ld_alarm(struct q_conn * const c);
