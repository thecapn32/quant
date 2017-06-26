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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#include <ev.h>
#pragma clang diagnostic pop

#include <picotls.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>

#include <warpcore/warpcore.h>


// All open QUIC connections.
extern SPLAY_HEAD(conn, q_conn) q_conns;
extern pthread_mutex_t q_conns_lock;


/// A QUIC connection.
struct q_conn {
    SPLAY_ENTRY(q_conn) next;

    uint64_t id; ///< Connection ID

    uint32_t vers; ///< QUIC version in use for this connection.
    uint32_t next_sid;
    uint8_t flags;
    uint8_t state; ///< State of the connection.

    uint8_t _unused[2];
    socklen_t peer_len;   ///< Length of @p peer.
    struct sockaddr peer; ///< Address of our peer.
    SPLAY_HEAD(stream, q_stream) streams;
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

    // TLS state
    ptls_t * tls;

    // lock and condition variables
    pthread_mutex_t lock;
    pthread_cond_t write_cv;
    pthread_cond_t accept_cv;
    pthread_cond_t connect_cv;
    pthread_cond_t read_cv;
};


extern int64_t __attribute__((nonnull))
conn_cmp(const struct q_conn * const a, const struct q_conn * const b);

SPLAY_PROTOTYPE(conn, q_conn, next, conn_cmp)


#define CONN_CLSD 0
#define CONN_VERS_SENT 1
#define CONN_VERS_RECV 2
#define CONN_ESTB 3
#define CONN_FINW 99 // TODO: renumber

#define CONN_FLAG_CLNT 0x01
#define CONN_FLAG_SERV 0x02
#define CONN_FLAG_TLS_DONE 0x04


struct ev_loop;

extern void __attribute__((nonnull)) detect_lost_pkts(struct q_conn * const c);

extern struct q_conn * new_conn(const uint8_t type);

extern void __attribute__((nonnull))
init_conn(struct q_conn * const c,
          const uint64_t id,
          const struct sockaddr * const peer,
          const socklen_t peer_len);

extern void __attribute__((nonnull))
tx(struct w_sock * const ws, struct q_conn * const c);

extern void __attribute__((nonnull))
rx(struct ev_loop * const l, ev_io * const rx_w, int e);

extern void __attribute__((nonnull)) set_ld_alarm(struct q_conn * const c);
