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
#include <stdint.h>

#include <ev.h>
#include <warpcore/warpcore.h>

#include "quic.h"

struct q_conn;
struct q_stream;
struct pn_space;


struct recovery {
    // LD state
    ev_timer ld_alarm;   // loss_detection_timer
    uint16_t crypto_cnt; // crypto_count
    uint16_t pto_cnt;    // pto_count

    uint8_t _unused2[4];

    ev_tstamp last_sent_ack_elicit_t; // time_of_last_sent_ack_eliciting_packet
    ev_tstamp last_sent_crypto_t;     // time_of_last_sent_crypto_packet

    // largest_sent_packet -> pn->lg_sent
    // largest_acked_packet -> pn->lg_acked

    ev_tstamp latest_rtt; // latest_rtt
    ev_tstamp srtt;       // smoothed_rtt
    ev_tstamp rttvar;     // rttvar
    ev_tstamp min_rtt;    // min_rtt

    // max_ack_delay -> c->tp_out.max_ack_del

    ev_tstamp loss_t; // loss_time

    uint64_t ack_eliciting_in_flight; // nr of ACK-eliciting pkts inflight

    // CC state
    uint64_t ce_cnt;       // ecn_ce_counter
    uint64_t in_flight;    // bytes_in_flight
    uint64_t cwnd;         // congestion_window
    ev_tstamp rec_start_t; // recovery_start_time
    uint64_t ssthresh;     // sshtresh
};


#ifndef NDEBUG
extern uint64_t prev_in_flight, prev_cwnd, prev_ssthresh;
extern ev_tstamp prev_srtt, prev_rttvar;

#define log_cc(c)                                                              \
    do {                                                                       \
        const uint64_t ssthresh =                                              \
            (c)->rec.ssthresh == UINT64_MAX ? 0 : (c)->rec.ssthresh;           \
        const int64_t delta_in_flight =                                        \
            (int64_t)(c)->rec.in_flight - (int64_t)prev_in_flight;             \
        const int64_t delta_cwnd =                                             \
            (int64_t)(c)->rec.cwnd - (int64_t)prev_cwnd;                       \
        const int64_t delta_ssthresh =                                         \
            (int64_t)ssthresh - (int64_t)prev_ssthresh;                        \
        const ev_tstamp delta_srtt = (c)->rec.srtt - prev_srtt;                \
        const ev_tstamp delta_rttvar = (c)->rec.rttvar - prev_rttvar;          \
        if (delta_in_flight || delta_cwnd || delta_ssthresh ||                 \
            !is_zero(delta_srtt) || !is_zero(delta_rttvar))                    \
            warn(DBG,                                                          \
                 "in_flight=%" PRIu64 " (%s%+" PRId64 NRM "), cwnd" NRM        \
                 "=%" PRIu64 " (%s%+" PRId64 NRM "), ssthresh=%" PRIu64        \
                 " (%s%+" PRId64 NRM "), srtt=%f (%s%+f" NRM                   \
                 "), rttvar=%f (%s%+f" NRM ")",                                \
                 (c)->rec.in_flight,                                           \
                 delta_in_flight > 0 ? GRN : delta_in_flight < 0 ? RED : "",   \
                 delta_in_flight, (c)->rec.cwnd,                               \
                 delta_cwnd > 0 ? GRN : delta_cwnd < 0 ? RED : "", delta_cwnd, \
                 ssthresh,                                                     \
                 delta_ssthresh > 0 ? GRN : delta_ssthresh < 0 ? RED : "",     \
                 delta_ssthresh, (c)->rec.srtt,                                \
                 delta_srtt > 0 ? GRN : delta_srtt < 0 ? RED : "", delta_srtt, \
                 (c)->rec.rttvar,                                              \
                 delta_rttvar > 0 ? GRN : delta_rttvar < 0 ? RED : "",         \
                 delta_rttvar);                                                \
        prev_in_flight = (c)->rec.in_flight;                                   \
        prev_cwnd = (c)->rec.cwnd;                                             \
        prev_ssthresh = ssthresh;                                              \
        prev_srtt = (c)->rec.srtt;                                             \
        prev_rttvar = (c)->rec.rttvar;                                         \
    } while (0)
#else
#define log_cc(c)
#endif


extern void __attribute__((nonnull)) init_rec(struct q_conn * const c);

extern void __attribute__((nonnull))
on_pkt_sent(struct q_stream * const s, struct w_iov * const v);

extern void __attribute__((nonnull))
on_ack_received_1(struct q_conn * const c,
                  struct pn_space * const pn,
                  struct w_iov * const lg_ack,
                  const uint64_t ack_del);

extern void __attribute__((nonnull))
on_ack_received_2(struct q_conn * const c, struct pn_space * const pn);

extern void __attribute__((nonnull))
on_pkt_acked(struct q_conn * const c,
             struct pn_space * const pn,
             struct w_iov * const acked_pkt);

extern struct w_iov * __attribute__((nonnull))
find_sent_pkt(struct q_conn * const c,
              struct pn_space * const pn,
              const uint64_t nr);

extern void __attribute__((nonnull))
congestion_event(struct q_conn * const c, const ev_tstamp lg_lost_tx_t);
