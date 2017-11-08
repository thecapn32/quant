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

#include <stdint.h>

#include <ev.h>

#include "quic.h"

struct q_conn;
struct w_iov;


struct recovery {
    /// Sent-but-unACKed packets. The @p buf and @len fields of the w_iov
    /// structs are relative to any stream data.
    ///
    struct pm_nr_splay sent_pkts; // sent_packets

    // LD state
    ev_timer ld_alarm;   // loss_detection_alarm
    uint16_t hshake_cnt; // handshake_count
    uint16_t tlp_cnt;    // tlp_count
    uint16_t rto_cnt;    // rto_count

    uint8_t _unused2[2];

    uint64_t lg_sent_before_rto; // largest_sent_before_rto
    // ev_tstamp last_sent_t;       // time_of_last_sent_packet
    uint64_t lg_sent;        // largest_sent_packet
    uint64_t lg_acked;       // largest_acked_packet
    ev_tstamp latest_rtt;    // latest_rtt
    ev_tstamp srtt;          // smoothed_rtt
    ev_tstamp rttvar;        // rttvar
    uint64_t reorder_thresh; // reordering_threshold
    double reorder_fract;    // time_reordering_fraction
    ev_tstamp loss_t;        // loss_time

    // CC state
    uint64_t in_flight; // bytes_in_flight
    uint64_t cwnd;      // congestion_window
    uint64_t rec_end;
    uint64_t ssthresh;
};


extern void __attribute__((nonnull)) rec_init(struct q_conn * const c);

extern void __attribute__((nonnull))
on_pkt_sent(struct q_conn * const c, struct w_iov * const v);

extern void __attribute__((nonnull)) on_ack_rx_1(struct q_conn * const c,
                                                 const uint64_t ack,
                                                 const uint16_t ack_delay);

extern void __attribute__((nonnull)) on_ack_rx_2(struct q_conn * const c);

extern void __attribute__((nonnull))
on_pkt_acked(struct q_conn * const c, const uint64_t ack);

extern struct w_iov * __attribute__((nonnull))
find_sent_pkt(struct q_conn * const c, const uint64_t nr);

extern uint32_t __attribute__((nonnull))
rtxable_pkts_outstanding(struct q_conn * const c);
