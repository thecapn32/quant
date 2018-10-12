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
#include <stdint.h>

#include <ev.h>
#include <warpcore/warpcore.h>


struct q_conn;
struct q_stream;
struct pn_space;


struct recovery {
    // LD state
    ev_timer ld_alarm;   // loss_detection_alarm
    uint16_t hshake_cnt; // handshake_count
    uint16_t tlp_cnt;    // tlp_count
    uint16_t rto_cnt;    // rto_count

    uint8_t _unused2[2];

    ev_tstamp last_sent_hshk_t;    // time_of_last_sent_handshake_packet
    ev_tstamp last_sent_rtxable_t; // time_of_last_sent_retransmittable_packet
    ev_tstamp min_rtt;             // min_rtt
    ev_tstamp latest_rtt;          // latest_rtt
    ev_tstamp srtt;                // smoothed_rtt
    ev_tstamp rttvar;              // rttvar
    uint64_t reorder_thresh;       // reordering_threshold
    ev_tstamp loss_t;              // loss_time

    // CC state
    uint64_t in_flight; // bytes_in_flight
    uint64_t cwnd;      // congestion_window
    uint64_t eor;       // end_of_recovery
    uint64_t ssthresh;

    uint64_t ect0_cnt;
    uint64_t ect1_cnt;
    uint64_t ce_cnt;
};


#define log_cc(c)                                                              \
    warn(DBG, "in_flight=%" PRIu64 ", cwnd=%" PRIu64 ", ssthresh=%" PRIu64,    \
         (c)->rec.in_flight, (c)->rec.cwnd, (c)->rec.ssthresh)


extern void __attribute__((nonnull)) init_rec(struct q_conn * const c);

extern void __attribute__((nonnull))
on_pkt_sent(struct q_stream * const s, struct w_iov * const v);

extern void __attribute__((nonnull))
on_ack_frame_start(struct q_conn * const c,
                   struct pn_space * const pn,
                   const uint64_t ack,
                   const uint64_t ack_del);

extern void __attribute__((nonnull))
on_ack_frame_end(struct q_conn * const c, struct pn_space * const pn);

extern void __attribute__((nonnull)) on_pkt_acked(struct q_conn * const c,
                                                  struct pn_space * const pn,
                                                  const uint64_t ack);

extern struct w_iov * __attribute__((nonnull))
find_sent_pkt(struct q_conn * const c,
              struct pn_space * const pn,
              const uint64_t nr);
