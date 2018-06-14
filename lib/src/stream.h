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

#include <stdbool.h>
#include <stdint.h>

#include <warpcore/warpcore.h>

#include "conn.h"
#include "quic.h"

#define STRM_FL_INI_SRV 0x01
#define STRM_FL_DIR_UNI 0x02


struct q_stream {
    splay_entry(q_stream) node;
    struct q_conn * c;

    struct w_iov_sq out;   ///< Tail queue containing outbound data.
    uint64_t out_ack_cnt;  ///< Number of unique ACKs received for pkts in o.
    uint64_t out_off;      ///< Current outbound stream offset.
    uint64_t out_data_max; ///< Outbound max_stream_data.
    uint64_t out_data;     ///< Outbound data sent.

    struct w_iov_sq in;         ///< Tail queue containing inbound data.
    struct pm_off_splay in_ooo; ///< Out-of-order inbound data.
    uint64_t in_off;            ///< Current inbound in-order stream offset.
    uint64_t in_data_max;       ///< Inbound max_stream_data.
    uint64_t in_data;           ///< Inbound data received.

    uint64_t id;
    uint8_t state;
    uint8_t tx_max_stream_data : 1; ///< We need to open the receive window.
    uint8_t blocked : 1;            ///< We are receive-window-blocked.
    uint8_t : 6;
    uint8_t _unused[6];
};

#define STRM_STAT_IDLE 0
#define STRM_STAT_OPEN 1
#define STRM_STAT_HCRM 2 ///< half-closed remote
#define STRM_STAT_HCLO 3 ///< half-closed local
#define STRM_STAT_CLSD 4


#define strm_to_state(strm, s)                                                 \
    do {                                                                       \
        warn(DBG, "conn %s strm " FMT_SID " state %u -> %u",                   \
             scid2str((strm)->c), (strm)->id, (strm)->state, (s));             \
        (strm)->state = (s);                                                   \
    } while (0)

#define is_fully_acked(s) ((s)->out_ack_cnt == sq_len(&(s)->out))


extern int __attribute__((nonnull))
stream_cmp(const struct q_stream * const a, const struct q_stream * const b);

SPLAY_PROTOTYPE(stream, q_stream, node, stream_cmp)


extern struct q_stream * __attribute__((nonnull))
get_stream(struct q_conn * const c, const uint64_t id);

extern struct q_stream * __attribute__((nonnull))
new_stream(struct q_conn * const c, const uint64_t id, const bool active);

extern void __attribute__((nonnull)) free_stream(struct q_stream * const s);

extern void __attribute__((nonnull))
track_bytes_in(struct q_stream * const s, const uint64_t n);

extern void __attribute__((nonnull))
track_bytes_out(struct q_stream * const s, const uint64_t n);
