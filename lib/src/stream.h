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

#include "conn.h" // IWYU pragma: keep
#include "quic.h"
#include "tls.h"


#define STRM_FL_INI_SRV 0x01
#define STRM_FL_DIR_UNI 0x02


#define STRM_STATE(k, v) k = v
#define STRM_STATES                                                            \
    STRM_STATE(strm_idle, 0), STRM_STATE(strm_open, 1),                        \
        STRM_STATE(strm_hcrm, 2), STRM_STATE(strm_hclo, 3),                    \
        STRM_STATE(strm_clsd, 4)

// Define stream states.
// \dotfile conn-states.dot "Connection state diagram."
typedef enum { STRM_STATES } strm_state_t;

extern const char * const strm_state_str[];


struct q_stream {
    splay_entry(q_stream) node;
    struct q_conn * c;

    struct w_iov_sq out;   ///< Tail queue containing outbound data.
    uint64_t out_ack_cnt;  ///< Number of unique ACKs received for pkts in o.
    uint64_t out_data;     ///< Current outbound stream offset (= data sent).
    uint64_t out_data_max; ///< Outbound max_stream_data.

    struct w_iov_sq in;         ///< Tail queue containing inbound data.
    struct pm_off_splay in_ooo; ///< Out-of-order inbound data.
    uint64_t in_data_max;       ///< Inbound max_stream_data.
    uint64_t in_data;           ///< In-order stream data received.

    int64_t id;
    strm_state_t state;
    uint8_t tx_max_stream_data : 1; ///< We need to open the receive window.
    uint8_t blocked : 1;            ///< We are receive-window-blocked.
    uint8_t : 6;
    uint8_t _unused[3];
};


#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define strm_to_state(strm, s)                                                 \
    do {                                                                       \
        if ((strm)->id >= 0) {                                                 \
            warn(DBG, "conn %s strm " FMT_SID " state %s -> " YEL "%s" NRM,    \
                 scid2str((strm)->c), (strm)->id,                              \
                 strm_state_str[(strm)->state], strm_state_str[(s)]);          \
        }                                                                      \
        (strm)->state = (s);                                                   \
    } while (0)
#else
#define strm_to_state(strm, s) (strm)->state = (s)
#endif


static inline __attribute__((always_inline, const)) bool
is_fully_acked(const struct q_stream * const s)
{
    return s->out_ack_cnt == sq_len(&s->out);
}


static inline __attribute__((always_inline, const)) int64_t
crpt_strm_id(const epoch_t epoch)
{
    return -((int64_t)epoch + 1);
}


static inline __attribute__((always_inline, const)) epoch_t
strm_epoch(const struct q_stream * const s)
{
    if (s->id < 0)
        return (epoch_t)(-s->id) - 1;
    if (s->c->state == conn_opng)
        return 1;
    return 3;
}


extern int __attribute__((nonnull))
stream_cmp(const struct q_stream * const a, const struct q_stream * const b);

extern struct q_stream * __attribute__((nonnull))
get_stream(struct q_conn * const c, const int64_t id);

extern struct q_stream *
new_stream(struct q_conn * const c, const int64_t id, const bool active);

extern void __attribute__((nonnull)) free_stream(struct q_stream * const s);

extern void __attribute__((nonnull))
track_bytes_in(struct q_stream * const s, const uint64_t n);

extern void __attribute__((nonnull))
track_bytes_out(struct q_stream * const s, const uint64_t n);

extern void __attribute__((nonnull)) reset_stream(struct q_stream * const s);

SPLAY_PROTOTYPE(stream, q_stream, node, stream_cmp)
