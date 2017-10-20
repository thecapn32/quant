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

#include <warpcore/warpcore.h>

struct q_conn;
struct stream;

struct q_stream {
    splay_entry(q_stream) node;
    struct q_conn * c;

    struct w_iov_sq out;  ///< Tail queue containing outbound data.
    uint64_t out_ack_cnt; ///< Number of unique ACKs received for pkts in o.
    uint64_t out_off;     ///< Current stream offset.

    struct w_iov_sq in; ///< tail queue containing inbound data
    uint64_t in_off;

    uint64_t max_stream_data;

    uint32_t id;
    uint8_t state;
    uint8_t fin_sent : 1;
    uint8_t : 7;
    uint8_t _unused[2];
};

#define STRM_STAT_IDLE 0
#define STRM_STAT_OPEN 1
#define STRM_STAT_HCRM 2 ///< half-closed remote
#define STRM_STAT_HCLO 3 ///< half-closed local
#define STRM_STAT_CLSD 4


extern int32_t __attribute__((nonnull))
stream_cmp(const struct q_stream * const a, const struct q_stream * const b);

SPLAY_PROTOTYPE(stream, q_stream, node, stream_cmp)


extern struct q_stream * __attribute__((nonnull))
get_stream(struct q_conn * const c, const uint32_t id);

extern struct q_stream * __attribute__((nonnull))
new_stream(struct q_conn * const c, const uint32_t id);

extern void __attribute__((nonnull)) free_stream(struct q_stream * const s);
