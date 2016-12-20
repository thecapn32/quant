// Copyright (c) 2016, NetApp, Inc.
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

#include <sys/queue.h>

#include "tommy.h"


struct q_stream {
    node stream_node;
    struct q_conn * c;

    uint32_t id;
    uint8_t state;
    uint8_t _unused[3];

    // uint8_t * out;
    // uint64_t out_len;
    struct w_iov_chain * ov; ///< w_chain containing outbound data.
    uint64_t out_off;

    uint8_t * in;
    uint64_t in_len;
    uint64_t in_off;
};

// SND_UNA


// #define STRM_IDLE 0
// #define STRM_RESV 1
// #define STRM_OPEN 2
// #define STRM_HFCL_REM 3
// #define STRM_HFCL_LOC 4
// #define STRM_CLSD 5


struct q_conn;

extern uint16_t __attribute__((nonnull))
enc_stream_frames(struct q_conn * const c,
                  uint8_t * const buf,
                  const uint16_t len);

extern struct q_stream * __attribute__((nonnull))
get_stream(struct q_conn * const c, const uint32_t id);

extern struct q_stream * __attribute__((nonnull))
new_stream(struct q_conn * const c, const uint32_t id);
