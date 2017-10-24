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

struct q_conn;
struct q_stream;
struct w_iov;

extern void __attribute__((nonnull))
dec_frames(struct q_conn * const c, struct w_iov * v);

extern uint16_t __attribute__((nonnull))
enc_padding_frame(struct w_iov * const v,
                  const uint16_t pos,
                  const uint16_t len);

extern uint16_t __attribute__((nonnull)) enc_ack_frame(struct q_conn * const c,
                                                       struct w_iov * const v,
                                                       const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_stream_frame(struct q_stream * const s, struct w_iov * const v);

extern uint16_t __attribute__((nonnull))
enc_conn_close_frame(struct w_iov * const v,
                     const uint16_t pos,
                     const uint32_t err_code,
                     const char * const reas,
                     const uint16_t reas_len);
