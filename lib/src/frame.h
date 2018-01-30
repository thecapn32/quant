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

#include <stdint.h>

struct q_conn;
struct q_stream;
struct w_iov;


#define FRAM_TYPE_PAD 0x00
#define FRAM_TYPE_RST_STRM 0x01
#define FRAM_TYPE_CONN_CLSE 0x02
#define FRAM_TYPE_APPL_CLSE 0x03
#define FRAM_TYPE_MAX_DATA 0x04
#define FRAM_TYPE_MAX_STRM_DATA 0x05
#define FRAM_TYPE_MAX_SID 0x06
#define FRAM_TYPE_PING 0x07
#define FRAM_TYPE_BLCK 0x08
#define FRAM_TYPE_STRM_BLCK 0x09
#define FRAM_TYPE_ID_BLCK 0x0a
#define FRAM_TYPE_NEW_CID 0x0b
#define FRAM_TYPE_STOP_SEND 0x0c
#define FRAM_TYPE_PONG 0x0d
#define FRAM_TYPE_ACK 0x0e
#define FRAM_TYPE_STRM 0x10
#define MAX_FRAM_TYPE FRAM_TYPE_STRM

#define F_STREAM_FIN 0x01
#define F_STREAM_LEN 0x02
#define F_STREAM_OFF 0x04

#ifndef NDEBUG
#define FRAM_IN BLD BLU
#define FRAM_OUT BLD GRN
#endif


extern uint64_t __attribute__((const))
shorten_ack_nr(const uint64_t ack, const uint64_t diff);

extern uint16_t __attribute__((nonnull))
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

extern uint16_t __attribute__((nonnull(1)))
enc_close_frame(struct w_iov * const v,
                const uint16_t pos,
                const uint8_t type,
                const uint16_t err_code,
                const char * const reas);

extern uint16_t __attribute__((nonnull(1, 2, 5))) dec_ack_frame(
    struct q_conn * const c,
    const struct w_iov * const v,
    const uint16_t pos,
    void (*before_ack)(struct q_conn * const, const uint64_t, const uint64_t),
    void (*on_each_ack)(struct q_conn * const, const uint64_t),
    void (*after_ack)(struct q_conn * const));

extern uint16_t __attribute__((nonnull))
enc_max_stream_data_frame(struct q_stream * const s,
                          struct w_iov * const v,
                          const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_max_data_frame(struct q_conn * const c,
                   struct w_iov * const v,
                   const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_max_stream_id_frame(struct q_conn * const c,
                        struct w_iov * const v,
                        const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_stream_blocked_frame(struct q_stream * const s,
                         const struct w_iov * const v,
                         const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_blocked_frame(struct q_conn * const c,
                  const struct w_iov * const v,
                  const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_stream_id_blocked_frame(struct q_conn * const c,
                            const struct w_iov * const v,
                            const uint16_t pos);
