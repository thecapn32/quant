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

#define F_STREAM 0x80
#define F_STREAM_FIN 0x40
#define F_STREAM_DATA_LEN 0x20

#define F_ACK 0x40
#define F_ACK_N 0x20
#define F_ACK_UNUSED 0x10

#define T_PADDING 0x00
#define T_RST_STREAM 0x01
#define T_CONNECTION_CLOSE 0x02
#define T_GOAWAY 0x03
#define T_WINDOW_UPDATE 0x04
#define T_BLOCKED 0x05
#define T_PING 0x07

#define QUIC_INTERNAL_ERROR 1
#define QUIC_INVALID_VERSION 20

/// Define an IEEE-754 16-bt floating type (backed by gcc/clang F16C)
// typedef __fp16 float16_t;


struct q_conn;
struct q_stream;

extern uint16_t __attribute__((nonnull))
dec_frames(struct q_conn * const c,
           const uint8_t * const buf,
           const uint16_t len);

extern uint16_t __attribute__((nonnull))
enc_stream_frame(struct q_stream * const s,
                 uint8_t * const buf,
                 const uint16_t pos,
                 const uint16_t len,
                 const uint16_t max_len);

extern uint16_t __attribute__((nonnull))
enc_padding_frame(uint8_t * const buf, const uint16_t len);

extern uint16_t __attribute__((nonnull))
enc_conn_close_frame(uint8_t * const buf, const uint16_t len);

extern uint16_t __attribute__((nonnull))
enc_ack_frame(uint8_t * const buf, const uint16_t len);
