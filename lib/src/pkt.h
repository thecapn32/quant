// SPDX-License-Identifier: BSD-2-Clause
//
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

#include <stdbool.h>
#include <stdint.h>

#include "quic.h"

#define MAX_PKT_LEN 1252
#define MIN_INI_LEN 1200

#define F_LONG_HDR 0x80

#define F_LH_VNEG 0x7F
#define F_LH_INIT 0x7E
#define F_LH_RTRY 0x7D
#define F_LH_HSHK 0x7C
#define F_LH_0RTT 0x7B

#define F_SH_OMIT_CID 0x40
#define F_SH_KPH 0x20
#define F_SH_1OCT 0x1F
#define F_SH_2OCT 0x1E
#define F_SH_4OCT 0x1D

#define CONN_CLSE_ERR_NO_ERROR 0x0
// #define CONN_CLSE_ERR_INTERNAL_ERROR 0x1
// #define CONN_CLSE_ERR_FLOW_CONTROL_ERROR 0x3
// #define CONN_CLSE_ERR_STREAM_ID_ERROR 0x4
// #define CONN_CLSE_ERR_STREAM_STATE_ERROR 0x5
// #define CONN_CLSE_ERR_FINAL_OFFSET_ERROR 0x6
// #define CONN_CLSE_ERR_FRAME_FORMAT_ERROR 0x7
// #define CONN_CLSE_ERR_TRANSPORT_PARAMETER_ERROR 0x8
// #define CONN_CLSE_ERR_VERSION_NEGOTIATION_ERROR 0x9
// #define CONN_CLSE_ERR_PROTOCOL_VIOLATION 0xA
// #define CONN_CLSE_ERR_FRAME_ERROR 0x1XX


#define pkt_flags(buf) (*(const uint8_t * const)(buf))

#define pkt_type(flags) (flags & (is_set(F_LONG_HDR, flags) ? ~0x80 : ~0xe0))

struct q_conn;
struct q_stream;
struct w_iov;
struct w_iov_sq;

extern uint64_t __attribute__((nonnull))
pkt_cid(const uint8_t * const buf, const uint16_t len);

extern uint64_t __attribute__((nonnull))
pkt_nr(const uint8_t * const buf, const uint16_t len, struct q_conn * const c);

extern uint32_t __attribute__((nonnull))
pkt_vers(const uint8_t * const buf, const uint16_t len);

extern uint16_t __attribute__((nonnull))
pkt_hdr_len(const uint8_t * const buf, const uint16_t len);

extern bool __attribute__((nonnull)) enc_pkt(struct q_stream * const s,
                                             const bool rtx,
                                             struct w_iov * const v,
                                             struct w_iov_sq * const q);

#ifndef NDEBUG
extern void __attribute__((nonnull))
log_pkt(const char * const dir, const struct w_iov * const v);
#else
#define log_pkt(...)                                                           \
    do {                                                                       \
    } while (0)
#endif
