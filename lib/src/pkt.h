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

#define MAX_PKT_LEN 1350
#define MIN_IP4_INI_LEN 1252
#define MIN_IP6_INI_LEN 1232

#define F_LONG_HDR 0x80
#define F_LH_TYPE_VERS_NEG 0x01
#define F_SH_CID 0x40
#define F_SH_KEY_PHASE 0x20


#define pkt_flags(buf) (*(const uint8_t * const)(buf))

#define pkt_type(buf)                                                          \
    (pkt_flags(buf) & F_LONG_HDR ? pkt_flags(buf) & ~0x80                      \
                                 : pkt_flags(buf) & ~0xe0)


struct q_conn;
struct q_stream;
struct w_iov;

extern uint64_t __attribute__((nonnull))
pkt_cid(const uint8_t * const buf, const uint16_t len);

extern uint64_t __attribute__((nonnull))
pkt_nr(const uint8_t * const buf, const uint16_t len);

extern uint32_t __attribute__((nonnull))
pkt_vers(const uint8_t * const buf, const uint16_t len);

extern uint16_t __attribute__((nonnull))
pkt_hdr_len(const uint8_t * const buf, const uint16_t len);

extern uint16_t __attribute__((nonnull(1, 3)))
enc_pkt(struct q_conn * const c,
        struct q_stream * const s,
        struct w_iov * const v);
