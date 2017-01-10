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

#include "quic_internal.h"


#define MAX_PKT_LEN 1350
#define MAX_NONCE_LEN 32
#define HASH_LEN 12

/// A QUIC public header.
struct q_pub_hdr {
    uint8_t flags;
    uint8_t nonce_len;
    uint8_t nr_len;
    uint8_t _unused;
    q_tag vers;
    uint64_t cid;
    uint64_t nr;
    uint8_t nonce[32];
};


#define F_VERS 0x01
#define F_PUB_RST 0x02
#define F_NONCE 0x04
#define F_CID 0x08
#define F_MULTIPATH 0x40 // reserved
#define F_UNUSED 0x80    // reserved (must be 0)


#define decode(dst, buf, buf_len, pos, len, fmt)                               \
    do {                                                                       \
        const size_t __len = len ? len : sizeof(dst);                          \
        ensure(pos + __len <= buf_len,                                         \
               "attempting to decode %zu byte%s starting at " #buf "["         \
               "%d], which is past " #buf_len " = %d",                         \
               __len, plural(__len), pos, buf_len);                            \
        memcpy(&dst, &buf[pos], __len);                                        \
        warn(debug, "decoding %zu byte%s from pos %d into " #dst " = " fmt,    \
             __len, plural(__len), pos, dst);                                  \
        pos += __len;                                                          \
    } while (0)


#define encode(buf, buf_len, pos, src, src_len, fmt)                           \
    do {                                                                       \
        const size_t __len = src_len ? src_len : sizeof(*src);                 \
        ensure(pos + __len <= buf_len,                                         \
               "attempting to encode %zu byte%s starting at " #buf "["         \
               "%d], which is past " #buf_len " = %d",                         \
               __len, plural(__len), pos, buf_len);                            \
        memcpy(&buf[pos], src, __len);                                         \
        warn(debug, "encoding " #src " = " fmt " into %zu byte%s from pos %d", \
             *src, __len, plural(__len), pos);                                 \
        pos += __len;                                                          \
    } while (0)


extern uint16_t __attribute__((nonnull))
dec_pub_hdr(struct q_pub_hdr * const ph,
            const uint8_t * const buf,
            const uint16_t len,
            struct q_conn ** const c);

extern uint16_t __attribute__((nonnull))
enc_pkt(struct q_conn * const c, uint8_t * const buf, const uint16_t len);
