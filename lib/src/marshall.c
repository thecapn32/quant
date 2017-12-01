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

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <quant/quant.h> // IWYU pragma: keep
#include <warpcore/warpcore.h>

#if defined(HAVE_ENDIAN_H)
// e.g., Linux
#include <endian.h>
#define ntohll be64toh
#define htonll htobe64
#elif defined(HAVE_SYS_ENDIAN_H)
// e.g., FreeBSD
#include <sys/endian.h>
#define ntohll be64toh
#define htonll htobe64
#endif

#include "marshall.h"


/// Computes number of bytes need to enccode @p v in QUIC varint encoding.
///
/// @param[in]  v     Value to check.
///
/// @return     Number of bytes needed in varint encoding (1, 2, 4 or 8).
///
uint16_t __attribute__((const)) varint_sizeof(const uint64_t v)
{
    if (v < 0x40)
        return 1;
    if (v < (0x40 << 8))
        return 2;
    if (v < (0x40 << 24))
        return 4;
    return 8;
}


#ifndef NDEBUG
#define log_enc(type, fmt)                                                     \
    if (unlikely(DLEVEL >= DBG && util_dlevel >= DBG))                         \
    util_warn(DBG, false, func, file, line, fmt,                               \
              (src_str[0] == '&' ? &src_str[1] : src_str), *(const type *)src, \
              i - pos, plural(i - pos), (src_len ? "fix" : "var"), buf_str,    \
              pos, i - 1)
#else
#define log_enc(type, fmt)                                                     \
    do {                                                                       \
    } while (0)
#endif


uint16_t __attribute__((nonnull)) marshall_enc(uint8_t * const buf,
                                               const uint16_t buf_len,
                                               const uint16_t pos,
                                               const void * const src,
                                               const uint16_t src_len
#ifndef NDEBUG
                                               ,
                                               const char * const fmt,
                                               const char * const func,
                                               const char * const file,
                                               const unsigned line,
                                               const char * const buf_str,
                                               const char * const src_str
#endif
)
{
    uint16_t i = pos;

    switch (src_len) {
    case 0:
        // varint encoding
        if (*(const uint64_t *)src < 0x40) {
            ensure(pos + 1 <= buf_len, "buf len %u insufficient", buf_len);
            buf[i++] = *(const uint8_t *)src;
            log_enc(uint64_t, fmt);

        } else if (*(const uint64_t *)src < (0x40 << 8)) {
            ensure(pos + 2 <= buf_len, "buf len %u insufficient", buf_len);
            buf[i++] = 0x40 | *(const uint16_t *)src >> 8;
            buf[i++] = *(const uint16_t *)src & 0xff;
            log_enc(uint64_t, fmt);

        } else if (*(const uint64_t *)src < (0x40 << 24)) {
            ensure(pos + 4 <= buf_len, "buf len %u insufficient", buf_len);
            const uint32_t v = htonl((0x80UL << 24) | *(const uint32_t *)src);
            memcpy(&buf[i], &v, 4);
            i += 4;
            log_enc(uint64_t, fmt);

        } else {
            ensure(pos + 8 <= buf_len, "buf len %u insufficient", buf_len);
            const uint64_t v = htonll((0xc0ULL << 56) | *(const uint64_t *)src);
            memcpy(&buf[i], &v, 8);
            i += 8;
            log_enc(uint64_t, fmt);
        }
        break;

    case 1:
        // single byte to network byte order
        ensure(pos + 1 <= buf_len, "buf len %u insufficient", buf_len);
        buf[i++] = *(const uint8_t *)src;
        log_enc(uint8_t, fmt);
        break;

    case 2:
        // uint16_t to network byte order
        ensure(pos + 2 <= buf_len, "buf len %u insufficient", buf_len);
        *(uint16_t *)(void *)&buf[i] = htons(*(const uint16_t *)src);
        i += 2;
        log_enc(uint16_t, fmt);
        break;

    case 4:
        // uint32_t to network byte order
        ensure(pos + 4 <= buf_len, "buf len %u insufficient", buf_len);
        *(uint32_t *)(void *)&buf[i] = htonl(*(const uint32_t *)src);
        i += 4;
        log_enc(uint32_t, fmt);
        break;

    case 8:
        // uint64_t to network byte order
        ensure(pos + 8 <= buf_len, "buf len %u insufficient", buf_len);
        *(uint64_t *)(void *)&buf[i] = htonll(*(const uint64_t *)src);
        i += 8;
        log_enc(uint64_t, fmt);
        break;

    default:
        die("cannot encode length %u", src_len);
    }

    return i;
}


#ifndef NDEBUG
#define log_dec(type)                                                          \
    if (unlikely(DLEVEL >= DBG && util_dlevel >= DBG))                         \
    util_warn(DBG, false, func, file, line, fmt, i - pos, plural(i - pos),     \
              (dst_len ? "fix" : "var"), buf_str, pos, i - 1, dst_str,         \
              *(const type *)dst)
#else
#define log_dec(type)                                                          \
    do {                                                                       \
    } while (0)
#endif


extern uint16_t __attribute__((nonnull))
marshall_dec(void * const dst,
             const uint8_t * const buf,
             const uint16_t buf_len,
             const uint16_t pos,
             const uint16_t dst_len
#ifndef NDEBUG
             ,
             const char * const fmt,
             const char * const func,
             const char * const file,
             const unsigned line,
             const char * const buf_str,
             const char * const dst_str
#endif
)
{
    uint16_t i = pos;

    switch (dst_len) {
    case 0:
        // varint decoding
        *(uint64_t *)dst = 0;
        if (buf[pos] < 0x40) {
            ensure(pos + 1 <= buf_len, "decoding from pos %u > buf len %u",
                   pos + 1, buf_len);
            *(uint8_t *)dst = buf[i++];
            log_dec(uint64_t);

        } else if (buf[pos] < 0x80) {
            ensure(pos + 2 <= buf_len, "decoding from pos %u > buf len %u",
                   pos + 2, buf_len);
            *(uint16_t *)dst = (uint16_t)((buf[i++] & 0x3f) << 8);
            *(uint16_t *)dst |= buf[i++];
            log_dec(uint64_t);

        } else if (buf[pos] < 0xc0) {
            ensure(pos + 4 <= buf_len, "decoding from pos %u > buf len %u",
                   pos + 4, buf_len);
            *(uint32_t *)dst =
                ntohl(*(const uint32_t *)(const void *)&buf[pos]) &
                0x3fffffffUL;
            i += 4;
            log_dec(uint64_t);

        } else {
            ensure(pos + 8 <= buf_len, "decoding from pos %u > buf len %u",
                   pos + 8, buf_len);
            *(uint64_t *)dst =
                ntohll(*(const uint64_t *)(const void *)&buf[pos]) &
                0x3fffffffffffffffULL;
            i += 8;
            log_dec(uint64_t);
        }
        break;

    case 1:
        // single byte from network byte order
        ensure(pos + 1 <= buf_len, "decoding from pos %u > buf len %u", pos + 1,
               buf_len);
        *(uint8_t *)dst = buf[i++];
        log_dec(uint8_t);
        break;

    case 2:
        // uint16_t from network byte order
        ensure(pos + 2 <= buf_len, "decoding from pos %u > buf len %u", pos + 2,
               buf_len);
        *(uint16_t *)dst = ntohs(*(const uint16_t *)(const void *)&buf[pos]);
        i += 2;
        log_dec(uint16_t);
        break;

    case 4:
        // uint32_t from network byte order
        ensure(pos + 4 <= buf_len, "decoding from pos %u > buf len %u", pos + 4,
               buf_len);
        *(uint32_t *)dst = ntohl(*(const uint32_t *)(const void *)&buf[pos]);
        i += 4;
        log_dec(uint32_t);
        break;

    case 8:
        // uint64_t from network byte order
        ensure(pos + 8 <= buf_len, "decoding from pos %u > buf len %u", pos + 8,
               buf_len);
        *(uint64_t *)dst = ntohll(*(const uint64_t *)(const void *)&buf[pos]);
        i += 8;
        log_dec(uint64_t);
        break;

    default:
        die("cannot decode length %u", dst_len);
    }

    return i;
}
