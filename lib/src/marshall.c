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

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include <quant/config.h> // IWYU pragma: keep
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

#ifdef DEBUG_MARSHALL
#include <stdbool.h>

#include "quic.h"
#endif


/// Computes number of bytes need to enccode @p v in QUIC varint encoding.
///
/// @param[in]  v     Value to check.
///
/// @return     Number of bytes needed in varint encoding (1, 2, 4 or 8).
///
uint16_t __attribute__((const)) varint_size_needed(const uint64_t v)
{
    if (v < 0x40)
        return 1;
    if (v < (0x40 << 8))
        return 2;
    if (v < (0x40 << 24))
        return 4;
    return 8;
}


#ifdef DEBUG_MARSHALL
#define log_enc(type, fmt, enc_type)                                           \
    if (unlikely(DLEVEL >= DBG && util_dlevel >= DBG))                         \
    util_warn(DBG, false, func, file, line, fmt,                               \
              (src_str[0] == '&' ? &src_str[1] : src_str), *(const type *)src, \
              i - pos, plural(i - pos), (enc_type), buf_str, pos, i - 1)
#else
#define log_enc(type, fmt, enc_type)                                           \
    do {                                                                       \
    } while (0)
#endif


#define do_enc(var, type, fmt, enc_type)                                       \
    do {                                                                       \
        ensure(pos + sizeof(var) <= buf_len,                                   \
               "can't enc %u byte%s at pos %u - buf len is %u", sizeof(var),   \
               plural(sizeof(var)), i, buf_len);                               \
        memcpy(&buf[i], &(var), sizeof(var));                                  \
        i += sizeof(var);                                                      \
        log_enc(type, fmt, enc_type);                                          \
    } while (0)


uint16_t __attribute__((nonnull)) marshall_enc(uint8_t * const buf,
                                               const uint16_t buf_len,
                                               const uint16_t pos,
                                               const void * const src,
                                               const uint8_t src_len,
                                               const uint8_t enc_len
#ifdef DEBUG_MARSHALL
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

    ensure(src_len == 0 || enc_len == 0,
           "cannot set enc_len %u w/fixed-len enc", enc_len);

    switch (src_len) {
    case 0: {
        // varint encoding
        const uint64_t src64 = *(const uint64_t *)src;
        if (enc_len == 1 || (enc_len == 0 && src64 < 0x40)) {
            const uint8_t v = *(const uint8_t *)src;
            do_enc(v, uint64_t, fmt, "var");

        } else if (enc_len == 2 || (enc_len == 0 && src64 < (0x40 << 8))) {
            const uint16_t v = htons((0x40 << 8) | *(const uint16_t *)src);
            do_enc(v, uint64_t, fmt, "var");

        } else if (enc_len == 4 || (enc_len == 0 && src64 < (0x40 << 24))) {
            const uint32_t v = htonl((0x80UL << 24) | *(const uint32_t *)src);
            do_enc(v, uint64_t, fmt, "var");

        } else {
            const uint64_t v = htonll((0xc0ULL << 56) | src64);
            do_enc(v, uint64_t, fmt, "var");
        }
        break;
    }

    case 1: {
        // single byte to network byte order
        const uint8_t v = *(const uint8_t *)src;
        do_enc(v, uint8_t, fmt, "fix");
        break;
    }

    case 2: {
        // uint16_t to network byte order
        const uint16_t v = htons(*(const uint16_t *)src);
        do_enc(v, uint16_t, fmt, "fix");
        break;
    }

    case 4: {
        // uint32_t to network byte order
        const uint32_t v = htonl(*(const uint32_t *)src);
        do_enc(v, uint32_t, fmt, "fix");
        break;
    }

    case 8: {
        // uint64_t to network byte order
        const uint64_t v = htonll(*(const uint64_t *)src);
        do_enc(v, uint64_t, fmt, "fix");
        break;
    }

    default:
        die("cannot encode length %u", src_len);
    }

    return i;
}


uint16_t __attribute__((nonnull)) marshall_enc_pnr(uint8_t * const buf,
                                                   const uint16_t buf_len,
                                                   const uint16_t pos,
                                                   const uint64_t * const src,
                                                   const uint8_t enc_len
#ifdef DEBUG_MARSHALL
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

    // varint pnr encoding
    switch (enc_len) {
    case 1: {
        const uint8_t v = *(const uint8_t *)src;
        do_enc(v, uint32_t, fmt, "pnr");
        break;
    }

    case 2: {
        const uint16_t v = htons((0x80 << 8) | *(const uint16_t *)src);
        do_enc(v, uint32_t, fmt, "pnr");
        break;
    }

    case 4: {
        const uint32_t v = htonl((0xc0UL << 24) | *(const uint32_t *)src);
        do_enc(v, uint32_t, fmt, "pnr");
        break;
    }

    default:
        die("cannot encode length %u", enc_len);
    }

    return i;
}


uint16_t __attribute__((nonnull)) marshall_enc_buf(uint8_t * const buf,
                                                   const uint16_t buf_len,
                                                   const uint16_t pos,
                                                   const void * const src,
                                                   const uint16_t enc_len
#ifdef DEBUG_MARSHALL
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
    ensure(pos + enc_len <= buf_len, "buf len %u exhausted", buf_len);
    memcpy(&buf[pos], src, enc_len);
#ifdef DEBUG_MARSHALL
    if (unlikely(DLEVEL >= DBG && util_dlevel >= DBG))
        util_warn(DBG, false, func, file, line, fmt,
                  (src_str[0] == '&' ? &src_str[1] : src_str),
                  hex2str(src, enc_len), enc_len, plural(enc_len), "fix",
                  buf_str, pos, pos + enc_len - 1);
#endif
    return pos + enc_len;
}


#ifdef DEBUG_MARSHALL
#define log_dec(type, dec_type)                                                \
    if (unlikely(DLEVEL >= DBG && util_dlevel >= DBG))                         \
    util_warn(DBG, false, func, file, line, fmt, i - pos, plural(i - pos),     \
              (dec_type), buf_str, pos, i - 1,                                 \
              (dst_str[0] == '&' ? &dst_str[1] : dst_str), *(const type *)dst)
#else
#define log_dec(type, dec_type)                                                \
    do {                                                                       \
    } while (0)
#endif


#ifdef DEBUG_MARSHALL
#define warn_overrun                                                           \
    warn(WRN, "cannot decode from pos %u > buf len %u", pos + 1, buf_len)
#else
#define warn_overrun                                                           \
    do {                                                                       \
    } while (0)
#endif

#define do_dec(var)                                                            \
    do {                                                                       \
        if (unlikely(pos + sizeof(var) > buf_len)) {                           \
            warn_overrun;                                                      \
            return UINT16_MAX;                                                 \
        }                                                                      \
        memcpy(&(var), &buf[i], sizeof(var));                                  \
        i += sizeof(var);                                                      \
    } while (0)


extern uint16_t __attribute__((nonnull))
marshall_dec(void * const dst,
             const uint8_t * const buf,
             const uint16_t buf_len,
             const uint16_t pos,
             const uint8_t dst_len
#ifdef DEBUG_MARSHALL
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
            uint8_t v;
            do_dec(v);
            *(uint8_t *)dst = v;

        } else if (buf[pos] < 0x80) {
            uint16_t v;
            do_dec(v);
            *(uint16_t *)dst = ntohs(v) & VARINT2_MAX;

        } else if (buf[pos] < 0xc0) {
            uint32_t v;
            do_dec(v);
            *(uint32_t *)dst = ntohl(v) & VARINT4_MAX;

        } else {
            uint64_t v;
            do_dec(v);
            *(uint64_t *)dst = ntohll(v) & VARINT8_MAX;
        }
        log_dec(uint64_t, "var");
        break;

    case 1: {
        // single byte from network byte order
        uint8_t v;
        do_dec(v);
        *(uint8_t *)dst = v;
        log_dec(uint8_t, "fix");
        break;
    }

    case 2: {
        // uint16_t from network byte order
        uint16_t v;
        do_dec(v);
        *(uint16_t *)dst = ntohs(v);
        log_dec(uint16_t, "fix");
        break;
    }

    case 4: {
        // uint32_t from network byte order
        uint32_t v;
        do_dec(v);
        *(uint32_t *)dst = ntohl(v);
        log_dec(uint32_t, "fix");
        break;
    }

    case 8: {
        // uint64_t from network byte order
        uint64_t v;
        do_dec(v);
        *(uint64_t *)dst = ntohll(v);
        log_dec(uint64_t, "fix");
        break;
    }

    default:
        die("cannot decode length %u", dst_len);
    }

    return i;
}


extern uint16_t __attribute__((nonnull))
marshall_dec_pnr(void * const dst,
                 const uint8_t * const buf,
                 const uint16_t buf_len,
                 const uint16_t pos
#ifdef DEBUG_MARSHALL
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

    // varint pnr decoding
    if (buf[pos] < 0x80) {
        uint8_t v;
        do_dec(v);
        *(uint8_t *)dst = v;

    } else if (buf[pos] < 0x40) {
        uint16_t v;
        do_dec(v);
        *(uint16_t *)dst = ntohs(v) & 0x3fff;

    } else {
        uint32_t v;
        do_dec(v);
        *(uint32_t *)dst = ntohl(v) & 0x3fffffffUL;
    }
    log_dec(uint32_t, "pnr");

    return i;
}


extern uint16_t __attribute__((nonnull))
marshall_dec_buf(void * const dst,
                 const uint8_t * const buf,
                 const uint16_t buf_len,
                 const uint16_t pos,
                 const uint16_t dst_len
#ifdef DEBUG_MARSHALL
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
    if (unlikely(pos + dst_len > buf_len)) {
#ifdef DEBUG_MARSHALL
        warn(WRN, "cannot decode from pos %u > buf len %u (called from %s:%u)",
             pos + 4, buf_len, file, line);
#endif
        return UINT16_MAX;
    }

    memcpy(dst, &buf[pos], dst_len);
#ifdef DEBUG_MARSHALL
    if (unlikely(DLEVEL >= DBG && util_dlevel >= DBG))
        util_warn(DBG, false, func, file, line, fmt, dst_len, plural(dst_len),
                  "fix", buf_str, pos, pos + dst_len - 1,
                  (dst_str[0] == '&' ? &dst_str[1] : dst_str),
                  hex2str(dst, dst_len));
#endif
    return pos + dst_len;
}
