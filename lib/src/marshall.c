// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
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


#ifdef DEBUG_MARSHALL

#define trim_str(str)                                                          \
    __extension__({                                                            \
        while (*(str) == '&')                                                  \
            ++(str);                                                           \
        size_t len = strlen((str));                                            \
        while (len && *(str) == '(' && (str)[len - 1] == ')') {                \
            ++(str);                                                           \
            len -= 2;                                                          \
        }                                                                      \
        while (*(str) == '&') {                                                \
            ++(str);                                                           \
            --len;                                                             \
        }                                                                      \
        len;                                                                   \
    })


#define log_enc(type, fmt, enc_type)                                           \
    do {                                                                       \
        if (unlikely(DLEVEL >= DBG && util_dlevel >= DBG)) {                   \
            const size_t _src_len = trim_str(src_str);                         \
            const size_t _buf_len = trim_str(buf_str);                         \
            if (strcmp(enc_type, "buf") == 0)                                  \
                util_warn(DBG, false, func, file, line, (fmt), _src_len,       \
                          src_str, hex2str(src, enc_len), i - pos,             \
                          plural(i - pos), (enc_type), _buf_len, buf_str, pos, \
                          i - 1);                                              \
            else                                                               \
                util_warn(DBG, false, func, file, line, (fmt), _src_len,       \
                          src_str, *(const type *)src, i - pos,                \
                          plural(i - pos), (enc_type), _buf_len, buf_str, pos, \
                          i - 1);                                              \
        }                                                                      \
    } while (0)
#else
#define log_enc(type, fmt, enc_type)                                           \
    do {                                                                       \
    } while (0)
#endif


#define do_enc(var, len, type, fmt, enc_type)                                  \
    do {                                                                       \
        ensure(pos + (len) <= buf_len,                                         \
               "can't enc %zu byte%s at pos %u - buf len is %u",               \
               (size_t)(len), plural((len)), i, buf_len);                      \
        memcpy(&buf[i], &(var), (len));                                        \
        i += (len);                                                            \
        log_enc(type, (fmt), (enc_type));                                      \
    } while (0)


uint16_t marshall_enc(uint8_t * const buf,
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
                      const char * buf_str,
                      const char * src_str
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
        if (enc_len == 1 || (enc_len == 0 && src64 <= VARINT1_MAX)) {
            const uint8_t v = *(const uint8_t *)src;
            do_enc(v, sizeof(v), uint64_t, fmt, "var");

        } else if (enc_len == 2 || (enc_len == 0 && src64 <= VARINT2_MAX)) {
            const uint16_t v = htons((0x40 << 8) | *(const uint16_t *)src);
            do_enc(v, sizeof(v), uint64_t, fmt, "var");

        } else if (enc_len == 4 || (enc_len == 0 && src64 <= VARINT4_MAX)) {
            const uint32_t v = htonl((0x80UL << 24) | *(const uint32_t *)src);
            do_enc(v, sizeof(v), uint64_t, fmt, "var");

        } else {
            ensure(src64 <= VARINT8_MAX, "varint overflow");
            const uint64_t v = htonll((0xc0ULL << 56) | src64);
            do_enc(v, sizeof(v), uint64_t, fmt, "var");
        }
        break;
    }

    case 1: {
        // single byte to network byte order
        const uint8_t v = *(const uint8_t *)src;
        do_enc(v, sizeof(v), uint8_t, fmt, "fix");
        break;
    }

    case 2: {
        // uint16_t to network byte order
        const uint16_t v = htons(*(const uint16_t *)src);
        do_enc(v, sizeof(v), uint16_t, fmt, "fix");
        break;
    }

    case 3: {
        // 24 bits of a uint32_t to network byte order
        const uint32_t v = htonl(*(const uint32_t *)src << 8);
        do_enc(v, 3, uint32_t, fmt, "fix");
        break;
    }

    case 4: {
        // uint32_t to network byte order
        const uint32_t v = htonl(*(const uint32_t *)src);
        do_enc(v, sizeof(v), uint32_t, fmt, "fix");
        break;
    }

    case 8: {
        // uint64_t to network byte order
        const uint64_t v = htonll(*(const uint64_t *)src);
        do_enc(v, sizeof(v), uint64_t, fmt, "fix");
        break;
    }

    default:
        die("cannot encode length %u", src_len);
    }

    return i;
}


uint16_t marshall_enc_buf(uint8_t * const buf,
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
                          const char * buf_str,
                          const char * src_str
#endif
)
{
    ensure(pos + enc_len <= buf_len, "buf len %u exhausted", buf_len);
    ensure(src, "src is 0");
    memcpy(&buf[pos], src, enc_len);
#ifdef DEBUG_MARSHALL
    const uint16_t i = pos + enc_len;
    log_enc(uint8_t, fmt, "buf");
#endif
    return pos + enc_len;
}


#ifdef DEBUG_MARSHALL
#define log_dec(type, dec_type)                                                \
    do {                                                                       \
        if (unlikely(DLEVEL >= DBG && util_dlevel >= DBG)) {                   \
            const size_t _dst_len = trim_str(dst_str);                         \
            const size_t _buf_len = trim_str(buf_str);                         \
            if (strcmp(dec_type, "buf") == 0)                                  \
                util_warn(DBG, false, func, file, line, (fmt), i - pos,        \
                          plural(i - pos), (dec_type), _buf_len, buf_str, pos, \
                          i - 1, _dst_len, dst_str, hex2str(dst, dst_len));    \
            else                                                               \
                util_warn(DBG, false, func, file, line, (fmt), i - pos,        \
                          plural(i - pos), (dec_type), _buf_len, buf_str, pos, \
                          i - 1, _dst_len, dst_str, *(const type *)dst);       \
        }                                                                      \
    } while (0)
#else
#define log_dec(type, dec_type)                                                \
    do {                                                                       \
    } while (0)
#endif


#define warn_overrun                                                           \
    warn(WRN, "cannot decode from pos %u > buf len %u", pos + 1, buf_len)


#define do_dec(var, len)                                                       \
    do {                                                                       \
        if (unlikely(pos + (len) > buf_len)) {                                 \
            warn_overrun;                                                      \
            return UINT16_MAX;                                                 \
        }                                                                      \
        memcpy(&(var), &buf[i], (len));                                        \
        i += (len);                                                            \
    } while (0)


extern uint16_t marshall_dec(void * const dst,
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
                             const char * buf_str,
                             const char * dst_str
#endif
)
{
    uint16_t i = pos;

    switch (dst_len) {
    case 0:
        // varint decoding
        *(uint64_t *)dst = 0;
        if (buf[pos] <= VARINT1_MAX) {
            uint8_t v;
            do_dec(v, sizeof(v));
            *(uint8_t *)dst = v;

        } else if (buf[pos] < 0x80) {
            uint16_t v;
            do_dec(v, sizeof(v));
            *(uint16_t *)dst = ntohs(v) & VARINT2_MAX;

        } else if (buf[pos] < 0xc0) {
            uint32_t v;
            do_dec(v, sizeof(v));
            *(uint32_t *)dst = ntohl(v) & VARINT4_MAX;

        } else {
            uint64_t v;
            do_dec(v, sizeof(v));
            *(uint64_t *)dst = ntohll(v) & VARINT8_MAX;
        }
        log_dec(uint64_t, "var");
        break;

    case 1: {
        // single byte from network byte order
        uint8_t v;
        do_dec(v, sizeof(v));
        *(uint8_t *)dst = v;
        log_dec(uint8_t, "fix");
        break;
    }

    case 2: {
        // uint16_t from network byte order
        uint16_t v;
        do_dec(v, sizeof(v));
        *(uint16_t *)dst = ntohs(v);
        log_dec(uint16_t, "fix");
        break;
    }

    case 3: {
        // uint32_t from 24 bits in network byte order
        uint32_t v;
        do_dec(v, 3);
        *(uint32_t *)dst = ntohl(v << 8);
        log_dec(uint32_t, "fix");
        break;
    }

    case 4: {
        // uint32_t from network byte order
        uint32_t v;
        do_dec(v, sizeof(v));
        *(uint32_t *)dst = ntohl(v);
        log_dec(uint32_t, "fix");
        break;
    }

    case 8: {
        // uint64_t from network byte order
        uint64_t v;
        do_dec(v, sizeof(v));
        *(uint64_t *)dst = ntohll(v);
        log_dec(uint64_t, "fix");
        break;
    }

    default:
        die("cannot decode length %u", dst_len);
    }

    return i;
}


extern uint16_t marshall_dec_buf(void * const dst,
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
                                 const char * buf_str,
                                 const char * dst_str
#endif
)
{
    if (unlikely(pos + dst_len > buf_len)) {
        warn_overrun;
        return UINT16_MAX;
    }

    memcpy(dst, &buf[pos], dst_len);
#ifdef DEBUG_MARSHALL
    const uint16_t i = pos + dst_len;
    log_dec(uint8_t, "buf");
#endif
    return pos + dst_len;
}
