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
#include <stdint.h>
#include <warpcore/warpcore.h>

#include "quant/config.h"

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


/// C generic returning the type of the passed expression @p x. Only contains
/// entries for the types the marshalling functions support.
///
/// @param      x     An expression
///
/// @return     String containing the type of @p x.
///
// clang-format off
#define type_str(x)                                                            \
    _Generic((x),                                                              \
            uint8_t     : "uint8_t",                                           \
            uint16_t    : "uint16_t",                                          \
            uint32_t    : "uint32_t",                                          \
            uint64_t    : "uint64_t")
// clang-format on


#define dec(dst, buf, buf_len, pos, len, fmt)                                  \
    do {                                                                       \
        const size_t __len = len ? len : sizeof(dst);                          \
        ensure(pos + __len <= buf_len,                                         \
               "attempting to decode %zu byte%s starting at " #buf "["         \
               "%u], which is past " #buf_len " = %u",                         \
               __len, plural(__len), pos, buf_len - 1);                        \
        memcpy(&dst, &((const uint8_t *)buf)[pos], __len);                     \
        switch (__len) {                                                       \
        case 8: {                                                              \
            uint64_t * const __dst = (void * const) & dst;                     \
            *__dst = ntohll(*__dst);                                           \
            break;                                                             \
        }                                                                      \
        case 4: {                                                              \
            uint32_t * const __dst = (void * const) & dst;                     \
            *__dst = ntohl(*__dst);                                            \
            break;                                                             \
        }                                                                      \
        case 2: {                                                              \
            uint16_t * const __dst = (void * const) & dst;                     \
            *__dst = ntohs(*__dst);                                            \
            break;                                                             \
        }                                                                      \
        case 1:                                                                \
            break;                                                             \
        default:                                                               \
            die("cannot unmarshall field length %zu", __len);                  \
            break;                                                             \
        }                                                                      \
        warn(debug, "decoded %zu byte%s from " #buf "[%u..%zu] into %s " #dst  \
                    " = " fmt,                                                 \
             __len, plural(__len), pos, pos + __len - 1, type_str(dst), dst);  \
        pos += __len;                                                          \
    } while (0)


#define enc(buf, buf_len, pos, src, src_len, fmt)                              \
    do {                                                                       \
        const size_t __len = src_len ? src_len : sizeof(*src);                 \
        ensure(pos + __len <= buf_len,                                         \
               "attempting to encode %zu byte%s into " #buf                    \
               "[%u..%zu], which is past end of " #buf_len " = %u",            \
               __len, plural(__len), pos, pos + __len, buf_len - 1);           \
        memcpy(&((uint8_t * const) buf)[pos], src, __len);                     \
        switch (__len) {                                                       \
        case 8: {                                                              \
            uint64_t * const __dst =                                           \
                (void * const) & ((uint8_t * const) buf)[pos];                 \
            *__dst = htonll(*__dst);                                           \
            break;                                                             \
        }                                                                      \
        case 4: {                                                              \
            uint32_t * const __dst =                                           \
                (void * const) & ((uint8_t * const) buf)[pos];                 \
            *__dst = htonl(*__dst);                                            \
            break;                                                             \
        }                                                                      \
        case 2: {                                                              \
            uint16_t * const __dst =                                           \
                (void * const) & ((uint8_t * const) buf)[pos];                 \
            *__dst = htons(*__dst);                                            \
            break;                                                             \
        }                                                                      \
        case 1:                                                                \
            break;                                                             \
        default:                                                               \
            die("cannot marshall field length %zu", __len);                    \
            break;                                                             \
        }                                                                      \
        warn(debug, "encoded %s " #src " = " fmt " into %zu byte%s at " #buf   \
                    "[%u..%zu]",                                               \
             type_str(*src), *src, __len, plural(__len), pos,                  \
             pos + __len - 1);                                                 \
        pos += __len;                                                          \
    } while (0)
