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

#include <stdint.h>


extern uint8_t __attribute__((const)) varint_size_needed(const uint64_t v);

#ifndef NDEBUG
// #define DEBUG_MARSHALL
#endif


#define VARINT1_MAX 0x3fU
#define VARINT2_MAX 0x3FFFU
#define VARINT4_MAX 0x3fffffffUL
#define VARINT8_MAX 0x3fffffffffffffffULL
#define VARINT_MAX VARINT8_MAX

#ifdef DEBUG_MARSHALL
/// Encodes @p src in host byte-order data into network byte-order at at
/// position @p pos of buffer @p buf (which has total length @p buf_len), using
/// printf format string @p fmt to format the data for debug logging.
///
/// @p src_len must be sizeof(src) for fixed-length encoding, or zero for
/// "varint" encoding, in which case @p src must be uint64_t. In the latter
/// case, if @p enc_len is zero, the "varint" encoding will use the minimal
/// number of bytes necessary, otherwise, it will encode into @p enc_len bytes.
///
/// @param      buf      Buffer to encode into.
/// @param      buf_len  Buffer length.
/// @param      pos      Buffer position to start encoding from.
/// @param      src      Source data.
/// @param      src_len  Length of @p src (zero means "varint" encoding).
/// @param      enc_len  Length to encode (only affects "varint" encoding).
/// @param      fmt      Printf format for debug logging.
///
/// @return     Buffer offset of byte following the encoded data.
///
#define enc(buf, buf_len, pos, src, src_len, enc_len, fmt)                     \
    marshall_enc((buf), (buf_len), (pos), (src), (src_len), (enc_len),         \
                 "enc %.*s = " fmt NRM " into %u byte%s (%s) at %.*s[%u..%u]", \
                 __func__, __FILE__, __LINE__, #buf, #src)
#else
#define enc(buf, buf_len, pos, src, src_len, enc_len, fmt)                     \
    marshall_enc((buf), (buf_len), (pos), (src), (src_len), (enc_len))
#endif


extern uint16_t __attribute__((nonnull)) marshall_enc(uint8_t * const buf,
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
);


#ifdef DEBUG_MARSHALL
/// Encodes @p src raw data into position @p pos of buffer @p buf (which has
/// total length @p buf_len), using printf format string @p fmt to format the
/// data for debug logging.
///
/// @param      buf      Buffer to encode into.
/// @param      buf_len  Buffer length.
/// @param      pos      Buffer position to start encoding from.
/// @param      src      Source data.
/// @param      enc_len  Length to encode.
///
/// @return     Buffer offset of byte following the encoded data.
///
#define enc_buf(buf, buf_len, pos, src, enc_len)                               \
    marshall_enc_buf((buf), (buf_len), (pos), (src), (enc_len),                \
                     "enc %.*s = %s into %u byte%s (%s) at %.*s[%u..%u]",      \
                     __func__, __FILE__, __LINE__, #buf, #src)
#else
#define enc_buf(buf, buf_len, pos, src, enc_len)                               \
    marshall_enc_buf((buf), (buf_len), (pos), (src), (enc_len))
#endif


extern uint16_t __attribute__((nonnull))
marshall_enc_buf(uint8_t * const buf,
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
);


#ifdef DEBUG_MARSHALL
/// Decodes @p dst_len bytes (if given, otherwise varint encoding is assumed) of
/// network byte-order data starting at position @p pos of buffer @p buf (which
/// has total length @p buf_len) info variable @p dst in host byte-order, using
/// printf format string @p fmt to format the data for debug logging.
///
/// For varint decoding (@p dst_len is zero), @p dst *must* point to an
/// uint64_t.
///
/// @param      dst      Destination to decode into.
/// @param      buf      Buffer to decode from.
/// @param      buf_len  Buffer length.
/// @param      pos      Buffer position to start decoding from.
/// @param      dst_len  Length to decode. Zero for varint decoding.
/// @param      fmt      Printf format for debug logging.
///
/// @return     Buffer offset of byte following the decoded data, or UINT16_MAX
///             if the decoding failed.
///
#define dec(dst, buf, buf_len, pos, dst_len, fmt)                              \
    marshall_dec((dst), (buf), (buf_len), (pos), (dst_len),                    \
                 "dec %u byte%s (%s) from %.*s[%u..%u] into %.*s = " fmt NRM,  \
                 __func__, __FILE__, __LINE__, #buf, #dst)
#else
#define dec(dst, buf, buf_len, pos, dst_len, fmt)                              \
    marshall_dec((dst), (buf), (buf_len), (pos), (dst_len))

#endif


extern uint16_t __attribute__((nonnull)) marshall_dec(void * const dst,
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
);


#ifdef DEBUG_MARSHALL
/// Decodes @p dst_len bytes of raw data starting at position @p pos of buffer
/// @p buf (which has total length @p buf_len) info variable @p dst, using
/// printf format string @p fmt to format the data for debug logging.
///
/// @param      dst      Destination to decode into.
/// @param      buf      Buffer to decode from.
/// @param      buf_len  Buffer length.
/// @param      pos      Buffer position to start decoding from.
/// @param      dst_len  Length to decode. Zero for varint decoding.
///
/// @return     Buffer offset of byte following the decoded data, or UINT16_MAX
///             if the decoding failed.
///
#define dec_buf(dst, buf, buf_len, pos, dst_len)                               \
    marshall_dec_buf((dst), (buf), (buf_len), (pos), (dst_len),                \
                     "dec %u byte%s (%s) from %.*s[%u..%u] into %.*s = %s",    \
                     __func__, __FILE__, __LINE__, #buf, #dst)
#else
#define dec_buf(dst, buf, buf_len, pos, dst_len)                               \
    marshall_dec_buf((dst), (buf), (buf_len), (pos), (dst_len))
#endif


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
                 const char * buf_str,
                 const char * dst_str
#endif
);
