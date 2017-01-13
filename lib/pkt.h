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

#include <warpcore.h>

#include "quic_internal.h"

struct q_conn;


#define MAX_PKT_LEN 1350
#define MAX_NONCE_LEN 32
#define HASH_LEN 12

/// A QUIC public header.
struct q_cmn_hdr {
    uint8_t flags;
    uint64_t cid;
    q_tag vers;
    uint64_t nr;
    uint8_t aead[];
} __attribute__((packed));


#define F_VERS 0x01
#define F_PUB_RST 0x02
#define F_KEY_PHS 0x04
#define F_CID 0x08
#define F_MULTIPATH 0x40 // reserved
#define F_UNUSED 0x80    // reserved (must be 0)


/// Decode the packet number length information in the flags field of the
/// public
/// header.
///
/// @param[in]  flags  The flags in a public header
///
/// @return     Length of the packet number field in bytes.
///
inline uint8_t __attribute__((const)) dec_pkt_nr_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x30) >> 4;
    ensure(/* l >= 0 && */ l <= 3, "cannot decode packet number length %u", l);
    const uint8_t dec[] = {1, 2, 3, 6};
    return dec[l];
}

/// Encode a byte length @p n into a representation that can be or'ed into the
/// public header flags.
///
/// @param[in]  n     Byte length to encode.
///
/// @return     Encoded byte length suitable for or'ing into the public header
///             flags.
///
inline uint8_t __attribute__((const)) enc_pkt_nr_len(const uint8_t n)
{
    ensure(n == 1 || n == 2 || n == 4 || n == 6,
           "cannot encode packet number length %u", n);
    const uint8_t enc[] = {0xFF, 0, 1, 0xFF, 3, 0xFF, 4}; // 0xFF invalid
    return enc[n];
}


/// Calculate the minimum number of bytes needed to encode packet number @p n.
///
/// @param[in]  n     A packet number.
///
/// @return     The minimum number of bytes needed to encode @p n.
///
inline uint8_t __attribute__((const)) calc_req_pkt_nr_len(const uint64_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    if (n < UINT32_MAX)
        return 4;
    return 6;
}

extern uint16_t __attribute__((nonnull))
dec_cmn_hdr(struct q_cmn_hdr * const ph,
            const uint8_t * const buf,
            const uint16_t len,
            struct q_conn ** const c);

extern uint16_t __attribute__((nonnull)) enc_pkt(struct q_conn * const c,
                                                 uint8_t * const buf,
                                                 const uint16_t len,
                                                 const uint16_t max_len);
