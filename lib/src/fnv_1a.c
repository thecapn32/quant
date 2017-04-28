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

#include <stddef.h>
#include <stdint.h>

#include <warpcore/warpcore.h>

#include "fnv_1a.h"


uint128_t fnv_1a(const void * const buf,
                 const size_t len,
                 const size_t skip_pos,
                 const size_t skip_len)
{
    ensure((skip_pos <= len) && (skip_pos + skip_len <= len),
           "len %zu, skip_pos %zu, skip_len %zu", len, skip_pos, skip_len);

    const uint128_t prime =
        (((uint128_t)0x0000000001000000) << 64) | 0x000000000000013B;
    uint128_t hash =
        (((uint128_t)0x6C62272E07BB0142) << 64) | 0x62B821756295C58D;

    // two consecutive loops should be faster than one loop with an "if"
    const uint8_t * const bytes = buf;
    for (size_t i = 0; i < skip_pos; i++) {
        hash ^= bytes[i];
        hash *= prime;
    }
    for (size_t i = skip_pos + skip_len; i < len; i++) {
        hash ^= bytes[i];
        hash *= prime;
    }
    return hash;
}
