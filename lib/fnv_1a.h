// Copyright (c) 2016, NetApp, Inc.
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

#include <stddef.h>


#ifndef _UINT128_T
/// If @p stdint.h doesn't define @p uint128_t, define it for ourselves.
__extension__ typedef unsigned __int128 uint128_t;
#endif

///
/// Compute an [FNV-1a 128-bit
/// hash](http://www.isthe.com/chongo/tech/comp/fnv/index.html) over the given
/// buffer. A region of the buffer can be excluded from the hash, by specifying
/// its starting position in @p skip_pos and its length in @p skip_len.
///
/// @param      buf       The buffer.
/// @param      len       The length of @p buf.
/// @param      skip_pos  The beginning of the region of @p buf to exclude from
///                       the hash. Can be 0.
/// @param      skip_len  The length of the region of @p buf to exclude from the
///                       hash. Can be 0.
///
/// @return     The FNV-1a 128-bit hash of @p buffer, excluding the skip region.
///
extern uint128_t __attribute__((nonnull)) fnv_1a(const void * const buf,
                                                 const size_t len,
                                                 const size_t skip_pos,
                                                 const size_t skip_len);
