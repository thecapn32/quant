#pragma once

#include <stddef.h>
#include <stdint.h>


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
