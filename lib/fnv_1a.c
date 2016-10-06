#include <assert.h>

#include "fnv_1a.h"

uint128_t fnv_1a(const void * restrict const buf,
                 const size_t                len,
                 const size_t                skip_pos,
                 const size_t                skip_len)
{
    assert((skip_pos <= len) && (skip_pos + skip_len <= len));

    static const uint128_t prime =
        (((uint128_t)0x0000000001000000) << 64) | 0x000000000000013B;
    uint128_t hash =
        (((uint128_t)0x6C62272E07BB0142) << 64) | 0x62B821756295C58D;

    // two consecutive loops should be faster than one loop with an "if"
    const uint8_t * restrict const bytes = buf;
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
