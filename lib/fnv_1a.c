#include <stdint.h>

#include "fnv_1a.h"
#include "pkt.h"


uint128_t fnv_1a(const struct q_pkt * const pkt,
                 const uint16_t             skip,
                 const uint16_t             skip_len)
{
    static const uint128_t prime =
        (((uint128_t)0x0000000001000000) << 64) | 0x000000000000013B;
    uint128_t hash =
        (((uint128_t)0x6C62272E07BB0142) << 64) | 0x62B821756295C58D;
    for (uint16_t i = 0; i < pkt->len; i++)
        if (i < skip || i >= skip + skip_len) {
            hash ^= pkt->buf[i];
            hash *= prime;
        }
    return hash;
}
