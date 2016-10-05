#include "pkt.h"


uint8_t pkt_nr_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x30) >> 4;
    if (l == 0)
        return 1;
    else
        return 2 * l;
}
