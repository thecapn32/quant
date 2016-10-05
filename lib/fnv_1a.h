#pragma once

#include "pkt.h"

uint128_t fnv_1a(const struct q_pkt * const pkt,
                 const uint16_t             skip,
                 const uint16_t             skip_len);
