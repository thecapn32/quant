#pragma once

#include <tommyds/tommy.h>

// The tommy identifiers are quite long, shorten them a bit.
// This also lets is more easily use a different tommy data structure.
#define hash tommy_hashlin
#define hash_init tommy_hashlin_init
#define hash_insert tommy_hashlin_insert
#define hash_search tommy_hashlin_search
#define hash_u32(i) tommy_inthash_u32((tommy_uint32_t)(i))
#define node tommy_node
