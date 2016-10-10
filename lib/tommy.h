#pragma once

// there are some warnings in the tommyds code that I can't do anything about,
// other than suppress them
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdocumentation-unknown-command"
#pragma GCC diagnostic ignored "-Wpadded"
#pragma GCC diagnostic ignored "-Wreserved-id-macro"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#include <tommyds/tommy.h>
#pragma GCC diagnostic pop


// The tommy identifiers are quite long, shorten them a bit.
// This also lets is more easily use a different tommy data structure.
#define hash			tommy_hashlin
#define hash_init		tommy_hashlin_init
#define hash_insert		tommy_hashlin_insert
#define hash_search		tommy_hashlin_search
#define hash_u32(i)		tommy_inthash_u32((tommy_uint32_t)(i))
#define node			tommy_node
