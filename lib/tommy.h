#pragma once

#include <tommyds/tommy.h>

// The tommy identifiers are quite long, shorten them a bit.
// This also lets us more easily switch between different tommy data structures.
#define hash tommy_hashlin
#define hash_init tommy_hashlin_init
#define hash_insert tommy_hashlin_insert
#define hash_search tommy_hashlin_search
#define hash_foreach tommy_hashlin_foreach
#define hash_foreach_arg tommy_hashlin_foreach_arg
#define list tommy_list
#define list_head tommy_list_head
#define list_insert_tail tommy_list_insert_tail
#define node tommy_node
