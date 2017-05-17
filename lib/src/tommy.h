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

#pragma once

// IWYU pragma: begin_exports
#include <tommyds/tommy.h>
#include <tommyds/tommytypes.h>
// IWYU pragma: end_exports

// The tommy identifiers are quite long, shorten them a bit.
// This also lets us more easily switch between different tommy data structures.
#define hash tommy_hashlin
#define hash_done tommy_hashlin_done
#define hash_foreach tommy_hashlin_foreach
#define hash_foreach_arg tommy_hashlin_foreach_arg
#define hash_init tommy_hashlin_init
#define hash_insert tommy_hashlin_insert
#define hash_remove tommy_hashlin_remove_existing
#define hash_search tommy_hashlin_search
#define list tommy_list
#define list_head tommy_list_head
#define list_init tommy_list_init
#define list_insert_tail tommy_list_insert_tail
#define list_remove tommy_list_remove_existing
#define node tommy_node
