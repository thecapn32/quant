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

#include <stddef.h>
#include <stdint.h>

#include <warpcore/warpcore.h>


/// This is a C adaptation of the "discrete interval encoding tree" (DIET) data
/// structure described in: Martin Erwig, "Diets for fat sets", Journal of
/// Functional Programming, Vol. 8, No. 6, pp. 627–632, 1998.
/// https://web.engr.oregonstate.edu/~erwig/papers/abstracts.html#JFP98


/// An interval [hi..lo] to be used with diet structures.
///
struct ival {
    uint64_t lo;            ///< Lower bound of the interval.
    uint64_t hi;            ///< Upper bound of the interval.
    SPLAY_ENTRY(ival) node; ///< Splay tree node date.
};


extern int64_t __attribute__((nonnull))
ival_cmp(const struct ival * const a, const struct ival * const b);

struct diet {
    SPLAY_HEAD(, ival); ///< Splay head.
    uint64_t cnt;       ///< Number of nodes (intervals) in the diet tree.
};

SPLAY_PROTOTYPE(diet, ival, node, ival_cmp)

extern struct ival * diet_find(struct diet * const t, const uint64_t n);

extern struct ival * __attribute__((nonnull))
diet_insert(struct diet * const t, const uint64_t n);

extern void __attribute__((nonnull))
diet_remove(struct diet * const t, const uint64_t n);

extern void __attribute__((nonnull)) diet_free(struct diet * const t);

extern size_t __attribute__((nonnull))
diet_to_str(char * const str, const size_t len, struct diet * const d);

#define diet_max(t) (SPLAY_EMPTY(t) ? 0 : SPLAY_MAX(diet, (t))->hi)

#define diet_min(t) (SPLAY_EMPTY(t) ? 0 : SPLAY_MIN(diet, (t))->lo)
