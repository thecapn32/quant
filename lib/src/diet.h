// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2018, NetApp, Inc.
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

#include <ev.h>
#include <warpcore/warpcore.h>


/// This is a C adaptation of the "discrete interval encoding tree" (DIET) data
/// structure described in: Martin Erwig, "Diets for fat sets", Journal of
/// Functional Programming, Vol. 8, No. 6, pp. 627–632, 1998.
/// https://web.engr.oregonstate.edu/~erwig/papers/abstracts.html#JFP98
///
/// This implementation extends the basic diet structure by adding a "class"
/// field to each interval. Only intervals of the same class can be merged.
/// (This is used by quant to handle different packet types.) It also maintains
/// a timestamp of the last insert operation into an @p ival, for the purposes
/// of calculating the ACK deplay.


/// An interval [hi..lo] to be used with diet structures, of a given type.
///
struct ival {
    splay_entry(ival) node; ///< Splay tree node data.
    uint64_t lo;            ///< Lower bound of the interval.
    uint64_t hi;            ///< Upper bound of the interval.
    ev_tstamp t;            ///< Time stamp of last insert into this interval.
    uint8_t c;              ///< Interval class.
    uint8_t _unused[7];
};


extern int __attribute__((nonnull))
ival_cmp(const struct ival * const a, const struct ival * const b);

struct diet {
    splay_head(, ival); ///< Splay head.
    uint64_t cnt;       ///< Number of nodes (intervals) in the diet tree.
};


#define diet_initializer(d)                                                    \
    {                                                                          \
        splay_initializer(d), 0                                                \
    }


#define diet_init(d)                                                           \
    do {                                                                       \
        splay_init(d);                                                         \
        (d)->cnt = 0;                                                          \
    } while (0)


SPLAY_PROTOTYPE(diet, ival, node, ival_cmp)

extern struct ival * diet_find(struct diet * const d, const uint64_t n);

extern struct ival * __attribute__((nonnull)) diet_insert(struct diet * const d,
                                                          const uint64_t n,
                                                          const uint8_t c,
                                                          const ev_tstamp t);

extern void __attribute__((nonnull))
diet_remove(struct diet * const d, const uint64_t n);

extern void __attribute__((nonnull)) diet_free(struct diet * const d);

extern size_t __attribute__((nonnull))
diet_to_str(char * const str, const size_t len, struct diet * const d);

#define diet_max(d) (splay_empty(d) ? 0 : splay_max(diet, (d))->hi)

#define diet_min(d) (splay_empty(d) ? 0 : splay_min(diet, (d))->lo)

#define diet_empty(d) splay_empty(d)

#define diet_cnt(d) ((d)->cnt)

#define diet_class(d) ((d)->c)

#define diet_timestamp(d) ((d)->t)
