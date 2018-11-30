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

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <warpcore/warpcore.h>

#include "bitset.h"
#include "diet.h"


static void trace(struct diet * const d,
                  const uint64_t x
#ifdef NDEBUG
                  __attribute__((unused))
#endif
                  ,
#ifdef DIET_CLASS
                  const uint8_t t
#ifdef NDEBUG
                  __attribute__((unused))
#endif
                  ,
#endif
                  const char * const op
#ifdef NDEBUG
                  __attribute__((unused))
#endif
)
{
    char str[8192];
    diet_to_str(str, sizeof(str), d);
#ifdef DIET_CLASS
    warn(DBG, "cnt %" PRIu64 ", %s %u.%" PRIu64 ": %s", diet_cnt(d), op, t, x,
         str);
#else
    warn(DBG, "cnt %" PRIu64 ", %s %" PRIu64 ": %s", diet_cnt(d), op, x, str);
#endif

    uint64_t c = 0;
    char * s = str;
    while (*s)
        c += *(s++) == ',';
    ensure(str[0] == 0 || c + 1 == diet_cnt(d), "%u %u", c + 1, diet_cnt(d));
}


static void chk(struct diet * const d)
{
    struct ival *i, *next;
    for (i = splay_min(diet, d); i != 0; i = next) {
        next = splay_next(diet, d, i);
#ifdef DIET_CLASS
        ensure(next == 0 || i->hi + 1 < next->lo ||
                   diet_class(i) != diet_class(next),
               "%u.%" PRIu64 "-%" PRIu64 " %u.%" PRIu64 "-%" PRIu64,
               diet_class(i), i->lo, i->hi, diet_class(next), next->lo,
               next->hi);
#else
        ensure(next == 0 || i->hi + 1 < next->lo,
               "%" PRIu64 "-%" PRIu64 " %" PRIu64 "-%" PRIu64, i->lo, i->hi,
               next->lo, next->hi);
#endif
    }
}


#define N 30
bitset_define(values, N);

int main()
{
    srandom((unsigned)time(0));
#ifndef NDEBUG
    util_dlevel = DLEVEL; // default to maximum compiled-in verbosity
#endif
    struct diet d = diet_initializer(diet);
    struct values v = bitset_t_initializer(0);

    // insert some items
    while (N != bit_count(N, &v)) {
        const uint64_t x = (uint64_t)random() % N;
        if (bit_isset(N, x, &v) == 0) {
            bit_set(N, x, &v);
#ifdef DIET_CLASS
            const uint8_t t = (uint8_t)random() % 2;
#endif
            diet_insert(&d, x,
#ifdef DIET_CLASS
                        t,
#endif
                        0);
            trace(&d, x,
#ifdef DIET_CLASS
                  t,
#endif
                  "ins");
            chk(&d);
        }
    }

    // remove all items
    while (!splay_empty(&d)) {
        const uint64_t x = (uint64_t)random() % N;
        struct ival * const i = diet_find(&d, x);
        if (i) {
            diet_remove(&d, x);
            trace(&d, x,
#ifdef DIET_CLASS
                  0,
#endif
                  "rem");
            chk(&d);
        }
    }
    ensure(diet_cnt(&d) == 0, "incorrect node count %u != 0", diet_cnt(&d));

    return 0;
}
