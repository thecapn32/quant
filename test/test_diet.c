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

#include <bitstring.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>

#include <warpcore/warpcore.h>

#include "diet.h"


static void log(struct diet * const d,
                const uint64_t x,
                const uint8_t t,
                const char * const op)
{
    char str[8192];
    diet_to_str(str, sizeof(str), d);
    warn(DBG, "cnt %" PRIu64 ", %s %u.%" PRIu64 ": %s", diet_cnt(d), op, t, x,
         str);

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
        ensure(next == 0 || i->hi + 1 < next->lo ||
                   diet_class(i) != diet_class(next),
               "%u.%" PRIu64 "-%" PRIu64 " %u.%" PRIu64 "-%" PRIu64,
               diet_class(i), i->lo, i->hi, diet_class(next), next->lo,
               next->hi);
    }
}


#define N 30

int main()
{
    util_dlevel = DLEVEL; // default to maximum compiled-in verbosity
    struct diet d = diet_initializer(diet);
    bitstr_t bit_decl(values, N);
    bit_nclear(values, 0, N - 1);

    // insert some items
    int n = 0;
    while (n != -1) {
        bit_ffc(values, N, &n);
        const uint64_t x = arc4random_uniform(N);
        if (bit_test(values, x) == 0) {
            bit_set(values, x);
            const uint8_t t = (uint8_t)arc4random_uniform(2);
            diet_insert(&d, x, t, 0);
            log(&d, x, t, "ins");
            chk(&d);
        }
    }

    // remove all items
    while (!splay_empty(&d)) {
        const uint64_t x = arc4random_uniform(N);
        struct ival * const i = diet_find(&d, x);
        if (i) {
            diet_remove(&d, x);
            log(&d, x, 0, "rem");
            chk(&d);
        }
    }
    ensure(diet_cnt(&d) == 0, "incorrect node count %u != 0", diet_cnt(&d));

    return 0;
}
