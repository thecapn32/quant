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

#include <warpcore/warpcore.h>

#include "diet.h"


int main()
{
    const uint64_t n = 20;
    char s[256];
    struct diet d = diet_initializer(diet);
    util_dlevel = DLEVEL; // default to maximum compiled-in verbosity

    // insert some items
    uint64_t j = 1;
    while (j <= n) {
        const uint64_t x = arc4random_uniform(n) + 1;
        struct ival * const i = diet_find(&d, x);
        if (i == 0) {
            const uint8_t t = (uint8_t)arc4random_uniform(2);
            diet_insert(&d, x, t);
            diet_to_str(s, sizeof(s), &d);
            warn(DBG,
                 "[%03" PRIu64 "] ranges %03" PRIu64 ", ins %u.%03" PRIu64
                 ": %s",
                 j, diet_cnt(&d), t, x, s);
            j++;
        }
    }
    // the above should have printed "1.1-n" as the last line
    ensure(diet_cnt(&d) == 1, "incorrect node count %u != 1", diet_cnt(&d));

    // // remove all items
    // j = 1;
    // while (!splay_empty(&d)) {
    //     const uint64_t x = arc4random_uniform(n) + 1;
    //     struct ival * const i = diet_find(&d, x);
    //     if (i) {
    //         diet_remove(&d, x);
    //         diet_to_str(s, sizeof(s), &d);
    //         warn(DBG,
    //              "[%03" PRIu64 "] ranges %03" PRIu64 ", rem %03" PRIu64 ":
    //              %s", j, diet_cnt(&d), x, s);
    //         j++;
    //     }
    // }
    // ensure(diet_cnt(&d) == 0, "incorrect node count %u != 0", diet_cnt(&d));

    return 0;
}
