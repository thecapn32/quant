// SPDX-License-Identifier: BSD-2-Clause
//
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

#include <inttypes.h>
#include <stdint.h>

#include <warpcore/warpcore.h>

#include "diet.h"


int main()
{
    const uint64_t n = 20;
    char s[256];
    struct diet t = diet_initializer(diet);

    plat_initrandom();

    // insert some items
    uint64_t i = 1;
    while (i <= n) {
        const uint64_t x = (uint64_t)plat_random() % n + 1;
        if (diet_find(&t, x) == 0) {
            diet_insert(&t, x);
            diet_to_str(s, sizeof(s), &t);
            warn(DBG,
                 "[%03" PRIu64 "] ranges %03" PRIu64 ", ins %03" PRIu64 ": %s",
                 i, t.cnt, x, s);
            i++;
        }
    }
    // the above should have printed "1-n" as the last line

    // remove all items
    i = 1;
    while (!splay_empty(&t)) {
        const uint64_t x = (uint64_t)plat_random() % n + 1;
        if (diet_find(&t, x)) {
            diet_remove(&t, x);
            diet_to_str(s, sizeof(s), &t);
            warn(DBG,
                 "[%03" PRIu64 "] ranges %03" PRIu64 ", rem %03" PRIu64 ": %s",
                 i, t.cnt, x, s);
            i++;
        }
    }

    return 0;
}
