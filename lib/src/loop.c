// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
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

#include <stdbool.h>
#include <stdint.h>

#include <timeout.h>

#include "conn.h"
#include "loop.h"
#include "quic.h"


#if !HAVE_64BIT
#define WHEEL_BIT 5
#endif
#define WHEEL_NUM 6
#define TIMEOUT_DISABLE_INTERVALS
#include <timeout.c>


func_ptr api_func = 0;
void * api_conn = 0;
void * api_strm = 0;

static uint64_t now;
static bool break_loop;


void loop_break(void)
{
    break_loop = true;
    api_func = 0;
    api_conn = api_strm = 0;
}


void loop_init(void)
{
    now = w_now();
    break_loop = false;
}


uint64_t loop_now(void)
{
    return now;
}


void __attribute__((nonnull(1))) loop_run(struct w_engine * const w,
                                          const func_ptr f,
                                          struct q_conn * const c,
                                          struct q_stream * const s)
{
    ensure(api_func == 0, "other API call active");
    api_func = f;
    api_conn = c;
    api_strm = s;
    break_loop = false;

    while (likely(break_loop == false)) {
        now = w_now();
        timeouts_update(ped(w)->wheel, now);

        struct timeout * t;
        TIMEOUTS_FOREACH (t, ped(w)->wheel, TIMEOUTS_EXPIRED)
            (*t->callback.fn)(t->callback.arg);

        if (break_loop)
            break;

        const uint64_t next = timeouts_timeout(ped(w)->wheel);
        // warn(CRT, "%" PRIu64, next);
        if (next == 0)
            continue;

        if (w_nic_rx(w, (int64_t)next) == false)
            continue;

        struct w_sock_slist sl = w_sock_slist_initializer(sl);
        if (w_rx_ready(w, &sl) == 0)
            continue;

        now = w_now();
        timeouts_update(ped(w)->wheel, now);

        struct w_sock * ws;
        sl_foreach (ws, &sl, next)
            rx(ws);
    }

    api_func = 0;
    api_conn = api_strm = 0;
}
