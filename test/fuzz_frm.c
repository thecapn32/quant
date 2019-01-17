// Copyright (c) 2014-2018, NetApp, Inc.
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

#include <stdint.h>
#include <string.h>
#include <sys/param.h>

#define klib_unused

#include <khash.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include <conn.h>
#include <frame.h>
#include <pkt.h>
#include <quic.h>
#include <stream.h>
#include <tls.h>


extern int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size);

static void * w;
static struct q_conn * c;


static int init(void)
{
    w = q_init("lo"
#ifndef __linux__
               "0"
#endif
               ,
               0);
    c = new_conn(w, 0xcacacaca, 0, 0, 0, "fuzzer", 0, 0);
    init_tls(c);
    return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size)
{
    static int needs_init = 1;
    if (needs_init)
        needs_init = init();

    struct w_iov_sq i = w_iov_sq_initializer(i);
    q_alloc(w, &i, MAX_PKT_LEN);
    struct w_iov * v = sq_first(&i);
    v->len = (uint16_t)MIN(size, v->len);
    memcpy(v->buf, data, v->len);

    struct w_iov * const orig_v = v;
    dec_frames(c, &v);
    if (meta(v).stream == 0)
        free_iov(v);
    if (orig_v != v && meta(orig_v).stream == 0)
        free_iov(orig_v);

    struct q_stream * s;
    kh_foreach (s, c->streams_by_id)
        free_stream(s);

    for (epoch_t e = ep_init; e <= ep_data; e++)
        if (c->cstreams[e])
            free_stream(c->cstreams[e]);

    return 0;
}
