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

#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include <conn.h> // IWYU pragma: keep
#include <pkt.h>  // IWYU pragma: keep
#include <quic.h>


extern int LLVMFuzzerTestOneInput(uint8_t * data, size_t size);
extern int LLVMFuzzerInitialize(int * argc, char *** argv);


static void * w;


int LLVMFuzzerInitialize(int * argc __attribute__((unused)),
                         char *** argv __attribute__((unused)))
{
    char i[IFNAMSIZ] = "lo"
#ifndef __linux__
                       "0"
#endif
        ;
#ifndef NDEBUG
    util_dlevel = DBG;
#endif

    w = q_init(i, 0, 0, 0, 0);

    return 0;
}


int LLVMFuzzerTestOneInput(uint8_t * data, size_t size)
{
    struct q_conn c = {.w = w};
    struct w_iov_sq i;

    struct w_iov * v = q_alloc_iov(w, MAX_PKT_LEN, 0);
    v->buf = data;
    v->len = (uint16_t)size;

    if (dec_pkt_hdr_initial(v, false))
        dec_pkt_hdr_remainder(v, &c, &i);

    q_free_iov(v);

    return 0;
}
