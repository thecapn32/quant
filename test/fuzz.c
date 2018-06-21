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
#include <stdint.h>
#include <string.h>
#include <sys/param.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include <conn.h>
#include <pkt.h>
#include <quic.h>
#include <tls.h>


extern int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size);
extern int LLVMFuzzerInitialize(int * argc, char *** argv);


static void * w;
static struct q_conn * c;

int LLVMFuzzerInitialize(int * argc __attribute__((unused)),
                         char *** argv __attribute__((unused)))
{
    char i[IFNAMSIZ] = "lo"
#ifndef __linux__
                       "0"
#endif
        ;
#ifndef NDEBUG
    util_dlevel = ERR;
#endif

    w = q_init(i, 0, 0, 0, 0, false);
    const struct cid dcid = {.len = 1, .id = "\00"};
    const struct cid scid = {.len = 1, .id = "\ff"};
    c = new_conn(w, 0, &dcid, &scid, 0, 0, 0, 0);

    // create fake 1-RTT/early crypto contexts (by copying the handshake one)
    init_tls(c);
    init_hshk_prot(c);
    memcpy(&c->tls.in_pp.one_rtt[0], &c->tls.in_pp.handshake,
           sizeof(c->tls.in_pp.one_rtt));
    memcpy(&c->tls.in_pp.early_data, &c->tls.in_pp.handshake,
           sizeof(c->tls.in_pp.early_data));

    return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size)
{
    // we need one byte to init a flag
    if (size == 0)
        return 0;

    struct w_iov * v = q_alloc_iov(w, MAX_PKT_LEN, 0);
    ensure(v, "cannot alloc w_iov");

    const bool is_clnt = (data[0] % 2);

    memcpy(v->buf, &data[1], MIN(size - 1, v->len));
    v->len = (uint16_t)MIN(size - 1, v->len);
    struct w_iov_sq i = sq_head_initializer(i);

    if (dec_pkt_hdr_initial(v, is_clnt))
        dec_pkt_hdr_remainder(v, c, &i);

    q_free_iov(v);
    free_iov_sq(&i, c);

    return 0;
}
