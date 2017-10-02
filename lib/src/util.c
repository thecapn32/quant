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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

struct q_stream;


void q_write_str(void * const q,
                 struct q_stream * const s,
                 const char * const str)
{
    // allocate tail queue
    struct w_iov_sq o = sq_head_initializer(o);
    q_alloc(q, &o, (uint32_t)strlen(str));

    // chunk up string
    const char * i = str;
    struct w_iov * v;
    sq_foreach (v, &o, next) {
        strncpy((char *)v->buf, i, v->len);
        i += v->len;
    }

    // write it and free tail queue
    q_write(s, &o);
    q_free(q, &o);
}


void q_write_file(void * const q,
                  struct q_stream * const s,
                  const int f,
                  const uint32_t len)
{
    // allocate tail queue
    struct w_iov_sq o = sq_head_initializer(o);
    q_alloc(q, &o, len);
    const uint64_t n = w_iov_sq_cnt(&o);
    struct iovec * const iov = calloc(n, sizeof(struct iovec));
    ensure(iov, "could not calloc");

    // prep iovec and read file
    uint32_t i = 0;
    struct w_iov * v;
    sq_foreach (v, &o, next)
        iov[i++] = (struct iovec){.iov_base = v->buf, .iov_len = v->len};
    const ssize_t l = readv(f, iov, (int)n);
    ensure(len == l, "could not read file");

    // write it and free tail queue and iov
    q_write(s, &o);
    q_free(q, &o);
    free(iov);
}
