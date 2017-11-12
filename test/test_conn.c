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

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#ifndef NDEBUG
#include <getopt.h>
#include <stdlib.h>
#include <sys/param.h>
#endif

#include <quant/quant.h>
#include <warpcore/warpcore.h>


int main(int argc
#ifdef NDEBUG
         __attribute__((unused))
#endif
         ,
         char * argv[]
#ifdef NDEBUG
         __attribute__((unused))
#endif
)
{
#ifndef NDEBUG
    int ch;
    while ((ch = getopt(argc, argv, "v:")) != -1)
        if (ch == 'v')
            util_dlevel = MIN(DLEVEL, MAX(0, (short)strtoul(optarg, 0, 10)));
#endif

    // init
    char cert[MAXPATHLEN] =
        "/etc/letsencrypt/live/slate.eggert.org/fullchain.pem";
    char key[MAXPATHLEN] = "/etc/letsencrypt/live/slate.eggert.org/privkey.pem";
    void * q = q_init("lo"
#ifndef __linux__
                      "0"
#endif
                      ,
                      cert, key);

    // bind server socket
    struct q_conn * const sc = q_bind(q, 55555);

    // connect to server
    const struct sockaddr_in sip = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = inet_addr("127.0.0.1"),
                                    .sin_port = htons(55555)};
    struct q_conn * const cc = q_connect(q, &sip, "localhost");
    ensure(cc, "is zero");

    // accept connection
    q_accept(sc);

    // reserve a new stream
    struct q_stream * const s = q_rsv_stream(cc);

    // allocate buffers to transmit a packet
    struct w_iov_sq o = sq_head_initializer(o);
    q_alloc(q, &o, 1024);
    struct w_iov * const ov = sq_first(&o);

    // add some payload data
    ov->len = (uint16_t)snprintf((char *)ov->buf, 1024,
                                 "***HELLO, STR %u ON CONN %" PRIx64 "!***",
                                 q_sid(s), q_cid(cc));

    // send the data
    warn(INF, "writing %u byte%s: %s", ov->len, plural(ov->len),
         (char *)ov->buf);
    q_write(s, &o);

    // read the data
    struct w_iov_sq i = sq_head_initializer(i);
    q_read(sc, &i);
    struct w_iov * const iv = sq_first(&i);
    ensure(strncmp((char *)ov->buf, (char *)iv->buf, ov->len) == 0,
           "data mismatch");

    // close connections
    q_close(cc);
    q_close(sc);
    q_cleanup(q);
}
