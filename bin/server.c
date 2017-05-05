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

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>


static void usage(const char * const name,
                  const char * const ifname,
                  const uint16_t port,
                  const long timeout)
{
    printf("%s\n", name);
    printf("\t[-i interface]\tinterface to run over; default %s\n", ifname);
    printf("\t[-p port]\tdestination port; default %d\n", port);
    printf("\t[-t sec]\texit after some seconds (0 to disable); default %ld\n",
           timeout);
}


int main(int argc, char * argv[])
{
    char * ifname = "lo0";
    uint16_t port = 8443;
    long timeout = 3;
    int ch;

    while ((ch = getopt(argc, argv, "hi:p:t:")) != -1) {
        switch (ch) {
        case 'i':
            ifname = optarg;
            break;
        case 'p':
            port = MIN(UINT16_MAX, MAX(port, (uint16_t)strtol(optarg, 0, 10)));
            break;
        case 't':
            timeout = strtol(optarg, 0, 10);
            ensure(errno != EINVAL, "could not convert to integer");
            break;
        case 'h':
        case '?':
        default:
            usage(basename(argv[0]), ifname, port, timeout);
            return 0;
        }
    }

    void * const q = q_init(ifname, timeout);
    warn(debug, "%s ready on %s port %d", basename(argv[0]), ifname, port);

    const uint64_t c = q_bind(q, port);
    if (c) {
        while (1) {
            uint32_t sid;
            struct w_iov_stailq i = STAILQ_HEAD_INITIALIZER(i);
            q_read(c, &sid, &i);
            const uint32_t len = w_iov_stailq_len(&i);
            warn(info, "rx %u byte%s on str %d on conn %" PRIu64, len,
                 plural(len), sid, c);
            struct w_iov * v;
            STAILQ_FOREACH (v, &i, next)
                warn(info, "%s", v->buf);
            q_close(c);
        }
    }

    q_cleanup(q);
    return 0;
}
