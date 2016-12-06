// Copyright (c) 2016, NetApp, Inc.
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

#include <getopt.h>
#include <inttypes.h>
#include <sys/param.h>
#include <unistd.h>

#include "quic.h"

#include <warpcore.h>


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


// static void check_stream(void * arg, void * obj)
// {
//     struct q_conn * c = arg;
//     struct q_stream * s = obj;
//     if (s->in_len) {
//         warn(info,
//              "received %" PRIu64 " byte%c on stream %d on conn %" PRIu64 ":
//              %s",
//              s->in_len, plural(s->in_len), s->id, c->id, s->in);
//         // we have consumed the data
//         free(s->in);
//         s->in = 0;
//         s->in_len = 0;
//     }
// }


// static void check_conn(void * obj)
// {
//     struct q_conn * c = obj;
//     hash_foreach_arg(&c->streams, &check_stream, c);
// }


// static void read_cb(struct ev_loop * const loop
//                     __attribute__((unused)),
//                     ev_async * const w __attribute__((unused)),
//                     int e)
// {
//     assert(e = EV_READ, "unknown event %d", e);
//     hash_foreach(&q_conns, &check_conn);
// }


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
            assert(errno != EINVAL, "could not convert to integer");
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
        size_t len = 0;
        do {
            char msg[1024];
            const size_t msg_len = sizeof(msg);
            uint32_t sid;
            len = q_read(c, &sid, msg, msg_len);
            warn(info, "rx %zu byte%c on str %d on conn %" PRIu64 ": %s", len,
                 plural(len), sid, c, msg);
        } while (len != 0);
        q_close(c);
    }

    q_cleanup(q);
    return 0;
}
