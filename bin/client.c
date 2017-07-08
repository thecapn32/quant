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
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

struct q_conn;


#define MAX_CONNS 10


static void usage(const char * const name,
                  const char * const ifname,
                  const char * const dest,
                  const char * const port,
                  const long conns)
{
    printf("%s\n", name);
    printf("\t[-i interface]\t\tinterface to run over; default %s\n", ifname);
    printf("\t[-d destination]\tdestination; default %s\n", dest);
    printf("\t[-n connections]\tnumber of connections to start; default %ld\n",
           conns);
    printf("\t[-p port]\t\tdestination port; default %s\n", port);
#ifndef NDEBUG
    printf("\t[-v verbosity]\t\tverbosity level (0-%u, default %u)\n", DLEVEL,
           _dlevel);
#endif
}


int main(int argc, char * argv[])
{
    char * ifname = (char *)"lo"
#ifndef __linux__
                            "0"
#endif
        ;
    char * dest = (char *)"localhost";
    char * port = (char *)"8443";
    long conns = 1;
    int ch;

    while ((ch = getopt(argc, argv, "hi:d:p:n:t:"
#ifndef NDEBUG
                                    "v:"
#endif
                        )) != -1) {
        switch (ch) {
        case 'i':
            ifname = optarg;
            break;
        case 'd':
            dest = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'n':
            conns = strtol(optarg, 0, 10);
            ensure(errno != EINVAL, "could not convert to integer");
            ensure(conns <= MAX_CONNS, "only support up to %d connections",
                   MAX_CONNS);
            break;
#ifndef NDEBUG
        case 'v':
            _dlevel = MIN(DLEVEL, MAX(0, (uint32_t)strtoul(optarg, 0, 10)));
            break;
#endif
        case 'h':
        case '?':
        default:
            usage(basename(argv[0]), ifname, dest, port, conns);
            return 0;
        }
    }

    struct addrinfo * peer;
    const struct addrinfo hints = {.ai_family = PF_INET,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};
    const int err = getaddrinfo(dest, port, &hints, &peer);
    ensure(err == 0, "getaddrinfo: %s", gai_strerror(err));
    ensure(peer->ai_next == 0, "multiple addresses not supported");

    // start some connections
    void * const q = q_init(ifname);

    struct q_conn * c[MAX_CONNS];
    for (int n = 0; n < conns; n++) {
        warn(info, "%s starting conn #%d to %s:%s", basename(argv[0]), n, dest,
             port);
        c[n] = q_connect(q, peer->ai_addr, peer->ai_addrlen, dest);
        if (!c[n])
            break;

        for (int i = 0; i < 1; i++) {
            // reserve a new stream
            struct q_stream * const s = q_rsv_stream(c[n]);

            // allocate buffers to transmit a packet
            struct w_iov_stailq o = STAILQ_HEAD_INITIALIZER(o);
            q_alloc(q, &o, 1024);
            struct w_iov * const v = STAILQ_FIRST(&o);
            ensure(STAILQ_NEXT(v, next) == 0, "w_iov_stailq too long");

            // add some payload data
            v->len =
                (uint16_t)snprintf((char *)v->buf, 1024,
                                   "***HELLO, STR %u ON CONN %" PRIx64 "!***",
                                   q_sid(s), q_cid(c[n]));
            ensure(v->len < 1024, "buffer overrun");

            // send the data
            warn(info, "writing %u byte%s: %s", v->len, plural(v->len),
                 (char *)v->buf);
            q_write(c[n], s, &o);

            // return the buffer
            q_free(q, &o);
        }

        // close the QUIC connection
        q_close(c[n]);
    }

    // clean up
    freeaddrinfo(peer);
    q_cleanup(q);
    return 0;
}
