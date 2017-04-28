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
#include <sys/queue.h>
#include <sys/socket.h>

#include <quic/quic.h>
#include <warpcore/warpcore.h>


#define MAX_CONNS 10


static void usage(const char * const name,
                  const char * const ifname,
                  const char * const dest,
                  const char * const port,
                  const long conns,
                  const long timeout)
{
    printf("%s\n", name);
    printf("\t[-i interface]\t\tinterface to run over; default %s\n", ifname);
    printf("\t[-d destination]\tdestination; default %s\n", dest);
    printf("\t[-n connections]\tnumber of connections to start; default %ld\n",
           conns);
    printf("\t[-p port]\t\tdestination port; default %s\n", port);
    printf("\t[-t sec]\t\texit after some seconds (0 to disable); "
           "default %ld\n",
           timeout);
}


int main(int argc, char * argv[])
{
    char * ifname = "lo0";
    char * dest = "127.0.0.1";
    char * port = "8443";
    long conns = 1;
    long timeout = 3;
    int ch;

    while ((ch = getopt(argc, argv, "hi:d:p:n:t:")) != -1) {
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
        case 't':
            timeout = strtol(optarg, 0, 10);
            ensure(errno != EINVAL, "could not convert to integer");
            break;
        case 'h':
        case '?':
        default:
            usage(basename(argv[0]), ifname, dest, port, conns, timeout);
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
    void * const q = q_init(ifname, timeout);

    uint64_t cid[MAX_CONNS];
    for (int n = 0; n < conns; n++) {
        warn(info, "%s starting conn #%d to %s:%s", basename(argv[0]), n, dest,
             port);
        cid[n] = q_connect(q, peer->ai_addr, peer->ai_addrlen);

        for (int i = 0; i < 2; i++) {
            // reserve a new stream
            const uint32_t sid = q_rsv_stream(cid[n]);

            // allocate buffers to transmit a packet
            struct w_iov_stailq o = STAILQ_HEAD_INITIALIZER(o);
            q_alloc(q, &o, 1024);
            struct w_iov * const v = STAILQ_FIRST(&o);
            ensure(STAILQ_NEXT(v, next) == 0, "w_iov_stailq too long");

            // add some payload data
            v->len = (uint16_t)snprintf(
                v->buf, 1024, "***HELLO, STR %u ON CONN %" PRIu64 "!***", sid,
                cid[n]);
            ensure(v->len < 1024, "buffer overrun");
            warn(info, "payload len %u", v->len);

            // send the data
            warn(info, "writing: %s", (char *)v->buf);
            q_write(cid[n], sid, &o);

            // return the buffer
            q_free(q, &o);
        }

        // close the QUIC connection
        q_close(cid[n]);
    }

    // clean up
    freeaddrinfo(peer);
    q_cleanup(q);
    return 0;
}
