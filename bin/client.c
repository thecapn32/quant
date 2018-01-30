// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2018, NetApp, Inc.
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
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <unistd.h>

#include <http_parser.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>


static void __attribute__((noreturn))
usage(const char * const name, const char * const ifname)
{
    printf("%s [options] URL\n", name);
    printf("\t[-i interface]\tinterface to run over; default %s\n", ifname);
#ifndef NDEBUG
    printf("\t[-v verbosity]\tverbosity level (0-%d, default %d)\n", DLEVEL,
           util_dlevel);
#endif
    exit(0);
}


static void set_from_url(char * const var,
                         const size_t len,
                         const char * const url,
                         const struct http_parser_url * const u,
                         const enum http_parser_url_fields f,
                         const char * const def)
{
    if ((u->field_set & (1 << f)) == 0) {
        strncpy(var, def, len);
        var[len - 1] = 0;
    } else {
        strncpy(var, &url[u->field_data[f].off], u->field_data[f].len);
        var[u->field_data[f].len] = 0;
    }
}


int main(int argc, char * argv[])
{
#ifndef NDEBUG
    util_dlevel = DLEVEL; // default to maximum compiled-in verbosity
#endif
    char ifname[IFNAMSIZ] = "lo"
#ifndef __linux__
                            "0"
#endif
        ;
    int ch;

    while ((ch = getopt(argc, argv, "hi:v:")) != -1) {
        switch (ch) {
        case 'i':
            strncpy(ifname, optarg, sizeof(ifname) - 1);
            break;
        case 'v':
#ifndef NDEBUG
            util_dlevel = (short)MIN(DLEVEL, strtoul(optarg, 0, 10));
#endif
            break;
        case 'h':
        case '?':
        default:
            usage(basename(argv[0]), ifname);
        }
    }

    // parse and verify the URI passed on the command line
    struct http_parser_url u = {0};
    char * url = optind == argc ? "" : argv[optind];
    http_parser_parse_url(url, strlen(url), 0, &u);
    ensure((u.field_set & (1 << UF_USERINFO)) == 0 &&
               (u.field_set & (1 << UF_QUERY)) == 0 &&
               (u.field_set & (1 << UF_FRAGMENT)) == 0,
           "unsupported URL components");

    // extract relevant info from URL
    char dest[1024], port[64], path[2048];
    set_from_url(dest, sizeof(dest), url, &u, UF_HOST, "localhost");
    set_from_url(port, sizeof(port), url, &u, UF_PORT, "4433");
    set_from_url(path, sizeof(path), url, &u, UF_PATH, "/index.html");

    struct addrinfo * peer;
    const struct addrinfo hints = {.ai_family = PF_INET,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};
    const int err = getaddrinfo(dest, port, &hints, &peer);
    ensure(err == 0, "getaddrinfo: %s", gai_strerror(err));
    ensure(peer->ai_next == 0, "multiple addresses not supported");

    warn(INF, "%s retrieving %s", basename(argv[0]), url);
    void * const q = q_init(ifname, 0, 0);
    struct q_conn * const c =
        q_connect(q, (struct sockaddr_in *)(void *)peer->ai_addr, dest);

    if (c) {
        if (*path) {
            // create an HTTP/0.9 request
            char req[sizeof(path) + 6];
            snprintf(req, sizeof(req), "GET %s\r\n", path);
            struct q_stream * const s = q_rsv_stream(c);
            q_write_str(q, s, req);
            q_close_stream(s);

            // read HTTP/0.9 reply and dump it to stdout
            struct w_iov_sq i = sq_head_initializer(i);
            q_readall_str(s, &i);
            struct w_iov * v;
            sq_foreach (v, &i, next)
                printf("%.*s", v->len, v->buf);
            printf("\n");
            q_free(&i);
        }
        q_close(c);
    }

    q_cleanup(q);
    freeaddrinfo(peer);
    warn(DBG, "%s exiting", basename(argv[0]));
    return 0;
}
