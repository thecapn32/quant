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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <unistd.h>

#include <http_parser.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>


struct conn_cache_entry {
    struct sockaddr_in dst;
    struct q_conn * c;
    splay_entry(conn_cache_entry) node;
};


struct conn_cache {
    splay_head(, conn_cache_entry);
};


static uint32_t __attribute__((nonnull))
conn_cmp(const struct conn_cache_entry * const a,
         const struct conn_cache_entry * const b)
{
    const uint32_t diff = (a->dst.sin_addr.s_addr > b->dst.sin_addr.s_addr) -
                          (a->dst.sin_addr.s_addr < b->dst.sin_addr.s_addr);
    if (diff)
        return diff;
    return (a->dst.sin_port > b->dst.sin_port) -
           (a->dst.sin_port < b->dst.sin_port);
}


SPLAY_PROTOTYPE(conn_cache, conn_cache_entry, node, conn_cmp)
SPLAY_GENERATE(conn_cache, conn_cache_entry, node, conn_cmp)


struct stream_entry {
    sl_entry(stream_entry) next;
    struct q_conn * c;
    struct q_stream * s;
};


static sl_head(stream_list, stream_entry) sl = sl_head_initializer(sl);


static void __attribute__((noreturn, nonnull)) usage(const char * const name,
                                                     const char * const ifname,
                                                     const char * const cache)
{
    printf("%s [options] URL\n", name);
    printf("\t[-i interface]\tinterface to run over; default %s\n", ifname);
#ifndef NDEBUG
    printf("\t[-v verbosity]\tverbosity level (0-%d, default %d)\n", DLEVEL,
           util_dlevel);
#endif
    printf("\t[-s cache]\tTLS 0-RTT state cache; default %s\n", cache);
    exit(0);
}


static void __attribute__((nonnull))
set_from_url(char * const var,
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

static struct q_conn * __attribute__((nonnull))
get(void * const q,
    struct conn_cache * const cc,
    const char * const dest,
    const char * const port,
    struct w_iov_sq * const req)
{
    struct addrinfo * peer;
    const struct addrinfo hints = {.ai_family = PF_INET,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};
    const int err = getaddrinfo(dest, port, &hints, &peer);
    ensure(err == 0, "getaddrinfo: %s", gai_strerror(err));
    ensure(peer->ai_next == 0, "multiple addresses not supported");

    // add to stream list
    struct stream_entry * se = calloc(1, sizeof(*se));
    ensure(se, "calloc failed");
    sl_insert_head(&sl, se, next);

    // do we have a connection open to this peer?
    struct conn_cache_entry which = {.dst =
                                         *(struct sockaddr_in *)&peer->ai_addr};
    struct conn_cache_entry * cce = splay_find(conn_cache, cc, &which);
    if (cce == 0) {
        // no, open a new connection
        cce = calloc(1, sizeof(*cce));
        ensure(cce, "calloc failed");
        cce->c = q_connect(q, (struct sockaddr_in *)(void *)peer->ai_addr, dest,
                           req, &se->s);
        ensure(cce->c, "connection established");
        se->c = cce->c;

        // insert into connection cache
        cce->dst = *(struct sockaddr_in *)&peer->ai_addr;
        splay_insert(conn_cache, cc, cce);

    } else {
        se->s = q_rsv_stream(cce->c);
        q_write(se->s, req);
    }

    q_close_stream(se->s);
    freeaddrinfo(peer);

    return cce->c; // NOLINT
}


static void __attribute__((nonnull)) free_cc(struct conn_cache * const cc)
{
    struct conn_cache_entry *i, *next;
    for (i = splay_min(conn_cache, cc); i != 0; i = next) {
        next = splay_next(conn_cache, cc, i);
        splay_remove(conn_cache, cc, i);
        free(i);
    }
}


static void free_sl(void)
{
    struct stream_entry *i = 0, *tmp = 0;
    sl_foreach_safe (i, &sl, next, tmp) {
        sl_remove(&sl, i, stream_entry, next);
        free(i);
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
    char cache[MAXPATHLEN] = "/tmp/" QUANT "-session";

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
            usage(basename(argv[0]), ifname, cache);
        }
    }

    void * const q = q_init(ifname, 0, 0, cache);
    struct conn_cache cc = splay_initializer(cc);
    struct http_parser_url u = {0};

    while (optind < argc) {
        // parse and verify the URIs passed on the command line
        const char * const url = argv[optind++];
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

        // assemble an HTTP/0.9 request
        char req[sizeof(path) + 6];
        const int req_len = snprintf(req, sizeof(req), "GET %s\r\n", path);
        struct w_iov_sq r = sq_head_initializer(r);
        q_chunk_str(q, req, (uint32_t)req_len, &r);

        // open a new connection, or get an open one
        warn(INF, "%s retrieving %s", basename(argv[0]), url);
        get(q, &cc, dest, port, &r);
    }

    // collect the replies
    struct stream_entry * se = 0;
    sl_foreach (se, &sl, next) {
        // read HTTP/0.9 reply and dump it to stdout
        struct w_iov_sq i = sq_head_initializer(i);
        q_readall_str(se->s, &i);
        struct w_iov * v;
        sq_foreach (v, &i, next)
            printf("%.*s", v->len, v->buf);
        printf("\n");
        q_free(se->c, &i);
    }

    q_cleanup(q);
    free_cc(&cc);
    free_sl();
    warn(DBG, "%s exiting", basename(argv[0]));
    return 0;
}
