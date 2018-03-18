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

#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef __linux__
#include <sys/types.h>
#endif

#include <http_parser.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

struct q_conn;


static void __attribute__((noreturn)) usage(const char * const name,
                                            const char * const ifname,
                                            const uint16_t port,
                                            const char * const dir,
                                            const char * const cert,
                                            const char * const key)
{
    printf("%s [options]\n", name);
    printf("\t[-i interface]\tinterface to run over; default %s\n", ifname);
    printf("\t[-p port]\tdestination port; default %d\n", port);
    printf("\t[-d dir]\tserver root directory; default %s\n", dir);
    printf("\t[-c cert]\tTLS certificate; default %s\n", cert);
    printf("\t[-k key]\tTLS key; default %s\n", key);
#ifndef NDEBUG
    printf("\t[-v verbosity]\tverbosity level (0-%d, default %d)\n", DLEVEL,
           util_dlevel);
#endif
    exit(0);
}


struct cb_data {
    struct q_stream * s;
    struct q_conn * c;
    struct w_engine * w;
    int dir;
    uint32_t _dummy;
};


static int send_err(const struct cb_data * const d, const uint16_t code)
{
    const char * msg;
    switch (code) {
    case 403:
        msg = "403 Forbidden";
        break;
    case 404:
        msg = "404 Not Found";
        break;
    default:
        msg = "500 Internal Server Error";
    }

    q_write_str(d->w, d->c, d->s, msg, true);
    return 0;
}


static int serve_cb(http_parser * parser, const char * at, size_t len)
{
    (void)parser;
    const struct cb_data * const d = parser->data;
    warn(INF, "conn %" PRIx64 " str %u serving URL %.*s", q_cid(d->c),
         q_sid(d->s), (int)len, at);

    char path[MAXPATHLEN] = ".";
    strncpy(&path[*at == '/' ? 1 : 0], at, MIN(len, sizeof(path) - 1));

    // hacky way to prevent directory traversals
    if (strstr(path, ".."))
        return send_err(d, 403);

    // check if this is a "GET /n" request for random data
    if (strstr(path, "./") == path) {
        uint32_t n = (uint32_t)MIN(UINT32_MAX, strtoul(&path[2], 0, 10));
        if (n == 0)
            return send_err(d, 403);
        struct w_iov_sq out = sq_head_initializer(out);
        q_alloc(d->w, &out, n);
        // randomize data
        struct w_iov * v;
        char c = 'A';
        sq_foreach (v, &out, next) {
            memset(v->buf, c, v->len);
            c = (c == 'Z' ? 'A' : c + 1);
        }
        q_write(d->s, &out, true);
        return 0;
    }

    struct stat info;
    if (fstatat(d->dir, path, &info, 0) == -1)
        return send_err(d, 404);

    // if this a directory, look up its index
    if (info.st_mode & S_IFDIR) {
        strncat(path, "/index.html", sizeof(path) - len - 1);
        if (fstatat(d->dir, path, &info, 0) == -1)
            return send_err(d, 404);
    }

    if ((info.st_mode & S_IFREG) == 0 || (info.st_mode & S_IFLNK) == 0)
        return send_err(d, 403);

    if (info.st_size >= UINT32_MAX)
        return send_err(d, 500);

    const int f = openat(d->dir, path, O_RDONLY | O_CLOEXEC);
    ensure(f != -1, "could not open %s", path);

    q_write_file(d->w, d->c, d->s, f, (uint32_t)info.st_size, true);

    return 0;
}


#define MAXPORTS 16

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
    char dir[MAXPATHLEN] = "/Users/lars/Sites/lars/output";
    char cert[MAXPATHLEN] =
        "/etc/letsencrypt/live/slate.eggert.org/fullchain.pem";
    char key[MAXPATHLEN] = "/etc/letsencrypt/live/slate.eggert.org/privkey.pem";
    uint16_t port[MAXPORTS] = {4433, 4434};
    size_t num_ports = 0;
    int ch;

    while ((ch = getopt(argc, argv, "hi:p:d:v:c:k:")) != -1) {
        switch (ch) {
        case 'i':
            strncpy(ifname, optarg, sizeof(ifname) - 1);
            break;
        case 'd':
            strncpy(dir, optarg, sizeof(dir) - 1);
            break;
        case 'c':
            strncpy(cert, optarg, sizeof(cert) - 1);
            break;
        case 'k':
            strncpy(key, optarg, sizeof(key) - 1);
            break;
        case 'p':
            port[num_ports++] =
                (uint16_t)MIN(UINT16_MAX, strtoul(optarg, 0, 10));
            ensure(num_ports < MAXPORTS, "can only listen on at most %u ports",
                   MAXPORTS);
            break;
        case 'v':
#ifndef NDEBUG
            util_dlevel = (short)MIN(DLEVEL, strtoul(optarg, 0, 10));
#endif
            break;
        case 'h':
        case '?':
        default:
            usage(basename(argv[0]), ifname, port[0], dir, cert, key);
        }
    }

    if (num_ports == 0)
        // if no -p args were given, we listen on two ports by default
        num_ports = 2;

    const int dir_fd = open(dir, O_RDONLY | O_CLOEXEC);
    ensure(dir_fd != -1, "%s does not exist", dir);

    struct w_engine * const w = q_init(ifname, cert, key, 0);
    struct q_conn * conn[MAXPORTS];
    for (size_t i = 0; i < num_ports; i++) {
        conn[i] = q_bind(w, port[i]);
        warn(DBG, "%s waiting on %s port %d", basename(argv[0]), ifname,
             port[i]);
    }

    bool first = true;
    while (1) {
        struct q_conn * const c = q_accept(w, first ? 0 : 10);
        first = false;
        if (c == 0)
            break;

        http_parser_settings settings = {.on_url = serve_cb};
        struct cb_data d = {.c = c, .w = w, .dir = dir_fd};
        http_parser parser = {.data = &d};
        http_parser_init(&parser, HTTP_REQUEST);

        struct w_iov_sq i = sq_head_initializer(i);
        struct q_stream * s = q_read(c, &i);
        if (s == 0)
            goto next;
        d.s = s;

        struct w_iov * v = 0;
        sq_foreach (v, &i, next) {
            const size_t parsed =
                http_parser_execute(&parser, &settings, (char *)v->buf, v->len);
            if (parsed != v->len)
                warn(ERR, "HTTP parser error: %.*s", v->len - parsed,
                     &v->buf[parsed]);
            if (q_is_str_closed(s))
                break;
        }

        q_free(c, &i);
    next:
        q_close(c);
    }

    q_cleanup(w);
    warn(DBG, "%s exiting", basename(argv[0]));
    return 0;
}
