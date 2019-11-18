// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
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

#ifdef PARTICLE
#include <netdb.h>
#define IF_NAME "wl3"
#elif defined(RIOT_VERSION)
#include "net/sock/dns.h"
#define IF_NAME ""
#endif


#include <stdio.h>
#include <unistd.h>

#include <quant/quant.h>

#include "minimal_transaction.h"


#define to_in4(x) ((struct sockaddr_in *)&(x))
#define to_in6(x) ((struct sockaddr_in6 *)&(x))
#define to_in(x) ((struct sockaddr *)&(x))


int resolve(const char * const name, struct sockaddr * const peer)
{
#ifdef RIOT_VERSION
    // FIXME this only works locally
    sock_dns_server.family = AF_INET6;
    memcpy(sock_dns_server.addr.ipv6,
           &(uint8_t[]){0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
                        0x62, 0x31, 0xff, 0xfe, 0x00, 0xbd, 0x77},
           IP6_LEN);
    sock_dns_server.port = SOCK_DNS_PORT;
#endif

    int ret = 1;
    while (ret) {

#ifdef PARTICLE
        const struct addrinfo hints = {.ai_family = AF_INET}; // no IPv6 support
        struct addrinfo * res;
        ret = getaddrinfo(name, 0, &hints, &res);
        if (ret == 0)
            memcpy(peer, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);

#elif defined(RIOT_VERSION)

        ret = sock_dns_query(name, &to_in6(*peer)->sin6_addr, peer->sa_family);

        // FIXME: this will fail, so just override it for the moment
        peer->sa_family = AF_INET6;
        memcpy(&to_in6(*peer)->sin6_addr,
               &(uint8_t[]){0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x48, 0x56, 0x94, 0xc7, 0x95, 0x16, 0x98},
               IP6_LEN);
        ret = 0;

#else
#error unimplemented
#endif

        if (ret) {
            warn(WRN, "unable to resolve %s, retrying (%d)", name, ret);
            w_nanosleep(1 * NS_PER_S);
        }
    }
    return ret;
}


void warpcore_transaction(const char * const msg, const size_t msg_len)
{
    struct w_engine * const w = w_init(IF_NAME, 0, 50);
    struct w_sock * const s = w_bind(w, 0, 0, 0);
    struct sockaddr_storage peer = {.ss_family = AF_UNSPEC};
    resolve("quant.eggert.org", to_in(peer));
    to_in6(peer)->sin6_port = bswap16(4433);

    struct w_iov_sq o = w_iov_sq_initializer(o);
    w_alloc_cnt(w, peer.ss_family, &o, 1, 0, 0);
    w_connect(s, to_in(peer));

    struct w_iov * const v = sq_first(&o);
    memcpy(v->buf, msg, msg_len);
    v->len = msg_len;

    w_tx(s, &o);
    while (w_tx_pending(&o))
        w_nic_tx(w);
    warn(DBG, "pkt tx: %s", v->buf);

    struct w_iov_sq i = w_iov_sq_initializer(i);
    if (w_nic_rx(w, 1 * MS_PER_S)) {
        w_rx(s, &i);
        warn(DBG, "pkt rx");
    }

    w_free(&o);
    w_free(&i);
    w_cleanup(w);
}


void quic_transaction(const char * const req, const size_t req_len)
{
    static const struct q_conf qc = {0, 0, 0, 0, 0, 0, 20, false};
    struct w_engine * const w = q_init(IF_NAME, &qc);

    static const char peername[] = "quant.eggert.org";
    struct sockaddr_storage peer = {.ss_family = AF_UNSPEC};
    resolve(peername, to_in(peer));
    to_in6(peer)->sin6_port = bswap16(4433);

    struct w_iov_sq o = w_iov_sq_initializer(o);
    q_alloc(w, &o, peer.ss_family, req_len - 1);
    struct w_iov * const v = sq_first(&o);
    memcpy(v->buf, req, req_len - 1);

    struct q_stream * s;
    static const struct q_conn_conf qcc = {
        0, 0, 0, 0, 0, 0, 0, 0, 0xff000000 + DRAFT_VERSION};
    struct q_conn * const c = q_connect(w, to_in(peer), peername, &o, &s, true,
                                        "hq-" DRAFT_VERSION_STRING, &qcc);

    if (c) {
        struct w_iov_sq i = w_iov_sq_initializer(i);
        q_read_stream(s, &i, true);
        warn(NTE, "retrieved %" PRIu32 " bytes", w_iov_sq_len(&i));
    } else
        warn(WRN, "could not retrieve %s", req);

    q_cleanup(w);
}
