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
#endif

#include <unistd.h>

#include "minimal_transaction.h"
#include "quant/quant.h"


struct addrinfo * resolve(const char * const name, const char * const port)
{
    struct addrinfo hints;
    hints.ai_family = PF_INET;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo * peer;
    ensure(getaddrinfo(name, port, &hints, &peer) == 0, "");
    return peer;
}


void warpcore_transaction(const char * const msg, const size_t msg_len)
{
    struct w_engine * const w = w_init("wl3", 0, 50);
    struct w_sock * const s = w_bind(w, 0, 0);
    struct addrinfo * const peer = resolve("quant.eggert.org", "4433");
    struct w_iov_sq o = w_iov_sq_initializer(o);

    w_alloc_cnt(w, &o, 1, 0, 0);
    w_connect(s, peer->ai_addr);
    freeaddrinfo(peer);

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


void quic_transaction()
{
    static const struct q_conf qc = {0, 0, 0, 0, 0, 0, 20, false};
    struct w_engine * const w = q_init("wl3", &qc);

    static const char peername[] = "10.100.25.62";
    struct addrinfo * peer = 0;
    do {
        peer = resolve(peername, "4433");
        if (peer == 0) {
            warn(WRN, "unable to resolve %s, retrying", peername);
            w_nanosleep(1 * NS_PER_S);
        }
    } while (peer == 0);

    static const char req[] = "GET /5000\r\n";
    struct w_iov_sq o = w_iov_sq_initializer(o);
    q_alloc(w, &o, sizeof(req) - 1);
    struct w_iov * const v = sq_first(&o);
    memcpy(v->buf, req, sizeof(req) - 1);

    struct q_stream * s;
    static const struct q_conn_conf qcc = {0, 0, 0, 0,
                                           0, 0, 0, 0xff000000 + DRAFT_VERSION};
    struct q_conn * const c = q_connect(w, peer->ai_addr, peername, &o, &s,
                                        true, "hq-" DRAFT_VERSION_STRING, &qcc);
    freeaddrinfo(peer);

    if (c) {
        struct w_iov_sq i = w_iov_sq_initializer(i);
        q_read_stream(s, &i, true);
        warn(NTE, "retrieved %" PRIu32 " bytes", w_iov_sq_len(&i));
    } else
        warn(WRN, "could not retrieve %s", req);

    q_cleanup(w);
}
