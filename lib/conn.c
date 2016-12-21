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

#include <inttypes.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <warpcore.h>

#include "conn.h"
#include "tommy.h"


// All open QUIC connections.
hash q_conns;


static int __attribute__((nonnull))
cmp_q_conn(const void * const arg, const void * const obj)
{
    return *(const uint64_t *)arg != ((const struct q_conn *)obj)->id;
}


struct q_conn * get_conn(const uint64_t id)
{
    return hash_search(&q_conns, cmp_q_conn, &id, (uint32_t)id);
}


struct q_conn * __attribute__((nonnull))
new_conn(const uint64_t id,
         const struct sockaddr * const peer,
         const socklen_t peer_len)
{
    ensure(get_conn(id) == 0, "conn %" PRIu64 " already exists", id);

    struct q_conn * const c = calloc(1, sizeof(*c));
    ensure(c, "could not calloc");
    // c->rx_w will be allocated and initialized when a w_sock exists
    c->id = id;
    c->out = 1;
    hash_init(&c->streams);
    hash_insert(&q_conns, &c->conn_node, c, (uint32_t)c->id);

    char host[NI_MAXHOST] = "";
    char port[NI_MAXSERV] = "";
    getnameinfo((const struct sockaddr *)peer, peer_len, host, sizeof(host),
                port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    c->peer = *peer;
    c->peer_len = peer_len;
    warn(info, "created new conn %" PRIu64 " with peer %s:%s", c->id, host,
         port);

    return c;
}
