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

#pragma once

#include <ev.h>
#include <stdint.h>
#include <sys/socket.h>

#include "tommy.h"


// All open QUIC connections.
extern hash q_conns;


/// A QUIC connection.
struct q_conn {
    node conn_node;

    uint64_t id;   ///< Connection ID
    uint64_t out;  ///< The highest packet number sent on this connection
    uint64_t in;   ///< The highest packet number received on this connection
    uint8_t state; ///< State of the connection.
    uint8_t vers;  ///< QUIC version in use for this connection. (Index into
                   ///< @p vers[].)
    uint8_t flags;

    /// @cond
    uint8_t _unused; ///< @internal Padding.
    /// @endcond

    socklen_t peer_len;   ///< Length of @p peer.
    struct sockaddr peer; ///< Address of our peer.
    hash streams;
    struct w_sock * sock; ///< File descriptor (socket) for the connection.
    ev_io * rx_w;         ///< RX watcher.
};

#define CONN_CLSD 0
#define CONN_VERS_SENT 1
#define CONN_VERS_RECV 2
#define CONN_ESTB 3
#define CONN_FINW 99 // TODO: renumber

#define CONN_FLAG_CLNT 0x01


extern struct q_conn * get_conn(const uint64_t id);

extern struct q_conn * __attribute__((nonnull))
new_conn(const uint64_t id,
         const struct sockaddr * const peer,
         const socklen_t peer_len);
