#pragma once

#include <ev.h>
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
    uint8_t _unused; ///< Unused.
    int fd;          ///< File descriptor (socket) for the connection.
    hash streams;
    struct sockaddr peer; ///< Address of our peer.
    socklen_t peer_len;   ///< Length of @p peer.
    uint8_t _unused2[4];  ///< Unused.
};

#define CONN_CLSD 0
#define CONN_VERS_SENT 1
#define CONN_VERS_RECV 2
#define CONN_ESTB 3
#define CONN_FINW 99 // TODO: renumber

#define CONN_FLAG_CLNT 0x01


struct q_conn * get_conn(const uint64_t id);

struct q_conn * new_conn(const uint64_t id,
                         const struct sockaddr * restrict const peer,
                         const socklen_t peer_len,
                         const int fd);
