#pragma once

#include <ev.h>
#include <sys/socket.h>

#include "tommy.h"


/// Represent QUIC versions in a way that lets them be used as integers or
/// printed as strings. These strings are not null-terminated, and therefore
/// need to be printed as @p %.4s with @p printf() or similar.
union q_vers {
    uint32_t as_int; ///< QUIC version in network byte-order.
    char as_str[4];  ///< QUIC version as non-null-terminated string.
};


/// The versions of QUIC supported by this implementation
extern const union q_vers vers[];

/// The length of @p vers[] in bytes. Divide by @p sizeof(vers[0]) for number of
/// elements.
extern const size_t vers_len;


/// A QUIC connection.
struct q_conn {
    uint64_t id;  ///< Connection ID
    uint64_t out; ///< The highest packet number sent on this connection
    uint64_t in;  ///< The highest packet number received on this connection
    node node;
    uint8_t flags;
    uint8_t state; ///< State of the connection.
    uint8_t vers;  ///< QUIC version in use for this connection. (Index into
                   ///@p q_vers[].)
    uint8_t _unused;
    int fd;
    socklen_t plen;
    struct sockaddr peer;
    uint8_t _unused2[4];
};

#define CLOSED 0
#define VERS_SENT 1
#define VERS_RECV 2
#define ESTABLISHED 3


void q_init(struct ev_loop * restrict const reloop);

void q_connect(struct ev_loop * restrict const loop,
               const int s,
               const struct sockaddr * restrict const peer,
               const socklen_t plen);

void q_serve(struct ev_loop * restrict const loop, const int s);
