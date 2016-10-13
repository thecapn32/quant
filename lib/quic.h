#pragma once

#include <ev.h>
#include <sys/queue.h>

#include "tommy.h"

/// Represent QUIC versions in a way that lets them be used as integers or
/// printed as strings.
union q_vers {
    uint32_t as_int;
    char as_str[5];
};

/// The versions of QUIC supported by this implementation
extern const union q_vers vers[];


/// A QUIC connection.
struct q_conn {
    uint64_t id;   ///< Connection ID
    uint64_t out;  ///< The highest packet number sent on this connection
    uint64_t in;   ///< The highest packet number received on this connection
    int s;         ///< The socket used for this connection
    uint8_t state; ///< State of the connection.
    uint8_t vers;  ///< QUIC version in use for this connection. (Index into
                   ///@p q_vers[].)
    uint8_t _unused[2];
    node node;
};

#define CLOSED 0
#define VERS_SENT 1
#define VERS_RECV 2
#define ESTABLISHED 3


void q_init(EV_P);
void q_connect(EV_P_ const int s);
void q_serve(EV_P_ const int s);
