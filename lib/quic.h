#pragma once

#include <ev.h>
#include <sys/queue.h>

#include "tommy.h"


/// The versions of QUIC supported by this implementation
extern const char * const q_vers[];

/// Macro to interpret a @p q_vers[] string as a @p uint32_t.
#define VERS_UINT32_T(v) (*(const uint32_t *)(const void *)(v))


/// A QUIC connection.
struct q_conn {
    uint64_t id;    ///< Connection ID
    uint64_t out;   ///< The highest packet number sent on this connection
    uint64_t in;    ///< The highest packet number received on this connection
    int      s;     ///< The socket used for this connection
    uint8_t  state; ///< State of the connection.
    uint8_t  vers;  ///< QUIC version in use for this connection. (Index into
                    ///@p q_vers[].)
    uint8_t _unused[2];
    node    node;
};

#define CLOSED 0
#define VERS_SENT 1
#define VERS_RECV 2


void q_init(void);
void q_connect(EV_P_ const int s);
void q_serve(EV_P_ const int s);
