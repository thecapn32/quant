#pragma once

#include <ev.h>
#include <sys/queue.h>

#include "tommy.h"

/// The versions of QUIC supported by this implementation
extern const char * const q_vers[];

/// A QUIC connection.
struct q_conn {
    uint64_t id;   ///< Connection ID
    uint64_t nr;   ///< The highest packet number sent on this connection
    uint64_t r_nr; ///< The highest packet number received on this connection
    int      sock; ///< The socket used for this connection
    uint8_t  vers_idx; ///< QUIC version in use for this connection. (Index into
                       ///@p q_vers[].)
    uint8_t _unused[3];
    node node;
};


void q_init(void);
void q_connect(EV_P_ const int s);
void q_serve(EV_P_ const int s);
