#pragma once

#include <sys/queue.h>

/// The versions of QUIC supported by this implementation
extern const char * const q_vers[];

/// A QUIC connection.
struct q_conn {
    uint64_t id;   ///< Connection ID
    uint64_t nr;   ///< The highest packet number sent on this connection
    uint64_t r_nr; ///< The highest packet number received on this connection
    int      sock; ///< The socket used for this connection
    uint32_t _unused;
    SLIST_ENTRY(q_conn) next;
};

void q_connect(const int s);
void q_serve(const int s);
