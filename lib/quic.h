#pragma once

//!< The versions of QUIC supported by this implementation
extern const char * const q_vers[];


struct q_conn {
    uint64_t id;
    int      socket;
};

void q_connect(const int s);
void q_serve(const int s);
