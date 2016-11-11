#pragma once

#include <pthread.h>

#include "conn.h"
#include "quic.h"
#include "stream.h"


extern pthread_mutex_t lock;
extern pthread_cond_t read_cv;


/// Represent QUIC tags in a way that lets them be used as integers or
/// printed as strings. These strings are not null-terminated, and therefore
/// need to be printed as @p %.4s with @p printf() or similar.
typedef union {
    uint32_t as_int; ///< QUIC tag in network byte-order.
    char as_str[4];  ///< QUIC tag as non-null-terminated string.
} q_tag;


/// The versions of QUIC supported by this implementation
extern const q_tag vers[];

/// The length of @p vers[] in bytes. Divide by @p sizeof(vers[0]) for number of
/// elements.
extern const size_t vers_len;
