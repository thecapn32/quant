#pragma once

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

struct q_conn;

void q_init(struct ev_loop * restrict const loop, const long timeout);

uint64_t q_connect(const int s,
                   const struct sockaddr * restrict const peer,
                   const socklen_t peer_len);

void q_serve(const int s);

void q_write(const uint64_t cid,
             const uint32_t sid,
             const void * restrict const buf,
             const size_t len);

uint32_t q_rsv_stream(const uint64_t cid);

