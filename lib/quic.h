#pragma once

#include <netdb.h>
#include <stdint.h>


struct q_conn;
struct w_iov;

extern void * __attribute__((nonnull))
q_init(const char * const ifname, const long timeout);

extern void __attribute__((nonnull)) q_cleanup(void * const q);

extern uint64_t __attribute__((nonnull))
q_connect(void * const q,
          const struct sockaddr * const peer,
          const socklen_t peer_len);

extern void q_close(const uint64_t cid);

extern uint64_t __attribute__((nonnull))
q_bind(void * const q, const uint16_t port);

// extern void __attribute__((nonnull)) q_write(const uint64_t cid,
//                                              const uint32_t sid,
//                                              const void * const buf,
//                                              const size_t len);

extern void __attribute__((nonnull))
q_write(const uint64_t cid, const uint32_t sid, struct w_iov * const buf);

extern size_t __attribute__((nonnull)) q_read(const uint64_t cid,
                                              uint32_t * const sid,
                                              void * const buf,
                                              const size_t len);

extern uint32_t q_rsv_stream(const uint64_t cid);

extern struct w_iov * __attribute__((nonnull))
q_alloc(void * const w, const uint32_t len);

extern void q_free(void * const w, struct w_iov * v);
