#pragma once


struct q_conn;

extern void * q_init(const char * const ifname, const long timeout);

extern void q_cleanup(void * const q);

extern uint64_t q_connect(void * const q,
                          const struct sockaddr * const peer,
                          const socklen_t peer_len);

extern void q_close(const uint64_t cid);

extern uint64_t q_bind(void * const q, const uint16_t port);

extern void q_write(const uint64_t cid,
                    const uint32_t sid,
                    const void * const buf,
                    const size_t len);

extern size_t q_read(const uint64_t cid,
                     uint32_t * const sid,
                     void * const buf,
                     const size_t len);

extern uint32_t q_rsv_stream(const uint64_t cid);
