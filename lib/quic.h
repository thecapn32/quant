#pragma once


struct q_conn;

void q_init(const long timeout);

void q_cleanup(void);

uint64_t q_connect(const int s,
                   const struct sockaddr * restrict const peer,
                   const socklen_t peer_len);

void q_close(const uint64_t cid);

uint64_t q_accept(const int s);

void q_write(const uint64_t cid,
             const uint32_t sid,
             const void * restrict const buf,
             const size_t len);

size_t q_read(const uint64_t cid,
              uint32_t * restrict const sid,
              void * restrict const buf,
              const size_t len);

uint32_t q_rsv_stream(const uint64_t cid);
