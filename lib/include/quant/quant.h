// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2018, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <quant/config.h> // IWYU pragma: export

struct w_iov_sq;
struct q_stream;

#define IDLE_TIMEOUT_MAX 600 // 10 minutes


extern struct w_engine * __attribute__((nonnull(1)))
q_init(const char * const ifname,
       const char * const cert,
       const char * const key,
       const char * const cache,
       const char * const tls_log,
       const bool verify_certs);

extern void __attribute__((nonnull)) q_cleanup(struct w_engine * const w);

extern struct q_conn * __attribute__((nonnull(1, 2, 3)))
q_connect(struct w_engine * const w,
          const struct sockaddr_in * const peer,
          const char * const peer_name,
          struct w_iov_sq * const early_data,
          struct q_stream ** const early_data_stream,
          const bool fin,
          const uint64_t idle_timeout);

extern void __attribute__((nonnull)) q_close(struct q_conn * const c);

extern struct q_conn * __attribute__((nonnull))
q_bind(struct w_engine * const w, const uint16_t port);

extern struct q_conn * __attribute__((nonnull))
q_accept(struct w_engine * const w, const uint64_t timeout);

extern void __attribute__((nonnull))
q_write(struct q_stream * const s, struct w_iov_sq * const q, const bool fin);

extern struct q_stream * __attribute__((nonnull))
q_read(struct q_conn * const c, struct w_iov_sq * const q, const bool block);

extern struct q_stream * __attribute__((nonnull))
q_rsv_stream(struct q_conn * const c);

extern void __attribute__((nonnull)) q_close_stream(struct q_stream * const s);

extern void __attribute__((nonnull)) q_alloc(struct w_engine * const w,
                                             struct w_iov_sq * const q,
                                             const uint32_t len);

extern void __attribute__((nonnull)) q_free(struct w_iov_sq * const q);

extern char * __attribute__((nonnull)) q_cid(const struct q_conn * const c);

extern uint64_t __attribute__((nonnull)) q_sid(const struct q_stream * const s);

extern void __attribute__((nonnull)) q_chunk_str(struct w_engine * const w,
                                                 const char * const str,
                                                 const uint32_t len,
                                                 struct w_iov_sq * o);

extern void __attribute__((nonnull)) q_write_str(struct w_engine * const w,
                                                 struct q_stream * const s,
                                                 const char * const str,
                                                 const bool fin);

extern void __attribute__((nonnull)) q_write_file(struct w_engine * const w,
                                                  struct q_stream * const s,
                                                  const int f,
                                                  const uint32_t len,
                                                  const bool fin);

extern bool __attribute__((nonnull)) q_is_str_closed(struct q_stream * const s);

extern void __attribute__((nonnull))
q_readall_str(struct q_stream * const s, struct w_iov_sq * const q);

#ifdef __cplusplus
}
#endif
