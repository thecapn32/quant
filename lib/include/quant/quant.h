// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2017, NetApp, Inc.
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

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <quant/config.h> // IWYU pragma: export

struct w_iov_sq;
struct q_stream;


extern void * __attribute__((nonnull)) q_init(const char * const ifname);

extern void __attribute__((nonnull)) q_cleanup(void * const q);

extern struct q_conn * __attribute__((nonnull))
q_connect(void * const q,
          const struct sockaddr_in * const peer,
          const char * const peer_name);

extern void __attribute__((nonnull)) q_close(struct q_conn * const c);

extern struct q_conn * __attribute__((nonnull))
q_bind(void * const q, const uint16_t port);

extern struct q_conn * __attribute__((nonnull))
q_accept(struct q_conn * const c);

extern void __attribute__((nonnull))
q_write(struct q_stream * const s, struct w_iov_sq * const q);

extern struct q_stream * __attribute__((nonnull))
q_read(struct q_conn * const c, struct w_iov_sq * const q);

extern struct q_stream * __attribute__((nonnull))
q_rsv_stream(struct q_conn * const c);

extern void __attribute__((nonnull)) q_close_stream(struct q_stream * const s);

extern void __attribute__((nonnull))
q_alloc(void * const w, struct w_iov_sq * const q, const uint32_t len);

extern void __attribute__((nonnull))
q_free(void * const w, struct w_iov_sq * const q);

extern uint64_t __attribute__((nonnull)) q_cid(const struct q_conn * const c);

extern uint32_t __attribute__((nonnull)) q_sid(const struct q_stream * const s);

extern void __attribute__((nonnull))
q_write_str(void * const q, struct q_stream * const s, const char * const str);

extern void __attribute__((nonnull)) q_write_file(void * const q,
                                                  struct q_stream * const s,
                                                  const int f,
                                                  const uint32_t len);

extern bool __attribute__((nonnull)) q_is_str_closed(struct q_stream * const s);

extern void __attribute__((nonnull))
q_readall_str(struct q_stream * const s, struct w_iov_sq * const q);
