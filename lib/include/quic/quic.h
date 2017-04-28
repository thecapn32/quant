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

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

struct w_iov_stailq;


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

extern void __attribute__((nonnull)) q_write(const uint64_t cid,
                                             const uint32_t sid,
                                             struct w_iov_stailq * const q);

extern size_t __attribute__((nonnull)) q_read(const uint64_t cid,
                                              uint32_t * const sid,
                                              void * const buf,
                                              const size_t len);

extern uint32_t q_rsv_stream(const uint64_t cid);

extern void __attribute__((nonnull))
q_alloc(void * const w, struct w_iov_stailq * const q, const uint32_t len);

extern void q_free(void * const w, struct w_iov_stailq * const q);
