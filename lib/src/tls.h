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

#include <stddef.h>
#include <stdint.h>

#include <picotls.h>

struct q_conn;
struct q_stream;
struct w_iov;


#define AEAD_LEN 16


struct tls {
    ptls_t * t;
    ptls_aead_context_t * dec_hshk;
    ptls_aead_context_t * enc_hshk;
    ptls_aead_context_t * dec_0rtt;
    ptls_aead_context_t * enc_0rtt;
    ptls_aead_context_t * dec_1rtt;
    ptls_aead_context_t * enc_1rtt;

    uint8_t tp_buf[96];
    ptls_raw_extension_t tp_ext[2];
    ptls_handshake_properties_t tls_hshake_prop;
    size_t max_early_data;
};


/// TLS context.
extern ptls_context_t tls_ctx;

extern void __attribute__((nonnull)) init_hshk_prot(struct q_conn * const c);

extern void __attribute__((nonnull)) init_0rtt_prot(struct q_conn * const c);

extern void __attribute__((nonnull)) init_tls(struct q_conn * const c);

extern void __attribute__((nonnull)) init_tp(struct q_conn * const c);

extern void __attribute__((nonnull)) free_tls(struct q_conn * const c);

extern uint32_t __attribute__((nonnull(1)))
tls_io(struct q_stream * const s, struct w_iov * const iv);

extern void init_tls_ctx(const char * const cert,
                         const char * const key,
                         const char * const ticket_store);

extern void cleanup_tls_ctx(void);

extern uint16_t __attribute__((nonnull)) dec_aead(struct q_conn * const c,
                                                  const struct w_iov * v,
                                                  const uint16_t hdr_len);

extern uint16_t __attribute__((nonnull)) enc_aead(struct q_conn * const c,
                                                  const struct w_iov * v,
                                                  const struct w_iov * x,
                                                  const uint16_t hdr_len);
