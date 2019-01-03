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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <picotls.h>

struct q_conn;
struct w_iov;
struct q_stream;
struct q_conf;


#define AEAD_LEN 16
#define MAX_HASH_LEN 32 // SHA256


struct cipher_ctx {
    ptls_aead_context_t * aead;
    ptls_cipher_context_t * pne;
};


typedef enum { ep_init = 0, ep_0rtt = 1, ep_hshk = 2, ep_data = 3 } epoch_t;


struct tls {
    ptls_t * t;
    uint8_t secret[2][PTLS_MAX_DIGEST_SIZE];
    ptls_raw_extension_t tp_ext[2];
    ptls_handshake_properties_t tls_hshk_prop;
    size_t max_early_data;
    epoch_t epoch_out; // TODO: remove
    uint8_t tp_buf[196];
};


/// TLS context.
extern ptls_context_t tls_ctx;

extern void __attribute__((nonnull)) init_prot(struct q_conn * const c);

extern void __attribute__((nonnull)) init_tls(struct q_conn * const c);

extern void __attribute__((nonnull)) init_tp(struct q_conn * const c);

extern void __attribute__((nonnull)) free_tls(struct q_conn * const c);

extern int __attribute__((nonnull(1)))
tls_io(struct q_stream * const s, struct w_iov * const iv);

extern void init_tls_ctx(const struct q_conf * const conf);

extern void free_tls_ctx(void);

extern uint16_t __attribute__((nonnull))
dec_aead(struct q_conn * const c,
         const struct w_iov * const xv,
         const struct w_iov * const v,
         const uint16_t len,
         const struct cipher_ctx * const ctx);

extern uint16_t __attribute__((nonnull))
enc_aead(struct q_conn * const c,
         const struct w_iov * const v,
         const struct w_iov * const xv);

extern void __attribute__((nonnull)) make_rtry_tok(struct q_conn * const c);

extern bool __attribute__((nonnull)) verify_rtry_tok(struct q_conn * const c,
                                                     const uint8_t * const tok,
                                                     const uint16_t tok_len);

extern void __attribute__((nonnull))
flip_keys(struct q_conn * const c, const bool out);

extern void __attribute__((nonnull))
maybe_flip_keys(struct q_conn * const c, const bool out);
