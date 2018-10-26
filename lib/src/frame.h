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
#include <stdint.h>

struct pn_space;
struct q_conn;
struct q_stream;
struct w_iov;
struct cid;


#define FRAM_TYPE_PAD 0x00
#define FRAM_TYPE_RST_STRM 0x01
#define FRAM_TYPE_CONN_CLSE 0x02
#define FRAM_TYPE_APPL_CLSE 0x03
#define FRAM_TYPE_MAX_DATA 0x04
#define FRAM_TYPE_MAX_STRM_DATA 0x05
#define FRAM_TYPE_MAX_SID 0x06
#define FRAM_TYPE_PING 0x07
#define FRAM_TYPE_BLCK 0x08
#define FRAM_TYPE_STRM_BLCK 0x09
#define FRAM_TYPE_SID_BLCK 0x0a
#define FRAM_TYPE_NEW_CID 0x0b
#define FRAM_TYPE_STOP_SEND 0x0c
#define FRAM_TYPE_RTIR_CID 0x0d
#define FRAM_TYPE_PATH_CHLG 0x0e
#define FRAM_TYPE_PATH_RESP 0x0f
#define FRAM_TYPE_STRM 0x10 // we only encode this type in the frames bitstr_t
#define FRAM_TYPE_STRM_MAX 0x17
#define FRAM_TYPE_CRPT 0x18
#define FRAM_TYPE_NEW_TOKN 0x19
#define FRAM_TYPE_ACK 0x1a // we only encode this type in the frames bitstr_t
#define FRAM_TYPE_ACK_ECN 0x1b
#define NUM_FRAM_TYPES (FRAM_TYPE_ACK_ECN + 1)

#define F_STREAM_FIN 0x01
#define F_STREAM_LEN 0x02
#define F_STREAM_OFF 0x04

#ifndef NDEBUG
#define FRAM_IN BLD BLU
#define FRAM_OUT BLD GRN
#endif


#ifdef NDEBUG
#define log_stream_or_crypto_frame(rtx, v, in, kind)                           \
    do {                                                                       \
    } while (0)
#else
extern void __attribute__((nonnull))
log_stream_or_crypto_frame(const bool rtx,
                           const struct w_iov * const v,
                           const bool in,
                           const char * const kind);
#endif

extern uint64_t __attribute__((const))
shorten_ack_nr(const uint64_t ack, const uint64_t diff);

extern uint16_t __attribute__((nonnull))
dec_frames(struct q_conn * const c, struct w_iov ** vv);

extern uint16_t __attribute__((const)) max_frame_len(const uint8_t type);

extern uint16_t __attribute__((nonnull))
enc_padding_frame(struct w_iov * const v,
                  const uint16_t pos,
                  const uint16_t len);

extern uint16_t __attribute__((nonnull))
enc_ack_frame(struct q_conn * const c,
              struct pn_space * const pn,
              struct w_iov * const v,
              const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_stream_or_crypto_frame(struct q_stream * const s,
                           struct w_iov * const v,
                           const uint16_t pos,
                           const bool enc_strm);

extern uint16_t __attribute__((nonnull))
enc_close_frame(const struct q_conn * const c,
                struct w_iov * const v,
                const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_path_response_frame(struct q_conn * const c,
                        const struct w_iov * const v,
                        const uint16_t pos);

extern uint16_t __attribute__((nonnull))
dec_ack_frame(struct q_conn * const c,
              const struct w_iov * const v,
              const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_max_stream_data_frame(struct q_stream * const s,
                          struct w_iov * const v,
                          const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_max_data_frame(struct q_conn * const c,
                   struct w_iov * const v,
                   const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_max_stream_id_frame(struct q_conn * const c,
                        struct w_iov * const v,
                        const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_stream_blocked_frame(struct q_stream * const s,
                         const struct w_iov * const v,
                         const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_blocked_frame(struct q_conn * const c,
                  const struct w_iov * const v,
                  const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_stream_id_blocked_frame(struct q_conn * const c,
                            const struct w_iov * const v,
                            const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_path_challenge_frame(struct q_conn * const c,
                         const struct w_iov * const v,
                         const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_new_cid_frame(struct q_conn * const c,
                  const struct w_iov * const v,
                  const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_new_token_frame(struct q_conn * const c,
                    const struct w_iov * const v,
                    const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_retire_cid_frame(struct q_conn * const c,
                     const struct w_iov * const v,
                     const uint16_t pos,
                     struct cid * const cid);
