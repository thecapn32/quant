// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
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

#include "bitset.h"

struct pn_space;
struct q_conn;
struct q_stream;
struct w_iov;
struct cid;


#define FRM_PAD 0x00 ///< PADDING
#define FRM_PNG 0x01 ///< PING
#define FRM_ACK 0x02 ///< ACK (only type encoded in the frames bitstr_t)
#define FRM_ACE 0x03 ///< ACK w/ECN
#define FRM_RST 0x04 ///< RESET_STREAM
#define FRM_STP 0x05 ///< STOP_SENDING
#define FRM_CRY 0x06 ///< CRYPTO
#define FRM_TOK 0x07 ///< NEW_TOKEN
#define FRM_STR 0x08 ///< STREAM (only type encoded in the frames bitstr_t)
#define FRM_STR_MAX 0x0f
#define FRM_MCD 0x10 ///< MAX_DATA (connection)
#define FRM_MSD 0x11 ///< MAX_STREAM_DATA
#define FRM_MSB 0x12 ///< MAX_STREAMS (bidirectional)
#define FRM_MSU 0x13 ///< MAX_STREAMS (unidirectional)
#define FRM_CDB 0x14 ///< (connection) DATA_BLOCKED
#define FRM_SDB 0x15 ///< STREAM_DATA_BLOCKED
#define FRM_SBB 0x16 ///< STREAMS_BLOCKED (bidirectional)
#define FRM_SBU 0x17 ///< STREAMS_BLOCKED (unidirectional)
#define FRM_CID 0x18 ///< NEW_CONNECTION_ID
#define FRM_RTR 0x19 ///< RETIRE_CONNECTION_ID
#define FRM_PCL 0x1a ///< PATH_CHALLENGE
#define FRM_PRP 0x1b ///< PATH_RESPONSE
#define FRM_CLQ 0x1c ///< CONNECTION_CLOSE (QUIC layer)
#define FRM_CLA 0x1d ///< CONNECTION_CLOSE (application)

#define NUM_FRAM_TYPES (FRM_CLA + 1)

bitset_define(frames, NUM_FRAM_TYPES);

#define F_STREAM_FIN 0x01
#define F_STREAM_LEN 0x02
#define F_STREAM_OFF 0x04

#define DEF_ACK_DEL_EXP 3

#ifndef NDEBUG
#define FRAM_IN BLD BLU
#define FRAM_OUT BLD GRN
#endif

#define has_frame(m, ft) bit_isset(NUM_FRAM_TYPES, (ft), &(m)->frames)

#ifdef NDEBUG
#define log_stream_or_crypto_frame(...)                                        \
    do {                                                                       \
    } while (0)
#else
extern void __attribute__((nonnull(2)))
log_stream_or_crypto_frame(const bool is_rtx,
                           const struct w_iov * const v,
                           const int64_t sid,
                           const bool in,
                           const char * const kind);
#endif

struct pkt_meta;

extern uint16_t __attribute__((nonnull))
dec_frames(struct q_conn * const c, struct w_iov ** vv, struct pkt_meta ** mm);

extern uint16_t __attribute__((const)) max_frame_len(const uint8_t type);

extern uint16_t __attribute__((nonnull))
enc_padding_frame(struct w_iov * const v,
                  struct pkt_meta * const m,
                  const uint16_t pos,
                  const uint16_t len);

extern uint16_t __attribute__((nonnull))
enc_ack_frame(struct pn_space * const pn,
              struct w_iov * const v,
              struct pkt_meta * const m,
              const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_stream_or_crypto_frame(struct q_stream * const s,
                           struct w_iov * const v,
                           struct pkt_meta * const m,
                           const uint16_t pos,
                           const bool enc_strm);

extern uint16_t __attribute__((nonnull))
enc_close_frame(struct w_iov * const v,
                struct pkt_meta * const m,
                const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_path_response_frame(const struct w_iov * const v,
                        struct pkt_meta * const m,
                        const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_max_stream_data_frame(struct q_stream * const s,
                          struct w_iov * const v,
                          struct pkt_meta * const m,
                          const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_max_data_frame(struct w_iov * const v,
                   struct pkt_meta * const m,
                   const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_max_streams_frame(struct w_iov * const v,
                      struct pkt_meta * const m,
                      const uint16_t pos,
                      const bool bidi);

extern uint16_t __attribute__((nonnull))
enc_stream_data_blocked_frame(struct q_stream * const s,
                              const struct w_iov * const v,
                              struct pkt_meta * const m,
                              const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_data_blocked_frame(const struct w_iov * const v,
                       struct pkt_meta * const m,
                       const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_streams_blocked_frame(const struct w_iov * const v,
                          struct pkt_meta * const m,
                          const uint16_t pos,
                          const bool bidi);

extern uint16_t __attribute__((nonnull))
enc_path_challenge_frame(const struct w_iov * const v,
                         struct pkt_meta * const m,
                         const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_new_cid_frame(const struct w_iov * const v,
                  struct pkt_meta * const m,
                  const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_new_token_frame(const struct w_iov * const v,
                    struct pkt_meta * const m,
                    const uint16_t pos);

extern uint16_t __attribute__((nonnull))
enc_retire_cid_frame(const struct w_iov * const v,
                     struct pkt_meta * const m,
                     const uint16_t pos,
                     struct cid * const dcid);

extern uint16_t __attribute__((nonnull))
enc_ping_frame(const struct w_iov * const v,
               struct pkt_meta * const m,
               const uint16_t pos);

extern uint16_t __attribute__((nonnull))
dec_ack_frame(struct q_conn * const c,
              const struct w_iov * const v,
              const struct pkt_meta * const m,
              const uint16_t pos);


static inline bool __attribute__((nonnull))
is_ack_eliciting(const struct frames * const f)
{
    static const struct frames ack_or_pad =
        bitset_t_initializer(1 << FRM_ACK | 1 << FRM_PAD);
    struct frames not_ack_or_pad = *f;
    bit_nand(NUM_FRAM_TYPES, &not_ack_or_pad, &ack_or_pad);
    return !bit_empty(NUM_FRAM_TYPES, &not_ack_or_pad);
}
