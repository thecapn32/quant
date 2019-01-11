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

#include "conn.h"
#include "pn.h"
#include "quic.h"


#define MAX_PKT_LEN 1252
#define MIN_INI_LEN 1200

#define HEAD_FORM 0x80      ///< header form (1 = long, 0 = short)
#define HEAD_FIXD 0x40      ///< fixed bit (= 1)
#define HEAD_PNRL_MASK 0x03 ///< packet number length mask

#define LH (HEAD_FORM | HEAD_FIXD)
#define LH_TYPE_MASK 0x30 ///< long header: packet type mask
#define LH_INIT 0x00      ///< long header packet type: Initial
#define LH_0RTT 0x10      ///< long header packet type: 0-RTT Protected
#define LH_HSHK 0x20      ///< long header packet type: Handshake
#define LH_RTRY 0x30      ///< long header packet type: Retry
#define LH_RSVD_MASK 0x0c ///< long header: reserved bits mask (= 0)

#define SH HEAD_FIXD
#define SH_SPIN 0x20      ///< short header: spin bit
#define SH_RSVD_MASK 0x18 ///< short header: reserved bits mask (= 0)
#define SH_KYPH 0x04      ///< short header: key phase bit


#define ERR_NONE 0x0
#define ERR_INTERNAL 0x1
#define ERR_FLOW_CONTROL 0x3
#define ERR_STREAM_ID 0x4
// #define ERR_STREAM_STATE 0x5
// #define ERR_FINAL_OFFSET 0x6
#define ERR_FRAME_ENC 0x7
#define ERR_TRANSPORT_PARAMETER 0x8
// #define ERR_VERSION_NEGOTIATION 0x9
#define ERR_PROTOCOL_VIOLATION 0xa
#define ERR_TLS(type) (0x100 + (type))


static inline bool __attribute__((always_inline, const))
is_lh(const uint8_t flags)
{
    return is_set(HEAD_FORM, flags);
}


static inline uint8_t __attribute__((always_inline, const))
pkt_type(const uint8_t flags)
{
    return is_lh(flags) ? flags & LH_TYPE_MASK : SH;
}


static inline uint8_t __attribute__((always_inline, const))
pkt_nr_len(const uint8_t flags)
{
    return (flags & HEAD_PNRL_MASK) + 1;
}


static inline uint8_t __attribute__((always_inline, const))
epoch_for_pkt_type(const uint8_t type)
{
    switch (type) {
    case LH_INIT:
    case LH_RTRY:
        return 0;
    case LH_0RTT:
        return 1;
    case LH_HSHK:
        return 2;
    default:
        return 3;
    }
}


static inline struct pn_space * __attribute__((always_inline, nonnull))
pn_for_pkt_type(struct q_conn * const c, const uint8_t t)
{
    switch (t) {
    case LH_INIT:
    case LH_RTRY:
        return &c->pn_init.pn;
    case LH_0RTT:
        return &c->pn_data.pn;
    case LH_HSHK:
        return &c->pn_hshk.pn;
    default:
        return &c->pn_data.pn;
    }
}


static inline const char * __attribute__((const, nonnull))
pkt_type_str(const uint8_t flags, const void * const vers)
{
    if (is_lh(flags)) {
        if (((const uint8_t * const)vers)[0] == 0 &&
            ((const uint8_t * const)vers)[1] == 0 &&
            ((const uint8_t * const)vers)[2] == 0 &&
            ((const uint8_t * const)vers)[3] == 0)
            return "Version Negotiation";
        switch (pkt_type(flags)) {
        case LH_INIT:
            return "Initial";
        case LH_RTRY:
            return "Retry";
        case LH_HSHK:
            return "Handshake";
        case LH_0RTT:
            return "0-RTT Protected";
        }
    } else if (pkt_type(flags) == SH)
        return "Short";
    return RED "Unknown" NRM;
}


struct q_stream;
struct w_iov;
struct w_iov_sq;
struct w_sock;
struct cipher_ctx;

extern void __attribute__((nonnull)) xor_hp(const struct w_iov * const xv,
                                            const struct w_iov * const v,
                                            const struct cipher_ctx * const ctx,
                                            const uint16_t pkt_nr_pos,
                                            const bool is_enc);

extern bool __attribute__((nonnull))
dec_pkt_hdr_beginning(struct w_iov * const xv,
                      struct w_iov * const v,
                      const bool is_clnt,
                      struct cid * const odcid,
                      uint8_t * const tok,
                      uint16_t * const tok_len);

extern bool __attribute__((nonnull))
dec_pkt_hdr_remainder(struct w_iov * const xv,
                      struct w_iov * const v,
                      struct q_conn * const c,
                      struct w_iov_sq * const x);

extern bool __attribute__((nonnull)) enc_pkt(struct q_stream * const s,
                                             const bool rtx,
                                             const bool enc_data,
                                             struct w_iov * const v);

extern void __attribute__((nonnull)) coalesce(struct w_iov_sq * const q);

extern void __attribute__((nonnull))
tx_vneg_resp(const struct w_sock * const ws, const struct w_iov * const v);


#ifndef NDEBUG
extern void __attribute__((nonnull(1, 2)))
log_pkt(const char * const dir,
        const struct w_iov * const v,
        const uint32_t ip,
        const uint16_t port,
        const struct cid * const odcid,
        const uint8_t * const tok,
        const uint16_t tok_len);
#else
#define log_pkt(...)                                                           \
    do {                                                                       \
    } while (0)
#endif
