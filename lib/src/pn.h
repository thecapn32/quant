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

#include <ev.h>
#include <warpcore/warpcore.h>

#include "diet.h"
#include "quic.h"
#include "tls.h"


struct q_conn;
struct ev_loop;


splay_head(pm_nr_splay, pkt_meta);


struct pn_space {
    struct diet recv; ///< Received packet numbers still needing to be ACKed.
    struct diet recv_all; ///< All received packet numbers.
    struct diet acked;    ///< Sent packet numbers already ACKed.

    /// Sent-but-unACKed packets. The @p buf and @p len fields of the w_iov
    /// structs are relative to any stream or crypto data.
    ///
    struct pm_nr_splay sent_pkts; // sent_packets

    uint64_t lg_sent;            // largest_sent_packet
    uint64_t lg_acked;           // largest_acked_packet
    uint64_t lg_sent_before_rto; // largest_sent_before_rto

    ev_timer ack_alarm;
    struct q_conn * c;
};


struct pn_hshk_space {
    struct pn_space pn;
    struct cipher_ctx in;
    struct cipher_ctx out;
};


struct pn_data_space {
    struct pn_space pn;
    struct cipher_ctx in[2];
    struct cipher_ctx out_0rtt;
    struct cipher_ctx out_1rtt;
};


extern int __attribute__((nonnull))
pm_nr_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b);


SPLAY_PROTOTYPE(pm_nr_splay, pkt_meta, nr_node, pm_nr_cmp)


extern void __attribute__((nonnull))
init_pn(struct pn_space * const pn, struct q_conn * const c);

extern void __attribute__((nonnull)) free_pn(struct pn_space * const pn);

extern void __attribute__((nonnull)) reset_pn(struct pn_space * const pn);

extern void __attribute__((nonnull))
ack_alarm(struct ev_loop * const l, ev_timer * const w, int e);


static inline bool __attribute__((nonnull, always_inline))
needs_ack(struct pn_space * const pn)
{
    return !diet_empty(&pn->recv);
}
