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

#include <stdbool.h>

#include "bitset.h"
#include "conn.h"
#include "frame.h"
#include "pn.h"
#include "stream.h"

#include <warpcore/warpcore.h>


SPLAY_GENERATE(pm_by_nr, pkt_meta, nr_node, pm_by_nr_cmp)


void init_pn(struct pn_space * const pn, struct q_conn * const c)
{
    diet_init(&pn->recv);
    diet_init(&pn->recv_all);
    diet_init(&pn->acked);
    splay_init(&pn->sent_pkts);
    pn->lg_sent = pn->lg_acked = UINT64_MAX;
    pn->c = c;
}


void free_pn(struct pn_space * const pn)
{
    diet_free(&pn->recv);
    diet_free(&pn->recv_all);
    diet_free(&pn->acked);

    while (!splay_empty(&pn->sent_pkts)) {
        struct pkt_meta * const p = splay_min(pm_by_nr, &pn->sent_pkts);
        free_iov(w_iov(pn->c->w, pm_idx(p)));
    }
}


void reset_pn(struct pn_space * const pn)
{
    free_pn(pn);
    pn->lg_sent = pn->lg_acked = UINT64_MAX;
    pn->ect0_cnt = pn->ect1_cnt = pn->ce_cnt = 0;
    pn->pkts_rxed_since_last_ack_tx = 0;
    bit_zero(NUM_FRAM_TYPES, &pn->rx_frames);
}


void abandon_pn(struct q_conn * const c, const epoch_t e)
{
    warn(DBG, "abandon %s epoch %u processing", conn_type(c), e);
    free_pn(&c->pn_init.pn);
    free_stream(c->cstreams[e]);
    dispose_cipher(&c->pn_init.in);
    dispose_cipher(&c->pn_init.out);
    c->cstreams[e] = 0;
}


ack_t needs_ack(const struct pn_space * const pn)
{
    const bool rxed_one_or_more = pn->pkts_rxed_since_last_ack_tx >= 1;
    if (rxed_one_or_more == false) {
        // warn(ERR, "no_ack: rxed_one_or_more == false");
        return no_ack;
    }

    const bool have_ack_eliciting = is_ack_eliciting(&pn->rx_frames);
    if (have_ack_eliciting == false) {
        // warn(ERR, "grat_ack: have_ack_eliciting == false");
        return grat_ack;
    }

    const bool in_hshk = &pn->c->pn_data.pn != pn;
    if (in_hshk) {
        // warn(ERR, "imm_ack: in_hshk");
        return imm_ack;
    }

    const bool rxed_two_or_more = pn->pkts_rxed_since_last_ack_tx >= 2;
    if (rxed_two_or_more) {
        // warn(ERR, "imm_ack: rxed_two_or_more");
        return imm_ack;
    }

    // warn(ERR, "del_ack");
    return del_ack;
}
