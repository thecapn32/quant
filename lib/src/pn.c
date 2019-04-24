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

#define klib_unused

#include <khash.h>
#include <warpcore/warpcore.h>

#include "bitset.h"
#include "conn.h"
#include "frame.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"


void pm_by_nr_del(khash_t(pm_by_nr) * const pbn,
                  const struct pkt_meta * const p)
{
    const khiter_t k = kh_get(pm_by_nr, pbn, p->hdr.nr);
    ensure(k != kh_end(pbn), "found");
    kh_del(pm_by_nr, pbn, k);
}


void pm_by_nr_ins(khash_t(pm_by_nr) * const pbn, struct pkt_meta * const p)
{
    int ret;
    const khiter_t k = kh_put(pm_by_nr, pbn, p->hdr.nr, &ret);
    ensure(ret >= 1, "inserted");
    kh_val(pbn, k) = p;
}


struct w_iov * find_sent_pkt(const struct pn_space * const pn,
                             const uint64_t nr,
                             struct pkt_meta ** const m)
{
    const khiter_t k = kh_get(pm_by_nr, pn->sent_pkts, nr);
    if (unlikely(k == kh_end(pn->sent_pkts)))
        return 0;
    *m = kh_val(pn->sent_pkts, k);
    return w_iov(pn->c->w, pm_idx(*m));
}


void init_pn(struct pn_space * const pn,
             struct q_conn * const c,
             const pn_t type)
{
    diet_init(&pn->recv);
    diet_init(&pn->recv_all);
    diet_init(&pn->acked);
    diet_init(&pn->lost);
    pn->sent_pkts = kh_init(pm_by_nr);
    pn->lg_sent = pn->lg_acked = UINT64_MAX;
    pn->c = c;
    pn->type = type;
}


void free_pn(struct pn_space * const pn)
{
    if (pn->sent_pkts) {
        struct pkt_meta * p;
        kh_foreach_value(pn->sent_pkts, p, {
            // let's take all pkts out of in_flight here
            if (p->in_flight) {
                pn->c->rec.in_flight -= p->udp_len;
                if (p->ack_eliciting)
                    pn->c->rec.ae_in_flight--;
            }
            // TX'ed but non-RTX'ed pkts are freed when their stream is freed
            if (p->has_rtx || !has_stream_data(p))
                free_iov(w_iov(pn->c->w, pm_idx(p)), p);
        });
        kh_destroy(pm_by_nr, pn->sent_pkts);
        pn->sent_pkts = 0;
    }

    diet_free(&pn->recv);
    diet_free(&pn->recv_all);
    diet_free(&pn->acked);
    diet_free(&pn->lost);
}


void reset_pn(struct pn_space * const pn)
{
    free_pn(pn);
    pn->sent_pkts = kh_init(pm_by_nr);
    pn->lg_sent = pn->lg_acked = UINT64_MAX;
    pn->ect0_cnt = pn->ect1_cnt = pn->ce_cnt = 0;
    pn->pkts_rxed_since_last_ack_tx = 0;
    bit_zero(NUM_FRAM_TYPES, &pn->rx_frames);
}


void abandon_pn(struct pn_space * const pn)
{
    ensure(pn->type != pn_data, "cannot abandon pn_data");

    warn(DBG, "abandoning %s %s processing", conn_type(pn->c),
         pn_type_str(pn->type));
    free_pn(pn);

    epoch_t e = ep_init;
    if (unlikely(pn->type == pn_hshk))
        e = ep_hshk;
    free_stream(pn->c->cstreams[e]);
    pn->c->cstreams[e] = 0;
    pn->loss_t = 0; // important for earliest_loss_t_pn

    dispose_cipher(&pn->early.in);
    dispose_cipher(&pn->early.out);

    // we need to kill the timer if there are no pkts outstanding
    set_ld_timer(pn->c);
}


ack_t needs_ack(const struct pn_space * const pn)
{
    struct q_conn * const c = pn->c;

    if (unlikely(c->imm_ack)) {
        // warn(ERR, "%s conn %s: imm_ack: forced", conn_type(c),
        //      cid2str(c->scid));
        return imm_ack;
    }

    const bool rxed_one_or_more = pn->pkts_rxed_since_last_ack_tx >= 1;
    if (rxed_one_or_more == false) {
        // warn(ERR, "%s conn %s: no_ack: rxed_one_or_more == false",
        // conn_type(c),
        //      cid2str(c->scid));
        return no_ack;
    }

    const bool have_ack_eliciting = is_ack_eliciting(&pn->rx_frames);
    if (have_ack_eliciting == false) {
        // warn(ERR, "%s conn %s: grat_ack: have_ack_eliciting == false",
        //      conn_type(c), cid2str(c->scid));
        return grat_ack;
    }

    const bool in_hshk = pn->type != pn_data;
    if (in_hshk) {
        // warn(ERR, "%s conn %s: imm_ack: in_hshk", conn_type(c),
        //      cid2str(c->scid));
        return imm_ack;
    }

    const bool rxed_two_or_more = pn->pkts_rxed_since_last_ack_tx >= 2;
    if (rxed_two_or_more) {
        // warn(ERR, "%s conn %s: imm_ack: rxed_two_or_more", conn_type(c),
        //      cid2str(c->scid));
        return imm_ack;
    }

    // warn(ERR, "%s conn %s: del_ack", conn_type(c), cid2str(c->scid));
    return del_ack;
}
