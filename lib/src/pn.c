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

#ifdef HAVE_ASAN
#include <sanitizer/asan_interface.h>
#else
#define ASAN_POISON_MEMORY_REGION(x, y)
#define ASAN_UNPOISON_MEMORY_REGION(x, y)
#endif

#include "bitset.h"
#include "conn.h"
#include "frame.h"
#include "pn.h"
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
                             const uint64_t nr)
{
    const khiter_t k = kh_get(pm_by_nr, pn->sent_pkts, nr);
    if (unlikely(k == kh_end(pn->sent_pkts)))
        return 0;
    return w_iov(pn->c->w, pm_idx(kh_val(pn->sent_pkts, k)));
}


void init_pn(struct pn_space * const pn, struct q_conn * const c)
{
    diet_init(&pn->recv);
    diet_init(&pn->recv_all);
    diet_init(&pn->acked);
    pn->sent_pkts = kh_init(pm_by_nr);
    pn->lg_sent = pn->lg_acked = UINT64_MAX;
    pn->c = c;
}


void free_pn(struct pn_space * const pn)
{
    if (pn->sent_pkts) {
        struct pkt_meta * p;
        kh_foreach_value(pn->sent_pkts, p,
                         { free_iov(w_iov(pn->c->w, pm_idx(p))); });
        kh_destroy(pm_by_nr, pn->sent_pkts);
        pn->sent_pkts = 0;
    }

    diet_free(&pn->recv);
    diet_free(&pn->recv_all);
    diet_free(&pn->acked);
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


void abandon_pn(struct q_conn * const c, const epoch_t e)
{
    warn(DBG, "abandon %s epoch %u processing", conn_type(c), e);
    free_stream(c->cstreams[e]);
    free_pn(&c->pn_init.pn);
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
