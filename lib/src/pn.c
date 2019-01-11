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

#include "pn.h"
#include "conn.h"
#include "stream.h"


struct ev_loop;


SPLAY_GENERATE(pm_by_nr, pkt_meta, nr_node, pm_by_nr_cmp)


static inline __attribute__((always_inline, nonnull)) epoch_t
epoch_for_pn(const struct pn_space * pn)
{
    if (pn == &pn->c->pn_init.pn)
        return ep_init;
    if (pn == &pn->c->pn_hshk.pn)
        return ep_hshk;
    return pn->c->state == conn_opng ? ep_0rtt : ep_data;
}


void ack_alarm(struct ev_loop * const l __attribute__((unused)),
               ev_timer * const w,
               int e __attribute__((unused)))
{
    struct pn_space * const pn = w->data;
    if (needs_ack(pn)) {
        warn(DBG, "ACK timer fired on %s conn %s epoch %u", conn_type(pn->c),
             cid2str(pn->c->scid), epoch_for_pn(pn));
        tx_ack(pn->c, epoch_for_pn(pn));
    }
    ev_timer_stop(loop, &pn->ack_alarm);
}


void init_pn(struct pn_space * const pn,
             struct q_conn * const c,
             const ev_tstamp ack_del)
{
    diet_init(&pn->recv);
    diet_init(&pn->recv_all);
    diet_init(&pn->acked);
    splay_init(&pn->sent_pkts);
    pn->lg_sent = pn->lg_acked = UINT64_MAX;
    pn->c = c;

    // initialize ACK timeout
    pn->ack_alarm.data = pn;
    pn->ack_alarm.repeat = ack_del;
    ev_init(&pn->ack_alarm, ack_alarm);
}


static void do_free_pn(struct pn_space * const pn, const bool free_iov)
{
    ev_timer_stop(loop, &pn->ack_alarm);

    // free any remaining buffers
    struct pkt_meta * p = splay_min(pm_by_nr, &pn->sent_pkts);
    while (p) {
        struct pkt_meta * const nxt = splay_next(pm_by_nr, &pn->sent_pkts, p);
        if (free_iov)
            free_iov(w_iov(pn->c->w, pm_idx(p)));
        else
            ensure(splay_remove(pm_by_nr, &pn->sent_pkts, p), "removed");
        p = nxt;
    }

    diet_free(&pn->recv);
    diet_free(&pn->recv_all);
    diet_free(&pn->acked);
}


void reset_pn(struct pn_space * const pn)
{
    do_free_pn(pn, false);

    pn->lg_sent = pn->lg_acked = UINT64_MAX;
    pn->ect0_cnt = pn->ect1_cnt = pn->ce_cnt = 0;
}


void free_pn(struct pn_space * const pn)
{
    do_free_pn(pn, true);
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
