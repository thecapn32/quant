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

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>

#include <ev.h>
#include <khash.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"
#include "tls.h"


struct ev_loop;

#define is_crypto_pkt(m) has_frame((m), FRM_CRY)


static inline bool __attribute__((nonnull))
in_recovery(const struct q_conn * const c, const ev_tstamp sent_t)
{
    // see InRecovery() pseudo code
    return sent_t <= c->rec.rec_start_t;
}


static bool __attribute__((nonnull))
crypto_pkts_in_flight(struct q_conn * const c)
{
    return (c->cstreams[ep_init] &&
            out_fully_acked(c->cstreams[ep_init]) == false) ||
           out_fully_acked(c->cstreams[ep_hshk]) == false;
}


static bool __attribute__((nonnull))
have_keys(struct q_conn * const c, const pn_t t)
{
    const struct pn_space * const pn = &c->pns[t];
    switch (t) {
    case pn_init:
    case pn_hshk:
        return pn->early.in.aead && pn->early.out.aead;
    case pn_data:
        return (pn->data.in_1rtt[0].aead && pn->data.out_1rtt[0].aead) ||
               (pn->data.in_1rtt[1].aead && pn->data.out_1rtt[1].aead);
    }
    die("unhandled pn %s", pn_type_str(t));
}


static void __attribute__((nonnull)) maybe_tx(struct q_conn * const c)
{
    if (has_wnd(c, c->w->mtu) == false)
        return;

    c->no_wnd = false;
    // don't set c->needs_tx = true, since it's not clear we must TX
    ev_feed_event(loop, &c->tx_w, 0);
}

static struct pn_space * __attribute__((nonnull))
earliest_loss_t_pn(struct q_conn * const c)
{
    struct pn_space * pn = &c->pns[pn_init];
    ev_tstamp loss_t = pn->loss_t;

    struct pn_space * const pn_h = &c->pns[pn_hshk];
    if (is_zero(pn_h->loss_t) == false &&
        (is_zero(loss_t) || pn_h->loss_t < loss_t)) {
        loss_t = pn_h->loss_t;
        pn = pn_h;
    }

    struct pn_space * const pn_d = &c->pns[pn_data];
    if (is_zero(pn_d->loss_t) == false &&
        (is_zero(loss_t) || pn_d->loss_t < loss_t)) {
        // loss_t = pn_d->loss_t;
        pn = pn_d;
    }
    return pn;
}


void set_ld_timer(struct q_conn * const c)
{
    if (c->state == conn_idle || c->state == conn_clsg || c->state == conn_drng)
        // don't do LD while idle or draining
        return;

    // see SetLossDetectionTimer() pseudo code

    const char * type = BLD RED "???" NRM;
    const struct pn_space * const pn = earliest_loss_t_pn(c);

    if (!is_zero(pn->loss_t)) {
        type = "TT";
        c->rec.ld_alarm.repeat = pn->loss_t;
        goto set_to;
    }

    if (unlikely(crypto_pkts_in_flight(c) || have_keys(c, pn_data) == false)) {
        type = "crypto RTX";
        ev_tstamp to =
            2 * (unlikely(is_zero(c->rec.srtt)) ? kInitialRtt : c->rec.srtt);
        to = MAX(to, kGranularity) * (1 << c->rec.crypto_cnt);
        c->rec.ld_alarm.repeat = c->rec.last_sent_crypto_t + to;
        goto set_to;
    }

    // don't arm the alarm if there are no ack-eliciting packets in flight
    if (unlikely(c->rec.ae_in_flight == 0)) {
        warn(DBG, "no RTX-able pkts outstanding, stopping ld_alarm");
        ev_timer_stop(loop, &c->rec.ld_alarm);
        return;
    }

    type = "PTO";
    ev_tstamp to = c->rec.srtt + MAX(4 * c->rec.rttvar, kGranularity) +
                   (double)c->tp_out.max_ack_del / MSECS_PER_SEC;
    to = MAX(to, kGranularity) * (1 << c->rec.pto_cnt);
    c->rec.ld_alarm.repeat = c->rec.last_sent_ack_elicit_t + to;

set_to:
    c->rec.ld_alarm.repeat -= ev_now(loop);

    warn(DBG, "%s alarm in %f sec on %s conn %s", type,
         c->rec.ld_alarm.repeat < 0 ? 0 : c->rec.ld_alarm.repeat, conn_type(c),
         cid2str(c->scid));
    if (c->rec.ld_alarm.repeat <= 0)
        ev_invoke(loop, &c->rec.ld_alarm, true);
    else
        ev_timer_again(loop, &c->rec.ld_alarm);
}


void congestion_event(struct q_conn * const c, const ev_tstamp sent_t)
{
    // see CongestionEvent() pseudo code

    if (!in_recovery(c, sent_t)) {
        c->rec.rec_start_t = ev_now(loop);
        c->rec.cwnd /= kLossReductionDivisor;
        c->rec.ssthresh = c->rec.cwnd = MAX(c->rec.cwnd, kMinimumWindow);

        // XXX this is no longer in -19
        if (c->rec.pto_cnt > kPersistentCongestionThreshold)
            c->rec.cwnd = kMinimumWindow;
    }
}


// static void __attribute__((nonnull)) unregister_rtx(struct pm_sl * rtx)
// {
//     while (!sl_empty(rtx)) {
//         struct pkt_meta * const pm = sl_first(rtx);
//         sl_remove_head(rtx, rtx_next);
//         sl_remove_head(&pm->rtx, rtx_next);
//         ensure(sl_empty(&pm->rtx), "not empty");
//     }
// }


static void __attribute__((nonnull))
detect_lost_pkts(struct pn_space * const pn, const bool do_cc)
{
    if (pn->sent_pkts == 0)
        // abandoned PN
        return;

    struct q_conn * const c = pn->c;
    pn->loss_t = 0;
    const ev_tstamp loss_del =
        kTimeThreshold * MAX(c->rec.latest_rtt, c->rec.srtt);

    // Packets sent before this time are deemed lost.
    const ev_tstamp lost_send_t = ev_now(loop) - loss_del;

    // Packets with packet numbers before this are deemed lost.
    const uint64_t lost_pn = unlikely(pn->lg_acked == UINT64_MAX)
                                 ? 0
                                 : pn->lg_acked - kPacketThreshold;

    uint64_t lg_lost = UINT64_MAX;
    ev_tstamp lg_lost_tx_t = 0;
    bool in_flight_lost = false;
    struct pkt_meta * p;
    kh_foreach_value(pn->sent_pkts, p, {
        ensure(p->acked == false, "ACKed pkt in sent_pkts");
        ensure(p->lost == false, "lost pkt in sent_pkts");

        if (p->hdr.nr > pn->lg_acked)
            continue;

        // Mark packet as lost, or set time when it should be marked.
        if (p->tx_t <= lost_send_t || p->hdr.nr <= lost_pn) {
            p->lost = true;
            in_flight_lost |= p->in_flight;
            c->i.pkts_out_lost++;
            // cppcheck-suppress knownConditionTrueFalse
            if (unlikely(lg_lost == UINT64_MAX) || p->hdr.nr > lg_lost) {
                lg_lost = p->hdr.nr;
                lg_lost_tx_t = p->tx_t;
            }
        } else {
            if (is_zero(pn->loss_t))
                pn->loss_t = p->tx_t + loss_del;
            else
                pn->loss_t = MIN(pn->loss_t, p->tx_t + loss_del);
        }

        // OnPacketsLost
        if (p->lost)
            on_pkt_lost(p);
    });

    // OnPacketsLost
    if (do_cc && in_flight_lost)
        congestion_event(c, lg_lost_tx_t);

    log_cc(c);
}


static void __attribute__((nonnull))
on_ld_alarm(struct ev_loop * const l __attribute__((unused)),
            ev_timer * const w,
            int direct)
{
    struct q_conn * const c = w->data;
    ev_timer_stop(loop, &c->rec.ld_alarm);

    // see OnLossDetectionTimeout pseudo code
    struct pn_space * const pn = earliest_loss_t_pn(c);

    if (!is_zero(pn->loss_t)) {
        warn(DBG, "TT alarm pn %u on %s conn %s", pn->type, conn_type(c),
             cid2str(c->scid));
        detect_lost_pkts(pn, true);

        // XXX: this will be part of the -20 pseudo code - causes TX to resume
        ev_invoke(loop, &c->tx_w, 1);

    } else if (crypto_pkts_in_flight(c)) {
        warn(DBG, "crypto RTX #%u on %s conn %s", c->rec.crypto_cnt + 1,
             conn_type(c), cid2str(c->scid));
        detect_lost_pkts(&c->pns[pn_init], false);
        detect_lost_pkts(&c->pns[pn_hshk], false);
        detect_lost_pkts(&c->pns[pn_data], false);
        if (c->rec.crypto_cnt++ >= 2 && c->sockopt.enable_ecn) {
            warn(NTE, "turning off ECN for %s conn %s", conn_type(c),
                 cid2str(c->scid));
            c->sockopt.enable_ecn = false;
            w_set_sockopt(c->sock, &c->sockopt);
        }
        ev_invoke(loop, &c->tx_w, 0);
        c->i.pto_cnt++;

    } else if (have_keys(c, pn_data) == false) {
        warn(DBG, "anti-deadlock RTX #%u on %s conn %s", c->rec.crypto_cnt + 1,
             conn_type(c), cid2str(c->scid));

        // XXX this doesn't quite implement the pseudo code
        ev_invoke(loop, &c->tx_w, 1);
        c->rec.crypto_cnt++;

    } else {
        warn(DBG, "PTO alarm #%u on %s conn %s", c->rec.pto_cnt, conn_type(c),
             cid2str(c->scid));
        c->rec.pto_cnt++;
        c->i.pto_cnt++;
        ev_invoke(loop, &c->tx_w, 2);
    }

    if (!direct)
        // we were called via set_ld_timer, so don't call it again
        set_ld_timer(c);
}


static void __attribute__((nonnull))
track_acked_pkts(struct w_iov * const v, struct pkt_meta * const m)
{
    adj_iov_to_start(v, m);
    const uint8_t * pos = v->buf + m->ack_block_pos;
    const uint8_t * const end = v->buf + v->len;

    // this is a similar loop as in dec_ack_frame() - keep changes in sync
    uint64_t lg_ack_in_block = m->lg_acked;
    for (uint64_t n = m->ack_block_cnt + 1; n > 0; n--) {
        uint64_t ack_block_len = 0;
        decv(&ack_block_len, &pos, end);
        diet_remove_ival(
            &m->pn->recv,
            &(const struct ival){.lo = lg_ack_in_block - ack_block_len,
                                 .hi = lg_ack_in_block});
        if (n > 1) {
            uint64_t gap = 0;
            decv(&gap, &pos, end);
            lg_ack_in_block = lg_ack_in_block - ack_block_len - gap - 2;
        }
    }

    adj_iov_to_data(v, m);
}


void on_pkt_sent(struct pkt_meta * const m)
{
    m->txed = true;

    // see OnPacketSent() pseudo code

    pm_by_nr_ins(m->pn->sent_pkts, m);
    // nr is set in enc_pkt()
    m->tx_t = ev_now(loop);
    // ack_eliciting is set in enc_pkt()
    m->in_flight = m->ack_eliciting || has_frame(m, FRM_PAD);

    struct q_conn * const c = m->pn->c;
    if (likely(m->in_flight)) {
        if (unlikely(is_crypto_pkt(m)))
            c->rec.last_sent_crypto_t = m->tx_t;
        if (likely(m->ack_eliciting)) {
            c->rec.last_sent_ack_elicit_t = m->tx_t;
            c->rec.ae_in_flight++;
        }

        // OnPacketSentCC
        c->rec.in_flight += m->udp_len;
    }

    set_ld_timer(c);
}


static void __attribute__((nonnull))
update_rtt(struct q_conn * const c, ev_tstamp ack_del)
{
    // see UpdateRtt() pseudo code
    if (unlikely(is_zero(c->rec.srtt))) {
        c->rec.min_rtt = c->rec.srtt = c->rec.latest_rtt;
        c->rec.rttvar = c->rec.latest_rtt / 2;
        return;
    }

    c->rec.min_rtt = MIN(c->rec.min_rtt, c->rec.latest_rtt);
    ack_del = MIN(ack_del, c->tp_out.max_ack_del);

    if (c->rec.latest_rtt > c->rec.min_rtt + ack_del)
        c->rec.latest_rtt -= ack_del;

    c->rec.rttvar =
        .75 * c->rec.rttvar + .25 * fabs(c->rec.srtt - c->rec.latest_rtt);
    c->rec.srtt = .875 * c->rec.srtt + .125 * c->rec.latest_rtt;
}


void on_ack_received_1(struct pkt_meta * const lg_ack, const uint64_t ack_del)
{
    // see OnAckReceived() pseudo code
    struct pn_space * const pn = lg_ack->pn;
    struct q_conn * const c = pn->c;
    pn->lg_acked = MAX(pn->lg_acked, lg_ack->hdr.nr);

    // we're only called for the largest ACK'ed
    if (lg_ack->ack_eliciting) {
        c->rec.latest_rtt = ev_now(loop) - lg_ack->tx_t;
        update_rtt(c, ack_del / 1000000.0); // ack_del is passed in usec
    }

    // ProcessECN() is done in dec_ack_frame()
}


void on_ack_received_2(struct pn_space * const pn)
{
    // see OnAckReceived() pseudo code

    struct q_conn * const c = pn->c;
    detect_lost_pkts(pn, true);
    c->rec.crypto_cnt = c->rec.pto_cnt = 0;
    set_ld_timer(c);

    // not part of pseudo code - causes TX to resume when the window opens
    maybe_tx(c);
}


static void __attribute__((nonnull))
on_pkt_acked_cc(const struct pkt_meta * meta_acked)
{
    // OnPacketAckedCC
    struct q_conn * const c = meta_acked->pn->c;
    c->rec.in_flight -= meta_acked->udp_len;
    if (meta_acked->ack_eliciting)
        c->rec.ae_in_flight--;

    if (in_recovery(c, meta_acked->tx_t))
        return;

    // TODO: Do not increase congestion window in recovery period.

    if (c->rec.cwnd < c->rec.ssthresh)
        c->rec.cwnd += meta_acked->udp_len;
    else
        c->rec.cwnd += kMaxDatagramSize * meta_acked->udp_len / c->rec.cwnd;
}


void on_pkt_acked(struct w_iov * const acked_pkt, struct pkt_meta * meta_acked)
{
    // see OnPacketAcked() pseudo code
    struct pn_space * const pn = meta_acked->pn;
    struct q_conn * const c = pn->c;
    if (meta_acked->in_flight && meta_acked->lost == false)
        on_pkt_acked_cc(meta_acked);

    diet_insert(&pn->acked, meta_acked->hdr.nr, (ev_tstamp)NAN);
    pm_by_nr_del(pn->sent_pkts, meta_acked);

    // rest of function is not from pseudo code

    // stop ACKing packets that were contained in the ACK frame of this packet
    if (has_frame(meta_acked, FRM_ACK))
        track_acked_pkts(acked_pkt, meta_acked);

    // // if this ACK is for a pkt that was RTX'ed, update the record
    // struct pkt_meta * const meta_rtx = sl_first(&meta_acked->rtx);
    // if (meta_rtx) {
    //     if (meta_acked->has_rtx) {
    //         // ensure(meta_acked->lost, "meta_acked->lost");
    //         // ensure(sl_next(meta_rtx, rtx_next) == 0, "rtx chain corrupt");

    //         // remove RTX info
    //         warn(DBG, "%s pkt " FMT_PNR_OUT " was RTX'ed as " FMT_PNR_OUT,
    //              conn_type(c), meta_acked->hdr.nr, meta_rtx->hdr.nr);
    //         unregister_rtx(&meta_rtx->rtx);

    //         // treat the RTX'ed data has ACK'ed, use stand-in w_iov for RTX
    //         info const uint64_t acked_nr = meta_acked->hdr.nr;
    //         pm_by_nr_del(pn->sent_pkts, meta_rtx);
    //         meta_acked->hdr.nr = meta_rtx->hdr.nr;
    //         meta_rtx->hdr.nr = acked_nr;
    //         pm_by_nr_ins(pn->sent_pkts, meta_acked);
    //         meta_acked = meta_rtx;
    //     } else
    //         unregister_rtx(&meta_acked->rtx);
    // }

    meta_acked->acked = true;

    struct q_stream * const s = meta_acked->stream;
    if (s) {
        if (unlikely(meta_acked->is_fin))
            // this ACKs a FIN
            maybe_api_return(q_close_stream, c, s);

        // if this ACKs its stream's out_una, move that forward
        struct w_iov * tmp;
        sq_foreach_from_safe (s->out_una, &s->out, next, tmp) {
            struct pkt_meta * const mou = &meta(s->out_una); // meta use OK
            if (mou->acked == false)
                break;
            // if this ACKs a crypto packet, we can free it
            if (unlikely(s->id < 0 && mou->lost == false)) {
                sq_remove(&s->out, s->out_una, w_iov, next);
                free_iov(s->out_una, mou);
            }
        }

        if (s->id >= 0 && s->out_una == 0) {
            // a q_write may be done
            maybe_api_return(q_write, c, s);
            if (c->did_0rtt)
                maybe_api_return(q_connect, c, 0);
        }

    } else
        free_iov(acked_pkt, meta_acked);
}


void on_pkt_lost(struct pkt_meta * const m)
{
    struct pn_space * const pn = m->pn;
    struct q_conn * const c = pn->c;

    warn(DBG, "%s %s pkt " FMT_PNR_OUT " considered lost", conn_type(c),
         pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.nr);

    if (m->in_flight) {
        c->rec.in_flight -= m->udp_len;
        if (m->ack_eliciting)
            c->rec.ae_in_flight--;
    }

    // rest of function is not from pseudo code

    diet_insert(&pn->lost, m->hdr.nr, (ev_tstamp)NAN);
    pm_by_nr_del(pn->sent_pkts, m);

    if (m->has_rtx)
        die("has RTX");
    //     unregister_rtx(&m->rtx);

    if (m->stream == 0)
        free_iov(w_iov(c->w, pm_idx(m)), m);
}


void init_rec(struct q_conn * const c)
{
    if (ev_is_active(&c->rec.ld_alarm))
        ev_timer_stop(loop, &c->rec.ld_alarm);

    // zero all, then reset
    memset(&c->rec, 0, sizeof(c->rec));

    c->rec.cwnd = kInitialWindow;
    c->rec.ssthresh = UINT64_MAX;
    c->rec.min_rtt = HUGE_VAL;
    c->rec.ld_alarm.data = c;
    ev_init(&c->rec.ld_alarm, on_ld_alarm);
}
