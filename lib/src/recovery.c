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

#ifndef NDEBUG
uint64_t prev_in_flight = 0, prev_cwnd = 0, prev_ssthresh = 0;
ev_tstamp prev_srtt = 0, prev_rttvar = 0;
#endif


#define is_crypto_pkt(v) has_frame((v), FRM_CRY)


static inline bool __attribute__((nonnull))
in_recovery(const struct q_conn * const c, const ev_tstamp sent_t)
{
    // see InRecovery() pseudo code
    return sent_t <= c->rec.rec_start_t;
}


static inline bool __attribute__((nonnull))
crypto_pkts_in_flight(struct q_conn * const c)
{
    return (c->cstreams[ep_init] &&
            out_fully_acked(c->cstreams[ep_init]) == false) ||
           out_fully_acked(c->cstreams[ep_hshk]) == false;
}


static void __attribute__((nonnull)) set_ld_timer(struct q_conn * const c)
{
    // see SetLossDetectionTimer() pseudo code

    if (c->state == conn_clsg || c->state == conn_drng)
        // don't do LD while draining
        return;

    // don't arm the alarm if there are no ack-eliciting packets in flight
    if (unlikely(c->rec.ae_in_flight == 0)) {
        // warn(DBG, "no RTX-able pkts outstanding, stopping ld_alarm");
        ev_timer_stop(loop, &c->rec.ld_alarm);
        return;
    }

    // const char * type = BLD RED "???" NRM;
    if (unlikely(crypto_pkts_in_flight(c))) {
        // type = "crypto RTX";
        ev_tstamp to =
            2 * (unlikely(is_zero(c->rec.srtt)) ? kInitialRtt : c->rec.srtt);
        to = MAX(to, kGranularity) * (1 << c->rec.crypto_cnt);
        c->rec.ld_alarm.repeat = c->rec.last_sent_crypto_t + to;
        goto set_to;
    }

    if (!is_zero(c->rec.loss_t)) {
        // type = "TT";
        c->rec.ld_alarm.repeat = c->rec.loss_t;
        goto set_to;
    }

    // type = "PTO";
    ev_tstamp to =
        c->rec.srtt + (4 * c->rec.rttvar) + (c->tp_out.max_ack_del / 1000.0);
    to = MAX(to, kGranularity) * (1 << c->rec.pto_cnt);
    c->rec.ld_alarm.repeat = c->rec.last_sent_ack_elicit_t + to;

set_to:
    c->rec.ld_alarm.repeat -= ev_now(loop);

    // warn(DBG, "%s alarm in %f sec on %s conn %s", type,
    //      c->rec.ld_alarm.repeat < 0 ? 0 : c->rec.ld_alarm.repeat,
    //      conn_type(c), cid2str(c->scid));
    if (c->rec.ld_alarm.repeat <= 0)
        ev_invoke(loop, &c->rec.ld_alarm, 0);
    else
        ev_timer_again(loop, &c->rec.ld_alarm);
}


void congestion_event(struct q_conn * const c, const ev_tstamp sent_t)
{
    // see CongestionEvent() pseudo code

    if (!in_recovery(c, sent_t)) {
        c->rec.rec_start_t = ev_now(loop);
        c->rec.cwnd /= kLossReductionDivisor;
        c->rec.cwnd = MAX(c->rec.cwnd, kMinimumWindow);
        c->rec.ssthresh = c->rec.cwnd;

        if (c->rec.pto_cnt > kPersistentCongestionThreshold)
            c->rec.cwnd = kMinimumWindow;
    }
}


static void __attribute__((nonnull))
detect_lost_pkts(struct q_conn * const c,
                 struct pn_space * const pn,
                 const bool do_cc)
{
    const ev_tstamp now = ev_now(loop);

    c->rec.loss_t = 0;
    const ev_tstamp loss_del =
        kTimeThreshold * MAX(c->rec.latest_rtt, c->rec.srtt);

    // Packets sent before this time are deemed lost.
    const ev_tstamp lost_send_t = now - loss_del;

    // Packets with packet numbers before this are deemed lost.
    const uint64_t lost_pn = pn->lg_acked - kPacketThreshold;

    struct pkt_meta *p, *nxt, *largest_lost_pkt = 0;
    for (p = splay_min(pm_by_nr, &pn->sent_pkts); p; p = nxt) {
        nxt = splay_next(pm_by_nr, &pn->sent_pkts, p);

        if (p->is_acked || p->is_lost)
            continue;

        if (p->hdr.nr > pn->lg_acked)
            continue;

        // Mark packet as lost, or set time when it should be marked.
        if (p->tx_t <= lost_send_t ||
            (likely(pn->lg_acked != UINT64_MAX) && p->hdr.nr <= lost_pn)) {
            p->is_lost = true;
            if (unlikely(largest_lost_pkt == 0) ||
                p->hdr.nr > largest_lost_pkt->hdr.nr)
                largest_lost_pkt = p;
        } else if (is_zero(c->rec.loss_t))
            c->rec.loss_t = p->tx_t + loss_del;
        else
            c->rec.loss_t = MIN(c->rec.loss_t, p->tx_t + loss_del);

        // OnPacketsLost:
        if (p->is_lost) {
            warn(DBG, "%s pkt " FMT_PNR_OUT " considered lost",
                 pkt_type_str(p->hdr.flags, &p->hdr.vers), p->hdr.nr);

            if (is_ack_eliciting(&p->frames)) {
                c->rec.in_flight -= p->udp_len;
                c->rec.ae_in_flight--;
            }

            log_cc(c);

            if (p->is_rtx || !has_stream_data(p)) {
                if (p->is_rtx)
                    // remove from the original w_iov rtx list
                    sl_remove(&sl_first(&p->rtx)->rtx, p, pkt_meta, rtx_next);
                free_iov(w_iov(c->w, pm_idx(p)));
                if (largest_lost_pkt == p)
                    largest_lost_pkt = 0;
            }
        }
    }
    if (do_cc && largest_lost_pkt)
        congestion_event(c, largest_lost_pkt->tx_t);
    log_cc(c);
}


static void __attribute__((nonnull))
on_ld_alarm(struct ev_loop * const l __attribute__((unused)),
            ev_timer * const w,
            int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    struct pn_space * const pn = pn_for_epoch(c, c->tls.epoch_out);
    ev_timer_stop(loop, &c->rec.ld_alarm);

    // see OnLossDetectionTimeout pseudo code
    if (crypto_pkts_in_flight(c)) {
        warn(DBG, "crypto RTX #%u on %s conn %s", c->rec.crypto_cnt + 1,
             conn_type(c), cid2str(c->scid));
        detect_lost_pkts(c, pn_for_epoch(c, ep_init), false);
        detect_lost_pkts(c, pn_for_epoch(c, ep_hshk), false);
        if (c->rec.crypto_cnt++ >= 2 && c->tls.epoch_out == ep_init &&
            c->sockopt.enable_ecn) {
            warn(NTE, "turning off ECN for %s conn %s", conn_type(c),
                 cid2str(c->scid));
            c->sockopt.enable_ecn = false;
            w_set_sockopt(c->sock, &c->sockopt);
        }
        tx(c, 0);

    } else if (!is_zero(c->rec.loss_t)) {
        warn(DBG, "TT alarm ep %u on %s conn %s", c->tls.epoch_out,
             conn_type(c), cid2str(c->scid));
        detect_lost_pkts(c, pn, true);

    } else {
        warn(DBG, "PTO alarm #%u on %s conn %s", c->rec.pto_cnt, conn_type(c),
             cid2str(c->scid));
        c->rec.pto_cnt++;
        tx(c, 2);
    }

    set_ld_timer(c);
}


static inline void __attribute__((nonnull))
track_acked_pkts(struct pn_space * const pn, struct w_iov * const v)
{
    adj_iov_to_start(v);

    // this is a similar loop as in dec_ack_frame() - keep changes in sync
    uint64_t lg_ack_in_block = meta(v).lg_acked;
    uint16_t i = meta(v).ack_block_pos;
    for (uint64_t n = meta(v).ack_block_cnt + 1; n > 0; n--) {
        uint64_t ack_block_len = 0;
        i = dec(&ack_block_len, v->buf, v->len, i, 0, "%" PRIu64);
        diet_remove_ival(&pn->recv, &(const struct ival){
                                        .lo = lg_ack_in_block - ack_block_len,
                                        .hi = lg_ack_in_block});
        if (n > 1) {
            uint64_t gap = 0;
            i = dec(&gap, v->buf, v->len, i, 0, "%" PRIu64);
            lg_ack_in_block = lg_ack_in_block - ack_block_len - gap - 2;
        }
    }

    adj_iov_to_data(v);
}


void on_pkt_sent(struct q_stream * const s, struct w_iov * const v)
{
    // see OnPacketSent() pseudo code

    meta(v).tx_t = ev_now(loop);

    struct q_conn * const c = s->c;
    struct pn_space * const pn = pn_for_epoch(c, strm_epoch(s));
    ensure(splay_insert(pm_by_nr, &pn->sent_pkts, &meta(v)) == 0, "inserted");

    if (likely(is_ack_eliciting(&meta(v).frames))) {
        if (unlikely(is_crypto_pkt(v)))
            // is_crypto_packet
            c->rec.last_sent_crypto_t = meta(v).tx_t;
        c->rec.last_sent_ack_elicit_t = meta(v).tx_t;
        c->rec.in_flight += meta(v).udp_len; // OnPacketSentCC
        c->rec.ae_in_flight++;
        log_cc(c);
        set_ld_timer(c);
    }
}


static void __attribute__((nonnull))
update_rtt(struct q_conn * const c, ev_tstamp ack_del)
{
    // see UpdateRtt() pseudo code

    c->rec.min_rtt = MIN(c->rec.min_rtt, c->rec.latest_rtt);
    ack_del = MIN(ack_del, c->tp_out.max_ack_del);

    if (c->rec.latest_rtt - c->rec.min_rtt > ack_del)
        c->rec.latest_rtt -= ack_del;

    if (unlikely(is_zero(c->rec.srtt))) {
        c->rec.srtt = c->rec.latest_rtt;
        c->rec.rttvar = c->rec.latest_rtt / 2;
    } else {
        const ev_tstamp rttvar_sample = fabs(c->rec.srtt - c->rec.latest_rtt);
        c->rec.rttvar = .75 * c->rec.rttvar + .25 * rttvar_sample;
        c->rec.srtt = .875 * c->rec.srtt + .125 * c->rec.latest_rtt;
    }
}


void on_ack_received_1(struct q_conn * const c,
                       struct pn_space * const pn,
                       struct w_iov * const lg_ack,
                       const uint64_t ack_del)
{
    // see OnAckReceived() pseudo code

    pn->lg_acked = MAX(pn->lg_acked, meta(lg_ack).hdr.nr);

    // we're only called for the largest ACK'ed
    if (is_ack_eliciting(&meta(lg_ack).frames)) {
        c->rec.latest_rtt = ev_now(loop) - meta(lg_ack).tx_t;
        update_rtt(c, ack_del / 1000000.0); // ack_del is passed in usec
    }

    // ProcessECN() is done in dec_ack_frame()
}


void on_ack_received_2(struct q_conn * const c, struct pn_space * const pn)
{
    // see OnAckReceived() pseudo code

    c->rec.crypto_cnt = c->rec.pto_cnt = 0;
    detect_lost_pkts(c, pn, true);
    set_ld_timer(c);

    // not part of pseudo code - causes TX to resume when the window opens

    if (has_wnd(c, c->w->mtu))
        c->needs_tx = true;
}


static void __attribute__((nonnull))
on_pkt_acked_cc(struct q_conn * const c, struct w_iov * const acked_pkt)
{
    // OnPacketAckedCC

    c->rec.in_flight -= meta(acked_pkt).udp_len;
    c->rec.ae_in_flight--;

    if (in_recovery(c, meta(acked_pkt).tx_t))
        return;

    if (c->rec.cwnd < c->rec.ssthresh)
        c->rec.cwnd += meta(acked_pkt).udp_len;
    else
        c->rec.cwnd += kMaxDatagramSize * meta(acked_pkt).udp_len / c->rec.cwnd;
}


void on_pkt_acked(struct q_conn * const c,
                  struct pn_space * const pn,
                  struct w_iov * const acked_pkt)
{
    // see OnPacketAcked() pseudo code
    if (is_ack_eliciting(&meta(acked_pkt).frames) &&
        meta(acked_pkt).is_lost == false)
        on_pkt_acked_cc(c, acked_pkt);

    diet_insert(&pn->acked, meta(acked_pkt).hdr.nr, ev_now(loop));
    ensure(splay_remove(pm_by_nr, &pn->sent_pkts, &meta(acked_pkt)), "removed");
    meta(acked_pkt).is_acked = true;

    // rest of function is not from pseudo code

    // if this ACK is for a pkt that was RTX'ed, update the record
    struct w_iov * orig = 0;
    if (meta(acked_pkt).is_rtx) {
        struct pkt_meta * const r = sl_first(&meta(acked_pkt).rtx);
        ensure(sl_next(r, rtx_next) == 0, "rtx chain corrupt");
        warn(DBG, FMT_PNR_OUT " was RTX'ed as " FMT_PNR_OUT,
             meta(acked_pkt).hdr.nr, r->hdr.nr);
        orig = w_iov(c->w, pm_idx(r));
    }

    struct q_stream * const s = meta(acked_pkt).stream;
    if (s && (orig == 0 || meta(orig).is_acked == false) &&
        s->out_una == (orig ? orig : acked_pkt)) {
        // if this ACKs its stream's out_una, move that forward
        sq_foreach_from (s->out_una, &s->out, next)
            if (meta(s->out_una).is_acked == false)
                break;

        if (s->out_una == 0) {
            // a q_write may be done
            maybe_api_return(q_write, c, s);
            if (s->id >= 0 && c->did_0rtt)
                maybe_api_return(q_connect, c, 0);
        }
    }

    if (s) {
        adj_iov_to_start(acked_pkt);
        if (unlikely(meta(acked_pkt).is_fin))
            // this ACKs a FIN
            maybe_api_return(q_close_stream, c, s);
        adj_iov_to_data(acked_pkt);
    }

    // stop ACKing packets that were contained in the ACK frame of this packet
    if (has_frame(acked_pkt, FRM_ACK))
        track_acked_pkts(pn, acked_pkt);

    if (!has_stream_data(&meta(acked_pkt)))
        free_iov(acked_pkt);
}


struct w_iov * find_sent_pkt(struct q_conn * const c,
                             struct pn_space * const pn,
                             const uint64_t nr)
{
    const struct pkt_meta which = {.hdr.nr = nr};
    const struct pkt_meta * const p =
        splay_find(pm_by_nr, &pn->sent_pkts, &which);
    return p ? w_iov(c->w, pm_idx(p)) : 0;
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
