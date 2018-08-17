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

#include <bitstring.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/param.h>

#include <ev.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "frame.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"
#include "tls.h"


struct ev_loop;


uint32_t rtxable_pkts_outstanding(struct q_conn * const c)
{
    uint32_t cnt = 0;
    struct pkt_meta * p;
    struct pn_space * const pn = pn_for_epoch(c, c->tls.epoch_out);
    splay_foreach (p, pm_nr_splay, &pn->sent_pkts)
        if (is_rtxable(p) && !p->is_acked)
            cnt++;
    return cnt;
}


static void __attribute__((nonnull)) set_ld_alarm(struct q_conn * const c)
{
    const uint32_t rtxable_outstanding = rtxable_pkts_outstanding(c);
    // don't arm the alarm if there are no packets with
    // retransmittable data in flight
    if (rtxable_outstanding == 0) {
        ev_timer_stop(loop, &c->rec.ld_alarm);
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        warn(DBG, "no RTX-able pkts outstanding, stopping ld_alarm");
#endif
        return;
    }

    ev_tstamp dur = 0;
    if (c->state != established) {
        dur = is_zero(c->rec.srtt) ? kDefaultInitialRtt : c->rec.srtt;
        dur = MAX(2 * dur, kMinTLPTimeout) * (1 << c->rec.hshake_cnt);
        warn(DBG, "handshake RTX alarm in %f sec on %s conn %s", dur,
             conn_type(c), scid2str(c));

    } else if (!is_zero(c->rec.loss_t)) {
        dur = c->rec.loss_t - c->rec.last_sent_t;
        warn(DBG, "early RTX or time alarm in %f sec on %s conn %s", dur,
             conn_type(c), scid2str(c));

        // XXX TLP is much too aggressive on server, due to artificially low
        // initial RTT (since it's not measured during the handshake yet)

        // } else if (c->rec.tlp_cnt < kMaxTLPs) {
        //     dur = MAX(1.5 * c->rec.srtt + c->rec.max_ack_del,
        //     kMinTLPTimeout); warn(DBG, "TLP alarm in %f sec on %s conn "
        //     FMT_CID, dur, conn_type(c),
        //          scid2str(c));

    } else {
        dur = c->rec.srtt + 4 * c->rec.rttvar;
        dur = MAX(dur, kMinRTOTimeout);
        dur *= (1 << c->rec.rto_cnt);
        warn(DBG, "RTO alarm in %f sec on %s conn %s", dur, conn_type(c),
             scid2str(c));
    }

    c->rec.ld_alarm.repeat = c->rec.last_sent_t + dur - ev_now(loop);
    ensure(c->rec.ld_alarm.repeat >= 0, "repeat %f", c->rec.ld_alarm.repeat);
    ev_timer_again(loop, &c->rec.ld_alarm);
}


static void __attribute__((nonnull))
detect_lost_pkts(struct q_conn * const c, struct pn_space * const pn)
{
    c->rec.loss_t = 0;
    ev_tstamp delay_until_lost = HUGE_VAL;
    if (!is_inf(c->rec.reorder_fract))
        delay_until_lost =
            (1 + c->rec.reorder_fract) * MAX(c->rec.latest_rtt, c->rec.srtt);
    else if (pn->lg_acked == pn->lg_sent)
        // Early retransmit alarm.
        delay_until_lost = 1.25 * MAX(c->rec.latest_rtt, c->rec.srtt);

    const ev_tstamp now = ev_now(loop);
    uint64_t largest_lost_packet = 0;
    struct pkt_meta *p, *nxt;

    for (p = splay_min(pm_nr_splay, &pn->sent_pkts);
         p && p->hdr.nr < pn->lg_acked; p = nxt) {
        nxt = splay_next(pm_nr_splay, &pn->sent_pkts, p);

        if (p->is_acked || p->is_lost)
            continue;

        const ev_tstamp time_since_sent = now - p->tx_t;
        const uint64_t delta = pn->lg_acked - p->hdr.nr;

        // warn(DBG,
        //      "pkt %" PRIu64
        //      ": time_since_sent %f > delay_until_lost %f || delta %" PRIu64
        //      " > c->rec.reorder_thresh %" PRIu64,
        //      p->hdr.nr, time_since_sent, delay_until_lost, delta,
        //      c->rec.reorder_thresh);

        if (time_since_sent > delay_until_lost ||
            delta > c->rec.reorder_thresh) {
            warn(WRN, "pkt " FMT_PNR_OUT " considered lost", p->hdr.nr);
            p->is_lost = true;

            // OnPacketsLost:
            if (is_rtxable(p)) {
                c->rec.in_flight -= p->tx_len;
                warn(DBG, "in_flight -%u = %" PRIu64, p->tx_len,
                     c->rec.in_flight);
            }

            largest_lost_packet = MAX(largest_lost_packet, p->hdr.nr);

            if (p->is_rtxed || !is_rtxable(p)) {
                warn(DBG, "free already-rtxed/non-rtxable pkt " FMT_PNR_OUT,
                     p->hdr.nr);
                splay_remove(pm_nr_splay, &pn->sent_pkts, p);
                q_free_iov(w_iov(c->w, pm_idx(p)));
            }

        } else if (is_zero(c->rec.loss_t) && !is_inf(delay_until_lost))
            c->rec.loss_t = now + delay_until_lost - time_since_sent;
    }

    // Start a new recovery epoch if the lost packet is larger
    // than the end of the previous recovery epoch.
    if (c->rec.rec_end < largest_lost_packet) {
        c->rec.rec_end = pn->lg_sent;
        c->rec.cwnd *= kLossReductionFactor;
        c->rec.cwnd = MAX(c->rec.cwnd, kMinimumWindow);
        c->rec.ssthresh = c->rec.cwnd;
        warn(DBG, "cwnd %" PRIu64 ", ssthresh %" PRIu64, c->rec.cwnd,
             c->rec.ssthresh);
    }
}


static void __attribute__((nonnull))
on_ld_alarm(struct ev_loop * const l __attribute__((unused)),
            ev_timer * const w,
            int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;

    // see OnLossDetectionAlarm pseudo code
    if (c->state != established) {
        c->rec.hshake_cnt++;
        warn(DBG, "handshake RTX #%u on %s conn %s", c->rec.hshake_cnt,
             conn_type(c), scid2str(c));
        tx(c, true, 0);

    } else if (!is_zero(c->rec.loss_t)) {
        warn(DBG, "early RTX or time loss detection alarm on %s conn %s",
             conn_type(c), scid2str(c));
        struct pn_space * const pn = pn_for_epoch(c, c->tls.epoch_out);
        detect_lost_pkts(c, pn);

        // } else if (c->rec.tlp_cnt < kMaxTLPs) {
        //     warn(DBG, "TLP alarm #%u on %s conn %s", c->rec.tlp_cnt,
        //          conn_type(c), scid2str(c));
        //     tx(c, true, 1); // XXX is this an RTX or not?
        //     c->rec.tlp_cnt++;

    } else {
        warn(DBG, "RTO alarm #%u on %s conn %s", c->rec.rto_cnt, conn_type(c),
             scid2str(c));
        if (c->rec.rto_cnt == 0) {
            struct pn_space * const pn = pn_for_epoch(c, c->tls.epoch_out);
            pn->lg_sent_before_rto = pn->lg_sent;
        }
        tx(c, true, 2); // XXX is this an RTX or not?
        c->rec.rto_cnt++;
    }

    // XXX is in the pseudo code, but it's already also called in  on_pkt_sent()
    // set_ld_alarm(c);
}


static void __attribute__((nonnull))
track_acked_pkts(struct q_conn * const c __attribute__((unused)),
                 struct pn_space * const pn,
                 const uint64_t ack,
                 const uint8_t flags __attribute__((unused)))
{
    diet_remove(&pn->recv, ack);
}


void on_pkt_sent(struct q_stream * const s, struct w_iov * const v)
{
    // sent_packets[packet_number] updated in enc_pkt()
    const ev_tstamp now = ev_now(loop);

    s->c->rec.last_sent_t = meta(v).tx_t = now;
    if (s->c->state != serv_tx_vneg) {
        // don't track version negotiation responses
        struct pn_space * const pn = pn_for_epoch(s->c, strm_epoch(s->id));
        splay_insert(pm_nr_splay, &pn->sent_pkts, &meta(v));
    }

    if (is_rtxable(&meta(v))) {
        s->c->rec.in_flight += meta(v).tx_len; // OnPacketSentCC
        warn(DBG, "in_flight +%u = %" PRIu64, meta(v).tx_len,
             s->c->rec.in_flight);
        set_ld_alarm(s->c);
    }
}


void on_ack_rx_1(struct q_conn * const c,
                 struct pn_space * const pn,
                 const uint64_t ack,
                 const uint64_t ack_del)
{
    // if the largest ACKed is newly ACKed, update the RTT
    if (pn->lg_acked >= ack)
        return;

    pn->lg_acked = ack;
    struct w_iov * const v = find_sent_pkt(c, pn, ack);
    if (v == 0) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        if (diet_find(&pn->acked, ack) == 0)
            warn(ERR, "got ACK for pkt " FMT_PNR_OUT " never sent", ack);
#endif
        return;
    }
    c->rec.latest_rtt = ev_now(loop) - meta(v).tx_t;

    // UpdateRtt

    // min_rtt ignores ack delay
    if (unlikely(is_zero(c->rec.min_rtt)))
        c->rec.min_rtt = c->rec.latest_rtt;
    else
        c->rec.min_rtt = MIN(c->rec.min_rtt, c->rec.latest_rtt);

    // adjust for ack delay if it's plausible
    if (c->rec.latest_rtt - c->rec.min_rtt > ack_del) {
        c->rec.latest_rtt -= ack_del;
        warn(DBG, "latest_rtt %f", c->rec.latest_rtt);

        // only save into max ack delay if it's used
        // for rtt calculation and is not ack only
        if (!is_ack_only(&meta(v)))
            c->rec.max_ack_del = MAX(c->rec.max_ack_del, ack_del);
    }

    // based on RFC6298
    if (is_zero(c->rec.srtt)) {
        c->rec.srtt = c->rec.latest_rtt;
        c->rec.rttvar = c->rec.latest_rtt / 2;
    } else {
        const ev_tstamp rttvar_sample = fabs(c->rec.srtt - c->rec.latest_rtt);
        c->rec.rttvar = .75 * c->rec.rttvar + .25 * rttvar_sample;
        c->rec.srtt = .875 * c->rec.srtt + .125 * c->rec.latest_rtt;
    }
    warn(DBG, "srtt = %f, rttvar = %f on %s conn %s", c->rec.srtt,
         c->rec.rttvar, conn_type(c), scid2str(c));

    // if this ACK'ed a CLOSE frame, move to draining
    if (c->state == closing && (bit_test(meta(v).frames, FRAM_TYPE_CONN_CLSE) ||
                                bit_test(meta(v).frames, FRAM_TYPE_APPL_CLSE)))
        conn_to_state(c, draining);
}


void on_ack_rx_2(struct q_conn * const c, struct pn_space * const pn)
{
    detect_lost_pkts(c, pn);
    set_ld_alarm(c);
}


// #define DEBUG_ACK_PARSING

void on_pkt_acked(struct q_conn * const c,
                  struct pn_space * const pn,
                  const uint64_t ack,
                  const uint8_t flags)
{
    struct w_iov * const v = find_sent_pkt(c, pn, ack);
    if (v == 0) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        if (diet_find(&pn->acked, ack) == 0)
            warn(ERR, "got ACK for pkt " FMT_PNR_OUT " never sent", ack);
#endif
        return;
    }

    adj_iov_to_start(v);
    adj_iov_to_data(v);
    if (!better_or_equal_prot(flags, meta(v).hdr.flags)) {
        warn(ERR,
             "0x%02x-type pkt has ACK for 0x%02x-type pkt " FMT_PNR_OUT
             ", ignoring",
             flags, meta(v).hdr.flags, ack);
        return;
    }

    // only act on first-time ACKs
    if (meta(v).is_acked) {
        warn(WRN, "repeated ACK for " FMT_PNR_OUT ", ignoring", ack);
        return;
    }
    warn(DBG, "first ACK for " FMT_PNR_OUT, ack);

    // If a packet sent prior to RTO was ACKed, then the RTO was spurious.
    // Otherwise, inform congestion control.
    if (c->rec.rto_cnt > 0 && ack > pn->lg_sent_before_rto) {
        c->rec.cwnd = kMinimumWindow; // OnRetransmissionTimeoutVerified
        warn(DBG, "cwnd %u", c->rec.cwnd);
    }
    c->rec.hshake_cnt = c->rec.tlp_cnt = c->rec.rto_cnt = 0;
    diet_insert(&pn->acked, ack, 0, ev_now(loop));
    splay_remove(pm_nr_splay, &pn->sent_pkts, &meta(v));

    // if this pkt was since RTX'ed, update the record
    struct w_iov * r = v;
    while (meta(r).is_rtxed) {
        warn(DBG, FMT_PNR_OUT " was RTX'ed as " FMT_PNR_OUT, meta(r).hdr.nr,
             meta(r).rtx->hdr.nr);
        diet_insert(&pn->acked, meta(r).rtx->hdr.nr, 0, ev_now(loop));
        splay_remove(pm_nr_splay, &pn->sent_pkts, meta(r).rtx);
        r = w_iov(c->w, pm_idx(meta(r).rtx));
    }

    // stop ACKing packets that were contained in the ACK frame of this packet
    if (meta(v).ack_header_pos) {
#ifndef NDEBUG
        const short l = util_dlevel;
#ifdef DEBUG_ACK_PARSING
        warn(DBG, "decoding ACK info from pkt " FMT_PNR_OUT " from pos %u", ack,
             meta(v).ack_header_pos);
        // temporarily suppress debug output
        util_dlevel = util_dlevel == DBG ? DBG : 0;
#else
        util_dlevel = 0;
#endif
#endif
        adj_iov_to_start(v);
        dec_ack_frame(c, v, meta(v).ack_header_pos, 0, &track_acked_pkts, 0);
        adj_iov_to_data(v);
#ifndef NDEBUG
        util_dlevel = l;
#ifdef DEBUG_ACK_PARSING
        warn(DBG, "done decoding ACK info from pkt " FMT_PNR_OUT " from pos %u",
             ack, meta(v).ack_header_pos);
#endif
#endif
    }
#ifndef NDEBUG
#ifdef DEBUG_ACK_PARSING
    else
        warn(DBG, "pkt " FMT_PNR_OUT " did not contain an ACK frame", ack);
#endif
#endif
    // OnPacketAckedCC
    if (is_rtxable(&meta(v)) && meta(v).is_lost == false) {
        c->rec.in_flight -= meta(v).tx_len;
        warn(DBG, "in_flight -%u = %" PRIu64, meta(v).tx_len, c->rec.in_flight);
    }

    if (ack >= c->rec.rec_end) {
        if (c->rec.cwnd < c->rec.ssthresh)
            c->rec.cwnd += meta(v).tx_len;
        else
            c->rec.cwnd += kDefaultMss * meta(v).tx_len / c->rec.cwnd;
        warn(DBG, "cwnd %" PRIu64, c->rec.cwnd);
    }

    struct pkt_meta * const p = meta(v).rtx ? meta(v).rtx : &meta(v);
    struct q_stream * const s = p->stream;
    if (p->is_acked == false && s) {
        p->is_acked = true;
        s->out_ack_cnt++;
        warn(DBG, "stream " FMT_SID " ACK cnt %u, len %u", s->id,
             s->out_ack_cnt, sq_len(&s->out));

        if (is_fully_acked(s)) {
            // a q_write may be done
            // warn(CRT, "fully acked");
            maybe_api_return(q_write, s->c, s);
            if (s->id && s->c->did_0rtt)
                maybe_api_return(q_connect, s->c, 0);
        }
    }
    meta(v).is_acked = true;

    if (!is_rtxable(&meta(v)))
        q_free_iov(v);
}


struct w_iov * find_sent_pkt(struct q_conn * const c,
                             struct pn_space * const pn,
                             const uint64_t nr)
{
    const struct pkt_meta which = {.hdr.nr = nr};
    const struct pkt_meta * const p =
        splay_find(pm_nr_splay, &pn->sent_pkts, &which);
    return p ? w_iov(c->w, pm_idx(p)) : 0;
}


void init_rec(struct q_conn * const c)
{
    // we don't need to init variables to zero

    c->rec.ld_alarm.data = c;
    ev_init(&c->rec.ld_alarm, on_ld_alarm);

    if (c->use_time_loss_det) {
        c->rec.reorder_thresh = UINT64_MAX;
        c->rec.reorder_fract = kTimeReorderingFraction;
    } else {
        c->rec.reorder_thresh = kReorderingThreshold;
        c->rec.reorder_fract = HUGE_VAL;
    }

    c->rec.cwnd = kInitialWindow;
    c->rec.ssthresh = UINT64_MAX;
}
