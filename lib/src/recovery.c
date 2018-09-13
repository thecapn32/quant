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


static inline bool __attribute__((nonnull))
in_recovery(const struct q_conn * const c, const uint64_t nr)
{
    return nr <= c->rec.eor;
}


static inline bool __attribute__((nonnull))
hshk_pkts_outstanding(struct q_conn * const c)
{
    struct q_stream * const init_stream = get_stream(c, crpt_strm_id(ep_init));
    struct q_stream * const hshk_stream = get_stream(c, crpt_strm_id(ep_hshk));
    return out_fully_acked(init_stream) == false ||
           out_fully_acked(hshk_stream) == false; //||
}


static void __attribute__((nonnull)) set_ld_alarm(struct q_conn * const c)
{
    // don't arm the alarm if there are no packets with
    // retransmittable data in flight
    if (c->rec.in_flight == 0) {
        ev_timer_stop(loop, &c->rec.ld_alarm);
#ifndef FUZZING
        // warn(DBG, "no RTX-able pkts outstanding, stopping ld_alarm");
#endif
        return;
    }

    // assumption: "handshake packet" = contains CRYPTO frame
    if (hshk_pkts_outstanding(c)) {
        ev_tstamp to =
            2 * (is_zero(c->rec.srtt) ? kDefaultInitialRtt : c->rec.srtt);
        to = MAX(to + c->rec.max_ack_del, kMinTLPTimeout) *
             (1 << c->rec.hshake_cnt);
        c->rec.ld_alarm.repeat = ev_now(loop) - c->rec.last_sent_hshk_t + to;
        warn(DBG, "handshake RTX alarm in %f sec on %s conn %s",
             c->rec.ld_alarm.repeat, conn_type(c), scid2str(c));

    } else if (!is_zero(c->rec.loss_t)) {
        c->rec.ld_alarm.repeat = c->rec.loss_t - c->rec.last_sent_rtxable_t;
        warn(DBG, "early RTX or time alarm in %f sec on %s conn %s",
             c->rec.ld_alarm.repeat, conn_type(c), scid2str(c));

    } else {
        ev_tstamp to = c->rec.srtt + (4 * c->rec.rttvar) + c->rec.max_ack_del;
        to = MAX(to, kMinRTOTimeout);
        c->rec.ld_alarm.repeat = to * (1 << c->rec.rto_cnt);
        if (c->rec.tlp_cnt < kMaxTLPs) {
            const ev_tstamp tlp_to =
                MAX(1.5 * c->rec.srtt + c->rec.max_ack_del, kMinTLPTimeout);
            c->rec.ld_alarm.repeat = MIN(tlp_to, to);
            warn(DBG, "TLP alarm in %f sec on %s conn %s",
                 c->rec.ld_alarm.repeat, conn_type(c), scid2str(c));
        } else
            warn(DBG, "RTO alarm in %f sec on %s conn %s",
                 c->rec.ld_alarm.repeat, conn_type(c), scid2str(c));
    }

    ensure(c->rec.ld_alarm.repeat >= 0, "repeat %f", c->rec.ld_alarm.repeat);
    ev_timer_again(loop, &c->rec.ld_alarm);
}


static void __attribute__((nonnull))
detect_lost_pkts(struct q_conn * const c, struct pn_space * const pn)
{
    c->rec.loss_t = 0;
    ev_tstamp delay_until_lost = HUGE_VAL;

    if (pn->lg_acked == pn->lg_sent)
        // Early retransmit timer.
        delay_until_lost = 1.125 * MAX(c->rec.latest_rtt, c->rec.srtt);

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
            if (is_ack_only(p) == false) {
                c->rec.in_flight -= p->tx_len;
                warn(DBG, "in_flight -%u = %" PRIu64, p->tx_len,
                     c->rec.in_flight);
            }
            largest_lost_packet = MAX(largest_lost_packet, p->hdr.nr);

            if (p->is_rtx || !is_rtxable(p))
                q_free_iov(w_iov(c->w, pm_idx(p)));

        } else if (is_zero(c->rec.loss_t) && !is_inf(delay_until_lost))
            c->rec.loss_t = now + delay_until_lost - time_since_sent;
    }

    // CongestionEvent:
    // Start a new recovery epoch if the lost packet is larger
    // than the end of the previous recovery epoch.
    if (!in_recovery(c, largest_lost_packet)) {
        c->rec.eor = pn->lg_sent;
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
    bool did_tx = false;

    // see OnLossDetectionAlarm pseudo code
    if (hshk_pkts_outstanding(c)) {
        warn(DBG, "handshake RTX #%u on %s conn %s", c->rec.hshake_cnt + 1,
             conn_type(c), scid2str(c));
        tx(c, true, 0);
        did_tx = true;
        c->rec.hshake_cnt++;

    } else if (!is_zero(c->rec.loss_t)) {
        warn(DBG, "early RTX or time loss detection alarm on %s conn %s",
             conn_type(c), scid2str(c));
        struct pn_space * const pn = pn_for_epoch(c, c->tls.epoch_out);
        detect_lost_pkts(c, pn);

    } else if (c->rec.tlp_cnt < kMaxTLPs) {
        warn(DBG, "TLP alarm #%u on %s conn %s", c->rec.tlp_cnt, conn_type(c),
             scid2str(c));
        tx(c, true, 1); // XXX is this an RTX or not?
        did_tx = true;
        c->rec.tlp_cnt++;

    } else {
        warn(DBG, "RTO alarm #%u on %s conn %s", c->rec.rto_cnt, conn_type(c),
             scid2str(c));
        if (c->rec.rto_cnt == 0) {
            struct pn_space * const pn = pn_for_epoch(c, c->tls.epoch_out);
            pn->lg_sent_before_rto = pn->lg_sent;
        }
        tx(c, true, 2); // XXX is this an RTX or not?
        did_tx = true;
        c->rec.rto_cnt++;
    }

    // XXX is in the pseudo code, but it's already also called in  on_pkt_sent()
    if (did_tx == false)
        // set_ld_alarm is also called in on_pkt_sent, avoid duplicate
        set_ld_alarm(c);
}


static inline void __attribute__((nonnull))
track_acked_pkts(struct q_conn * const c __attribute__((unused)),
                 struct pn_space * const pn,
                 const uint64_t ack)
{
    diet_remove(&pn->recv, ack);
}


void on_pkt_sent(struct q_stream * const s, struct w_iov * const v)
{
    // these are updated in enc_pkt():
    // * largest_sent_packet
    // * sent_packets[packet_number].packet_number
    // * sent_packets[packet_number].bytes
    //
    // these we maintain via the frames bitstr_t in pkt_meta:
    // * sent_packets[packet_number].ack_only

    meta(v).tx_t = ev_now(loop);
    struct pn_space * const pn = pn_for_epoch(s->c, strm_epoch(s));
    splay_insert(pm_nr_splay, &pn->sent_pkts, &meta(v));

    if (likely(s->c->state != conn_idle) && is_ack_only(&meta(v)) == false) {
        if (bit_test(meta(v).frames, FRAM_TYPE_CRPT))
            // is_handshake_packet
            s->c->rec.last_sent_hshk_t = meta(v).tx_t;
        s->c->rec.last_sent_rtxable_t = meta(v).tx_t;

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
    if (likely(pn->lg_acked != UINT64_MAX) && pn->lg_acked >= ack)
        return;

    pn->lg_acked = ack;
    struct w_iov * const v = find_sent_pkt(c, pn, ack);
    if (v == 0) {
#ifndef FUZZING
        if (diet_find(&pn->acked, ack) == 0)
            warn(ERR, "got ACK for pkt " FMT_PNR_OUT " never sent", ack);
#endif
        return;
    }
    c->rec.latest_rtt = ev_now(loop) - meta(v).tx_t;

    // UpdateRtt follows:

    // min_rtt ignores ack delay
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
    if (unlikely(is_zero(c->rec.srtt))) {
        c->rec.srtt = c->rec.latest_rtt;
        c->rec.rttvar = c->rec.latest_rtt / 2;
    } else {
        const ev_tstamp rttvar_sample = fabs(c->rec.srtt - c->rec.latest_rtt);
        c->rec.rttvar = .75 * c->rec.rttvar + .25 * rttvar_sample;
        c->rec.srtt = .875 * c->rec.srtt + .125 * c->rec.latest_rtt;
    }
    warn(DBG, "srtt = %f, rttvar = %f on %s conn %s", c->rec.srtt,
         c->rec.rttvar, conn_type(c), scid2str(c));

    // if this ACK'ed a CLOSE frame, move to conn_drng
    if (c->state == conn_clsg &&
        (bit_test(meta(v).frames, FRAM_TYPE_CONN_CLSE) ||
         bit_test(meta(v).frames, FRAM_TYPE_APPL_CLSE)))
        conn_to_state(c, conn_drng);
}


void on_ack_rx_2(struct q_conn * const c, struct pn_space * const pn)
{
    detect_lost_pkts(c, pn);
    set_ld_alarm(c);
    // TODO: ProcessECN(ack)
}


static void on_pkt_acked_cc(struct q_conn * const c, struct w_iov * const v)
{
    c->rec.in_flight -= meta(v).tx_len;
    warn(DBG, "in_flight -%u = %" PRIu64, meta(v).tx_len, c->rec.in_flight);

    if (in_recovery(c, meta(v).hdr.nr))
        return;

    if (c->rec.cwnd < c->rec.ssthresh)
        // slow start
        c->rec.cwnd += meta(v).tx_len;
    else
        // congestion avoidance
        c->rec.cwnd += kMaxDatagramSize * meta(v).tx_len / c->rec.cwnd;
    warn(DBG, "cwnd %" PRIu64, c->rec.cwnd);
}


// #define DEBUG_ACK_PARSING

void on_pkt_acked(struct q_conn * const c,
                  struct pn_space * const pn,
                  const uint64_t ack)
{
    struct w_iov * const v = find_sent_pkt(c, pn, ack);
    if (v == 0) {
#ifndef FUZZING
        if (diet_find(&pn->acked, ack) == 0)
            warn(ERR, "got ACK for pkt " FMT_PNR_OUT " never sent", ack);
#endif
        return;
    }

    // only act on first-time ACKs
    if (meta(v).is_acked) {
        warn(WRN, "repeated ACK for " FMT_PNR_OUT ", ignoring", ack);
        return;
    }
    warn(DBG, "first ACK for " FMT_PNR_OUT, ack);


    if (is_ack_only(&meta(v)) == false)
        on_pkt_acked_cc(c, v);

    // If a packet sent prior to RTO was ACKed, then the RTO was spurious.
    // Otherwise, inform congestion control.
    if (c->rec.rto_cnt > 0 && ack > pn->lg_sent_before_rto) {
        // OnRetransmissionTimeoutVerified
        c->rec.cwnd = kMinimumWindow;
        warn(DBG, "cwnd %u", c->rec.cwnd);
        // Declare all packets prior to packet_number lost.

        for (struct pkt_meta * p = splay_min(pm_nr_splay, &pn->sent_pkts);
             p && p->hdr.nr < ack;
             p = splay_next(pm_nr_splay, &pn->sent_pkts, p)) {
            warn(DBG, "pkt " FMT_PNR_OUT " considered lost", p->hdr.nr);
            p->is_lost = true;
            c->rec.in_flight -= p->tx_len;
            warn(DBG, "in_flight -%u = %" PRIu64, p->tx_len, c->rec.in_flight);
        }
    }

    c->rec.hshake_cnt = c->rec.tlp_cnt = c->rec.rto_cnt = 0;
    diet_insert(&pn->acked, ack, ev_now(loop));
    splay_remove(pm_nr_splay, &pn->sent_pkts, &meta(v));

    // rest of function is not from pseudo code

    // if this ACK is for a pkt that was RTX'ed, update the record
    struct w_iov * orig_v = v;
    if (meta(v).is_rtx) {
        meta(v).is_acked = true;
        struct pkt_meta * const r = sl_first(&meta(v).rtx);
        ensure(sl_next(r, rtx_next) == 0, "rtx chain corrupt");
        warn(DBG, FMT_PNR_OUT " was RTX'ed as " FMT_PNR_OUT, meta(v).hdr.nr,
             r->hdr.nr);
        orig_v = w_iov(c->w, pm_idx(r));
    }

    struct q_stream * const s = meta(orig_v).stream;
    if (s && meta(orig_v).is_acked == false) {
        s->out_ack_cnt++;
        warn(DBG, "stream " FMT_SID " ACK cnt %u, len %u %s", s->id,
             s->out_ack_cnt, sq_len(&s->out),
             out_fully_acked(s) ? "(fully acked)" : "");

        if (out_fully_acked(s)) {
            // a q_write may be done
            maybe_api_return(q_write, s->c, s);
            if (s->id >= 0 && s->c->did_0rtt)
                maybe_api_return(q_connect, s->c, 0);
        }
    }
    meta(orig_v).is_acked = true;

    if (s) {
        adj_iov_to_start(v);
        if (is_fin(v))
            // this ACKs a FIN
            maybe_api_return(q_close_stream, s->c, s);
        adj_iov_to_data(v);
    }

    // stop ACKing packets that were contained in the ACK frame of this packet
    if (meta(v).ack_header_pos) {
#ifndef NDEBUG
        const short l = util_dlevel;
#ifdef DEBUG_ACK_PARSING
        warn(DBG, "decoding ACK info from pkt " FMT_PNR_OUT " from pos %u", ack,
             meta(v).ack_header_pos);
        // temporarily suppress debug output
        util_dlevel = util_dlevel == DBG ? DBG : WRN;
#else
        util_dlevel = WRN;
#endif
#endif
        adj_iov_to_start(v);
        dec_ack_frame(c, v, meta(v).ack_header_pos, 0, &track_acked_pkts, 0,
                      true);
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

    if (!is_rtxable(&meta(orig_v)))
        q_free_iov(orig_v);
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
    c->rec.min_rtt = HUGE_VAL;

    c->rec.ld_alarm.data = c;
    ev_init(&c->rec.ld_alarm, on_ld_alarm);

    c->rec.reorder_thresh = kReorderingThreshold;
    c->rec.cwnd = kInitialWindow;
    c->rec.ssthresh = UINT64_MAX;
}
