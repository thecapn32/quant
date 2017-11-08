// Copyright (c) 2016-2017, NetApp, Inc.
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
#include "quic.h"
#include "recovery.h"
#include "stream.h"


struct ev_loop;


static bool __attribute__((nonnull))
no_rtxable_pkts_outstanding(struct q_conn * const c)
{
    struct pkt_meta * p;
    splay_foreach (p, pm_nr_splay, &c->rec.sent_pkts)
        if (p->is_rtxable && !p->is_acked)
            return false;
    return true;
}


static bool __attribute__((nonnull))
one_rtxable_pkt_outstanding(struct q_conn * const c)
{
    struct pkt_meta * p;
    return (p = splay_min(pm_nr_splay, &c->rec.sent_pkts)) &&
           splay_next(pm_nr_splay, &c->rec.sent_pkts, p);
}


static void __attribute__((nonnull)) detect_lost_pkts(struct q_conn * const c)
{
    c->rec.loss_t = 0;
    ev_tstamp delay_until_lost = HUGE_VAL;
    if (!is_inf(c->rec.reorder_fract))
        delay_until_lost =
            (1 + c->rec.reorder_fract) * MAX(c->rec.latest_rtt, c->rec.srtt);
    else if (c->rec.lg_acked == c->rec.lg_sent)
        // Early retransmit alarm.
        delay_until_lost = 1.125 * MAX(c->rec.latest_rtt, c->rec.srtt);

    const ev_tstamp now = ev_now(loop);
    uint64_t largest_lost_packet = 0;
    struct pkt_meta *p, *nxt;

    for (p = splay_min(pm_nr_splay, &c->rec.sent_pkts);
         p && p->nr < c->rec.lg_acked; p = nxt) {
        nxt = splay_next(pm_nr_splay, &c->rec.sent_pkts, p);

        if (p->is_acked)
            continue;

        const ev_tstamp time_since_sent = now - p->tx_t;
        const uint64_t delta = c->rec.lg_acked - p->nr;

        // warn(INF,
        //      "pkt %" PRIu64
        //      ": time_since_sent %f > delay_until_lost %f || delta %" PRIu64
        //      " > c->rec.reorder_thresh %" PRIu64,
        //      p->nr, time_since_sent, delay_until_lost, delta,
        //      c->rec.reorder_thresh);

        if (time_since_sent > delay_until_lost ||
            delta > c->rec.reorder_thresh) {
            warn(WRN, "pkt %" PRIu64 " considered lost", p->nr);

            // OnPacketsLost:
            if (p->is_rtxable) {
                c->rec.in_flight -= p->tx_len;
                warn(INF, "in_flight -%u = %" PRIu64, p->tx_len,
                     c->rec.in_flight);
            }

            largest_lost_packet = MAX(largest_lost_packet, p->nr);

            if (p->is_rtxed || !p->is_rtxable) {
                warn(DBG, "free rtxed/non-rtxable pkt %" PRIu64, p->nr);
                splay_remove(pm_nr_splay, &c->rec.sent_pkts, p);
                q_free_iov(w_engine(c->sock),
                           w_iov(w_engine(c->sock), w_iov_idx(p)));
            } else {
                warn(DBG, "mark non-rtxed pkt %" PRIu64, p->nr);
                p->tx_len = 0;
            }


        } else if (is_zero(c->rec.loss_t) && !is_inf(delay_until_lost))
            c->rec.loss_t = now + delay_until_lost - time_since_sent;
    }

    // Start a new recovery epoch if the lost packet is larger
    // than the end of the previous recovery epoch.
    if (c->rec.rec_end < largest_lost_packet) {
        c->rec.rec_end = c->rec.lg_sent;
        c->rec.cwnd *= kLossReductionFactor;
        c->rec.cwnd = MAX(c->rec.cwnd, kMinimumWindow);
        c->rec.ssthresh = c->rec.cwnd;
        warn(INF, "cwnd %" PRIu64 ", ssthresh %" PRIu64, c->rec.cwnd,
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
    if (c->state < CONN_STAT_ESTB) {
        c->rec.hshake_cnt++;
        warn(INF, "handshake RTX #%u on %s conn %" PRIx64, c->rec.hshake_cnt,
             conn_type(c), c->id);
        tx(c, true, 0);

    } else if (!is_zero(c->rec.loss_t)) {
        warn(INF, "early RTX or time loss detection alarm on %s conn %" PRIx64,
             conn_type(c), c->id);
        detect_lost_pkts(c);

    } else if (c->rec.tlp_cnt < kMaxTLPs) {
        warn(INF, "TLP alarm #%u on %s conn %" PRIx64, c->rec.tlp_cnt,
             conn_type(c), c->id);
        tx(c, true, 1); // XXX is this an RTX or not?
        c->rec.tlp_cnt++;

    } else {
        warn(INF, "RTO alarm #%u on %s conn %" PRIx64, c->rec.rto_cnt,
             conn_type(c), c->id);
        if (c->rec.rto_cnt == 0)
            c->rec.lg_sent_before_rto = c->rec.lg_sent;
        tx(c, true, 2);
        c->rec.rto_cnt++; // XXX is this an RTX or not?
    }

    set_ld_alarm(c);
}


static void __attribute__((nonnull))
track_acked_pkts(struct q_conn * const c, const uint64_t ack)
{
    diet_remove(&c->recv, ack);
}


static void __attribute__((nonnull)) update_rtt(struct q_conn * const c)
{
    if (is_zero(c->rec.srtt)) {
        c->rec.srtt = c->rec.latest_rtt;
        c->rec.rttvar = c->rec.latest_rtt / 2;
    } else {
        c->rec.rttvar =
            .75 * c->rec.rttvar + .25 * fabs(c->rec.srtt - c->rec.latest_rtt);
        c->rec.srtt = .875 * c->rec.srtt + .125 * c->rec.latest_rtt;
    }
    warn(INF, "srtt = %f, rttvar = %f on %s conn %" PRIx64, c->rec.srtt,
         c->rec.rttvar, conn_type(c), c->id);
}


void on_pkt_sent(struct q_conn * const c, struct w_iov * const v)
{
    // sent_packets[packet_number] updated in enc_pkt()
    const ev_tstamp now = ev_now(loop);

    /* c->rec.last_sent_t = */ meta(v).tx_t = now;
    if (c->state != CONN_STAT_VERS_REJ)
        // don't track version negotiation responses
        splay_insert(pm_nr_splay, &c->rec.sent_pkts, &meta(v));

    if (meta(v).is_rtxable) {
        c->rec.in_flight += meta(v).tx_len; // OnPacketSentCC
        warn(INF, "in_flight +%u = %" PRIu64, meta(v).tx_len, c->rec.in_flight);
        set_ld_alarm(c);
    }
}


void on_ack_rx_1(struct q_conn * const c,
                 const uint64_t ack,
                 const uint16_t ack_delay)
{
    // if the largest ACKed is newly ACKed, update the RTT
    if (c->rec.lg_acked >= ack)
        return;

    c->rec.lg_acked = ack;
    struct w_iov * const v = find_sent_pkt(c, ack);
    ensure(v, "found ACKed pkt %" PRIu64, ack);
    c->rec.latest_rtt = ev_now(loop) - meta(v).tx_t;
    if (c->rec.latest_rtt > ack_delay)
        c->rec.latest_rtt -= ack_delay;
    warn(INF, "latest_rtt %f", c->rec.latest_rtt);
    update_rtt(c);
}


void on_ack_rx_2(struct q_conn * const c)
{
    detect_lost_pkts(c);
    set_ld_alarm(c);
}


void on_pkt_acked(struct q_conn * const c, const uint64_t ack)
{
    struct w_iov * const v = find_sent_pkt(c, ack);
    if (!v) {
        warn(DBG, "got ACK for pkt %" PRIu64 " with no metadata", ack);
        return;
    }

    // only act on first-time ACKs
    if (meta(v).is_acked)
        warn(WRN, "repeated ACK for %" PRIu64, ack);
    else
        warn(NTE, "first ACK for %" PRIu64, ack);
    meta(v).is_acked = true;

    // If a packet sent prior to RTO was ACKed, then the RTO was spurious.
    // Otherwise, inform congestion control.
    if (c->rec.rto_cnt > 0 && ack > c->rec.lg_sent_before_rto) {
        c->rec.cwnd = kMinimumWindow; // OnRetransmissionTimeoutVerified
        warn(INF, "cwnd %u", c->rec.cwnd);
    }
    c->rec.hshake_cnt = c->rec.tlp_cnt = c->rec.rto_cnt = 0;
    splay_remove(pm_nr_splay, &c->rec.sent_pkts, &meta(v));

    if (no_rtxable_pkts_outstanding(c))
        maybe_api_return(q_close, c);

    // stop ACKing packets that were contained in the ACK frame of this
    // packet
    if (meta(v).ack_header_pos) {
        warn(DBG, "decoding ACK info from pkt %" PRIu64 " from pos %u", ack,
             meta(v).ack_header_pos);
        adj_iov_to_start(v);
        dec_ack_frame(c, v, meta(v).ack_header_pos, 0, &track_acked_pkts, 0);
        adj_iov_to_data(v);
        warn(DBG, "done decoding ACK info from pkt %" PRIu64 " from pos %u",
             ack, meta(v).ack_header_pos);
    } else
        warn(DBG, "pkt %" PRIu64 " did not contain an ACK frame", ack);

    // OnPacketAckedCC
    if (meta(v).is_rtxable) {
        c->rec.in_flight -= meta(v).tx_len;
        warn(INF, "in_flight -%u = %" PRIu64, meta(v).tx_len, c->rec.in_flight);
    }

    if (ack >= c->rec.rec_end) {
        if (c->rec.cwnd < c->rec.ssthresh)
            c->rec.cwnd += meta(v).tx_len;
        else
            c->rec.cwnd += kDefaultMss * meta(v).tx_len / c->rec.cwnd;
        warn(INF, "cwnd %" PRIu64, c->rec.cwnd);
    }

    // check if a q_write is done
    if (meta(v).is_rtxed == false) {
        struct q_stream * const s = meta(v).str;
        if (s && ++s->out_ack_cnt == sq_len(&s->out))
            // all packets are ACKed
            maybe_api_return(q_write, s);
    }
}


void set_ld_alarm(struct q_conn * const c)
{
    if (no_rtxable_pkts_outstanding(c)) {
        // retransmittable packets are not outstanding
        if (ev_is_active(&c->rec.ld_alarm)) {
            ev_timer_stop(loop, &c->rec.ld_alarm);
            warn(INF, "no RTX-able pkts outstanding, stopping LD alarm");
        }
        return;
    }

    ev_tstamp dur = 0;
    const ev_tstamp now = ev_now(loop);
    if (c->state < CONN_STAT_ESTB) {
        dur = is_zero(c->rec.srtt) ? kDefaultInitialRtt : c->rec.srtt;
        dur = MAX(2 * dur, kMinTLPTimeout) * (1 << c->rec.hshake_cnt);
        warn(INF, "handshake RTX alarm in %f sec on %s conn %" PRIx64, dur,
             conn_type(c), c->id);

    } else if (!is_zero(c->rec.loss_t)) {
        dur = c->rec.loss_t - now;
        warn(INF, "early RTX or time LD alarm in %f sec on %s conn %" PRIx64,
             dur, conn_type(c), c->id);

    } else if (c->rec.tlp_cnt < kMaxTLPs) {
        if (one_rtxable_pkt_outstanding(c))
            dur = 1.5 * c->rec.srtt + kDelayedAckTimeout;
        else
            dur = kMinTLPTimeout;
        dur = MAX(dur, 2 * c->rec.srtt);
        warn(INF, "TLP alarm in %f sec on %s conn %" PRIx64, dur, conn_type(c),
             c->id);

    } else {
        dur = c->rec.srtt + 4 * c->rec.rttvar;
        dur = MAX(dur, kMinRTOTimeout);
        dur *= (1 << c->rec.rto_cnt);
        warn(INF, "RTO alarm in %f sec on %s conn %" PRIx64, dur, conn_type(c),
             c->id);
    }

    c->rec.ld_alarm.repeat = dur;
    ev_timer_again(loop, &c->rec.ld_alarm);
}


struct w_iov * find_sent_pkt(struct q_conn * const c, const uint64_t nr)
{
    struct pkt_meta which_meta = {.nr = nr};
    const struct pkt_meta * const p =
        splay_find(pm_nr_splay, &c->rec.sent_pkts, &which_meta);
    if (p)
        return w_iov(w_engine(c->sock), w_iov_idx(p));
    return 0;
}


void rec_init(struct q_conn * const c)
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
    splay_init(&c->rec.sent_pkts);

    c->rec.lg_sent = c->is_clnt ? 999 : 7999; // TODO: randomize initial pkt nr

    c->rec.cwnd = kInitialWindow;
    c->rec.ssthresh = UINT64_MAX;
}
