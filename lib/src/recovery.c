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
    if (c->state == conn_clsg || c->state == conn_drng)
        // don't do LD while draining
        return;

    // don't arm the alarm if there are no packets with
    // retransmittable data in flight
    if (c->rec.in_flight == 0) {
        ev_timer_stop(loop, &c->rec.ld_alarm);
#ifndef FUZZING
        warn(DBG, "no RTX-able pkts outstanding, stopping ld_alarm");
#endif
        return;
    }

    // assumption: "handshake packet" = contains CRYPTO frame
    if (hshk_pkts_outstanding(c)) {
        ev_tstamp to =
            2 * (is_zero(c->rec.srtt) ? kDefaultInitialRtt : c->rec.srtt);
        to = MAX(to, kMinTLPTimeout) * (1 << c->rec.hshake_cnt);
        c->rec.ld_alarm.repeat = ev_now(loop) - c->rec.last_sent_hshk_t + to;
        warn(DBG, "handshake RTX alarm in %f sec on %s conn %s",
             c->rec.ld_alarm.repeat, conn_type(c), scid2str(c));

    } else if (!is_zero(c->rec.loss_t)) {
        c->rec.ld_alarm.repeat = c->rec.loss_t - c->rec.last_sent_rtxable_t;
        warn(DBG, "early RTX or time alarm in %f sec on %s conn %s",
             c->rec.ld_alarm.repeat, conn_type(c), scid2str(c));

    } else {
        ev_tstamp to = c->rec.srtt + (4 * c->rec.rttvar) +
                       (c->tp_out.max_ack_del / 1000.0);
        to = MAX(to, kMinRTOTimeout);
        c->rec.ld_alarm.repeat = to * (1 << c->rec.rto_cnt);
        if (c->rec.tlp_cnt < kMaxTLPs) {
            const ev_tstamp tlp_to =
                MAX(1.5 * c->rec.srtt + (c->tp_out.max_ack_del / 1000.0),
                    kMinTLPTimeout);
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
    for (p = splay_min(pm_by_nr, &pn->sent_pkts); p && p->hdr.nr < pn->lg_acked;
         p = nxt) {
        nxt = splay_next(pm_by_nr, &pn->sent_pkts, p);
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
                log_cc(c);
            }
            largest_lost_packet = MAX(largest_lost_packet, p->hdr.nr);

            if (p->is_rtx || !is_rtxable(p)) {
                if (p->is_rtx)
                    // remove from the original w_iov rtx list
                    sl_remove(&sl_first(&p->rtx)->rtx, p, pkt_meta, rtx_next);
                q_free_iov(w_iov(c->w, pm_idx(p)));
            }

        } else if (is_zero(c->rec.loss_t) && !is_inf(delay_until_lost))
            c->rec.loss_t = now + delay_until_lost - time_since_sent;
    }

    // CongestionEvent:
    // Start a new recovery epoch if the lost packet is larger
    // than the end of the previous recovery epoch.
    if (!in_recovery(c, largest_lost_packet)) {
        c->rec.eor = pn->lg_sent;
        c->rec.cwnd /= kLossReductionDivisor;
        c->rec.cwnd = MAX(c->rec.cwnd, kMinimumWindow);
        c->rec.ssthresh = c->rec.cwnd;
        log_cc(c);
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

    // XXX is in the pseudo code, but it's already also called in on_pkt_sent()
    if (did_tx == false)
        // set_ld_alarm is also called in on_pkt_sent, avoid duplicate
        set_ld_alarm(c);
}


static inline void __attribute__((nonnull))
track_acked_pkts(struct pn_space * const pn, struct w_iov * const v)
{
    adj_iov_to_start(v);

    // this is the same loop as in dec_ack_frame() - keep changes in sync
    uint64_t lg_ack_in_block = meta(v).lg_acked;
    uint16_t i = meta(v).ack_block_pos;
    for (uint64_t n = meta(v).ack_block_cnt + 1; n > 0; n--) {
        uint64_t ack_block_len = 0;
        dec(&ack_block_len, v->buf, v->len, i, 0, "%" PRIu64);

        uint64_t ack = lg_ack_in_block;
        while (ack_block_len >= lg_ack_in_block - ack) {
            diet_remove(&pn->recv, ack);
            if (likely(ack > 0))
                ack--;
            else
                break;
        }

        if (n > 1) {
            uint64_t gap = 0;
            i = dec(&gap, v->buf, v->len, i, 0, "%" PRIu64);
            lg_ack_in_block = ack - gap - 1;
        }
    }

    adj_iov_to_data(v);
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
    splay_insert(pm_by_nr, &pn->sent_pkts, &meta(v));

    if (likely(s->c->state != conn_idle) && is_ack_only(&meta(v)) == false) {
        if (bit_test(meta(v).frames, FRAM_TYPE_CRPT))
            // is_handshake_packet
            s->c->rec.last_sent_hshk_t = meta(v).tx_t;
        s->c->rec.last_sent_rtxable_t = meta(v).tx_t;

        s->c->rec.in_flight += meta(v).tx_len; // OnPacketSentCC
        log_cc(s->c);
    }

    // TODO this should be in the clause above, but since we currently don't RTX
    // NEW_TOKEN, NEW_CONNECTION_ID, etc. that means the timers don't back off
    // correctly
    set_ld_alarm(s->c);
}


static void __attribute__((nonnull))
update_rtt(struct q_conn * const c, const ev_tstamp ack_del)
{
    // implements UpdateRtt pseudocode

    // min_rtt = min(min_rtt, latest_rtt)
    c->rec.min_rtt = MIN(c->rec.min_rtt, c->rec.latest_rtt);

    // if (latest_rtt - min_rtt > ack_delay):
    if (c->rec.latest_rtt - c->rec.min_rtt > ack_del)
        // latest_rtt -= ack_delay
        c->rec.latest_rtt -= ack_del;

    // if (smoothed_rtt == 0):
    if (unlikely(is_zero(c->rec.srtt))) {
        // smoothed_rtt = latest_rtt
        c->rec.srtt = c->rec.latest_rtt;
        // rttvar = latest_rtt / 2
        c->rec.rttvar = c->rec.latest_rtt / 2;
    } else {
        // rttvar_sample = abs(smoothed_rtt - latest_rtt)
        const ev_tstamp rttvar_sample = fabs(c->rec.srtt - c->rec.latest_rtt);
        // rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
        c->rec.rttvar = .75 * c->rec.rttvar + .25 * rttvar_sample;
        // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * latest_rtt
        c->rec.srtt = .875 * c->rec.srtt + .125 * c->rec.latest_rtt;
    }

    log_cc(c);
}


void on_ack_received_1(struct q_conn * const c,
                       struct pn_space * const pn,
                       struct w_iov * const lg_ack,
                       const uint64_t ack_del)
{
    // implements first part of OnAckReceived pseudocode

    // largest_acked_packet = ack.largest_acked
    pn->lg_acked = meta(lg_ack).hdr.nr;

    // latest_rtt = now - sent_packets[ack.largest_acked].time
    c->rec.latest_rtt = ev_now(loop) - meta(lg_ack).tx_t;

    // UpdateRtt(latest_rtt, ack.ack_delay)
    update_rtt(c, ack_del / 1000000.0); // ack_del is passed in usec
}


void on_ack_received_2(struct q_conn * const c,
                       struct pn_space * const pn,
                       const uint64_t sm_new_acked)
{
    // implements second part of OnAckReceived pseudocode

    // if (rto_count > 0 && sm_new_acked > largest_sent_before_rto):
    if (c->rec.rto_cnt > 0 && sm_new_acked &&
        sm_new_acked > pn->lg_sent_before_rto) {
        // OnRetransmissionTimeoutVerified(smallest_newly_acked)

        // congestion_window = kMinimumWindow
        c->rec.cwnd = kMinimumWindow;

        // for (sent_packet: sent_packets):
        //   if (sent_packet.packet_number < packet_number):
        for (struct pkt_meta * p = splay_min(pm_by_nr, &pn->sent_pkts);
             p && p->hdr.nr < sm_new_acked;
             p = splay_next(pm_by_nr, &pn->sent_pkts, p)) {
            warn(DBG, "pkt " FMT_PNR_OUT " considered lost", p->hdr.nr);
            p->is_lost = true;
            if (is_ack_only(p) == false) {
                // bytes_in_flight -= lost_packet.bytes
                c->rec.in_flight -= p->tx_len;
                // XXX: sent_packets.remove(sent_packet.packet_number)
                log_cc(c);
            }
        }
    }

    // handshake_count = 0
    // tlp_count = 0
    // rto_count = 0
    c->rec.hshake_cnt = c->rec.tlp_cnt = c->rec.rto_cnt = 0;

    detect_lost_pkts(c, pn);
    set_ld_alarm(c);
    // TODO: ProcessECN(ack)
}


static void __attribute__((nonnull))
on_pkt_acked_cc(struct q_conn * const c, struct w_iov * const acked_pkt)
{
    // implement OnPacketAckedCC pseudocode

    // bytes_in_flight -= acked_packet.bytes
    ensure(meta(acked_pkt).is_lost == false, "oops");
    // XXX see if we can remove this check?
    if (meta(acked_pkt).is_lost == false)
        c->rec.in_flight -= meta(acked_pkt).tx_len;

    // if (InRecovery(acked_packet.packet_number)):
    if (in_recovery(c, meta(acked_pkt).hdr.nr))
        return;

    // if (congestion_window < ssthresh):
    if (c->rec.cwnd < c->rec.ssthresh)
        // congestion_window += acked_packet.bytes
        c->rec.cwnd += meta(acked_pkt).tx_len;
    else
        // congestion_window += kMaxDatagramSize * acked_packet.bytes /
        // congestion_window
        c->rec.cwnd += kMaxDatagramSize * meta(acked_pkt).tx_len / c->rec.cwnd;

    // log_cc(c);
}


void on_pkt_acked(struct q_conn * const c,
                  struct pn_space * const pn,
                  struct w_iov * const acked_pkt)
{
    // implements OnPacketAcked pseudo code

    // if (!acked_packet.is_ack_only):
    if (is_ack_only(&meta(acked_pkt)) == false)
        on_pkt_acked_cc(c, acked_pkt);

    // sent_packets.remove(acked_packet.packet_number)
    diet_insert(&pn->acked, meta(acked_pkt).hdr.nr, ev_now(loop));
    splay_remove(pm_by_nr, &pn->sent_pkts, &meta(acked_pkt));

    // rest of function is not from pseudo code

    // if this ACKs a CLOSE frame, move to conn_drng
    if (c->state == conn_clsg &&
        (bit_test(meta(acked_pkt).frames, FRAM_TYPE_CONN_CLSE) ||
         bit_test(meta(acked_pkt).frames, FRAM_TYPE_APPL_CLSE)))
        conn_to_state(c, conn_drng);

    // if this ACKs a current MAX_STREAM_DATA frame, we can stop sending it
    if (bit_test(meta(acked_pkt).frames, FRAM_TYPE_MAX_STRM_DATA)) {
        struct q_stream * const s =
            get_stream(c, meta(acked_pkt).max_stream_data_sid);
        if (s && s->new_in_data_max == meta(acked_pkt).max_stream_data)
            s->tx_max_stream_data = false;
    }

    // if this ACKs the current MAX_DATA frame, we can stop sending it
    if (bit_test(meta(acked_pkt).frames, FRAM_TYPE_MAX_DATA) &&
        c->tp_in.new_max_data == meta(acked_pkt).max_data)
        c->tx_max_data = false;

    // if this ACKs the current MAX_STREAM_ID frame, we can stop sending it
    if (bit_test(meta(acked_pkt).frames, FRAM_TYPE_MAX_SID) &&
        c->tp_in.new_max_bidi_streams == meta(acked_pkt).max_bidi_streams)
        c->tx_max_stream_id = false;

    // if this ACK is for a pkt that was RTX'ed, update the record
    struct w_iov * orig = acked_pkt;
    if (meta(acked_pkt).is_rtx) {
        meta(acked_pkt).is_acked = true;
        struct pkt_meta * const r = sl_first(&meta(acked_pkt).rtx);
        ensure(sl_next(r, rtx_next) == 0, "rtx chain corrupt");
        warn(DBG, FMT_PNR_OUT " was RTX'ed as " FMT_PNR_OUT,
             meta(acked_pkt).hdr.nr, r->hdr.nr);
        orig = w_iov(c->w, pm_idx(r));
    }

    struct q_stream * const s = meta(orig).stream;
    if (s && meta(orig).is_acked == false) {
        s->out_ack_cnt++;
        if (out_fully_acked(s)) {
            warn(DBG, "stream " FMT_SID " ACK cnt %u, len %u %s", s->id,
                 s->out_ack_cnt, sq_len(&s->out),
                 out_fully_acked(s) ? "(fully acked)" : "");

            // a q_write may be done
            maybe_api_return(q_write, s->c, s);
            if (s->id >= 0 && s->c->did_0rtt)
                maybe_api_return(q_connect, s->c, 0);
        }
    }
    meta(orig).is_acked = true;

    // if this ACKs its stream's out_una, move that forward
    if (meta(orig).stream && meta(orig).stream->out_una == orig) {
        struct w_iov * new_out_una = orig;
        sq_foreach_from (new_out_una, &s->out, next)
            if (meta(new_out_una).is_acked == false)
                break;
        meta(orig).stream->out_una = new_out_una;
    }

    if (s) {
        adj_iov_to_start(acked_pkt);
        if (is_fin(acked_pkt))
            // this ACKs a FIN
            maybe_api_return(q_close_stream, s->c, s);
        adj_iov_to_data(acked_pkt);
    }

    // stop ACKing packets that were contained in the ACK frame of this packet
    if (bit_test(meta(acked_pkt).frames, FRAM_TYPE_ACK))
        track_acked_pkts(pn, acked_pkt);

    if (!is_rtxable(&meta(orig)))
        q_free_iov(orig);
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

    memset(&c->rec, 0, sizeof(c->rec));

    c->rec.min_rtt = HUGE_VAL;

    c->rec.ld_alarm.data = c;
    ev_init(&c->rec.ld_alarm, on_ld_alarm);

    c->rec.reorder_thresh = kReorderingThreshold;
    c->rec.cwnd = kInitialWindow;
    c->rec.ssthresh = UINT64_MAX;

    log_cc(c);
}
