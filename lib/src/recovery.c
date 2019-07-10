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

#ifndef NDEBUG
#include <stdio.h>
#endif

#define klib_unused

#include <khash.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "bitset.h"
#include "conn.h"
#include "diet.h"
#include "event.h" // IWYU pragma: keep
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"
#include "tls.h"


#define is_crypto_pkt(m) has_frm((m)->frms, FRM_CRY)


static inline bool __attribute__((nonnull))
in_cong_recovery(const struct q_conn * const c, const ev_tstamp sent_t)
{
    // see InRecovery() pseudo code
    return sent_t <= c->rec.rec_start_t;
}


static bool __attribute__((nonnull))
have_unacked_crypto_data(struct q_conn * const c)
{
    return (c->cstrms[ep_init] &&
            out_fully_acked(c->cstrms[ep_init]) == false) ||
           out_fully_acked(c->cstrms[ep_hshk]) == false;
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
#ifdef PARTICLE
    return false; // old gcc doesn't seem to understand "noreturn" attribute
#endif
}


static void __attribute__((nonnull)) maybe_tx(struct q_conn * const c)
{
    if (has_wnd(c, c->w->mtu) == false)
        return;

    c->no_wnd = false;
    // don't set c->needs_tx = true, since it's not clear we must TX
    ev_feed_event(&c->tx_w, 0);
}


static struct pn_space * __attribute__((nonnull))
earliest_loss_t_pn(struct q_conn * const c)
{
    ev_tstamp loss_t = 0;
    struct pn_space * pn = 0;
    for (pn_t t = pn_init; t <= pn_data; t++) {
        if (c->pns[t].sent_pkts == 0)
            // abandoned pn space
            continue;

        if (is_ack_eliciting(&c->pns[t].tx_frames) == false)
            // no ACK-eliciting frames outstanding
            continue;

        if (pn == 0 ||
            (is_zero(c->pns[t].loss_t) == false && c->pns[t].loss_t < loss_t)) {
            pn = &c->pns[t];
            loss_t = pn->loss_t;
        }
    }
    return pn;
}


void set_ld_timer(struct q_conn * const c)
{
    if (c->state == conn_idle || c->state == conn_clsg || c->state == conn_drng)
        // don't do LD while idle or draining
        return;

        // see SetLossDetectionTimer() pseudo code

#ifdef DEBUG_TIMERS
    const char * type = BLD RED "???" NRM;
#endif
    const struct pn_space * const pn = earliest_loss_t_pn(c);

    if (pn && !is_zero(pn->loss_t)) {
#ifdef DEBUG_TIMERS
        type = "TT";
#endif
        c->rec.ld_alarm.repeat = pn->loss_t;
        goto set_to;
    }

    if (unlikely(have_unacked_crypto_data(c) ||
                 have_keys(c, pn_data) == false)) {
#ifdef DEBUG_TIMERS
        type = "crypto RTX";
#endif
        ev_tstamp to =
            2 * (unlikely(is_zero(c->rec.srtt)) ? kInitialRtt : c->rec.srtt);
        to = MAX(to, kGranularity) * (1 << c->rec.crypto_cnt);
        c->rec.ld_alarm.repeat = c->rec.last_sent_crypto_t + to;
        goto set_to;
    }

    // don't arm the alarm if there are no ack-eliciting packets in flight
    if (unlikely(c->rec.ae_in_flight == 0)) {
#ifdef DEBUG_TIMERS
        warn(DBG, "no RTX-able pkts in flight, stopping ld_alarm on %s conn %s",
             conn_type(c), cid2str(c->scid));
#endif
        ev_timer_stop(&c->rec.ld_alarm);
        return;
    }

#ifdef DEBUG_TIMERS
    type = "PTO";
#endif
    ev_tstamp to = c->rec.srtt + MAX(4 * c->rec.rttvar, kGranularity) +
                   (ev_tstamp)c->tp_out.max_ack_del / MSECS_PER_SEC;
    to *= 1 << c->rec.pto_cnt;
    c->rec.ld_alarm.repeat = c->rec.last_sent_ack_elicit_t + to;

set_to:
    c->rec.ld_alarm.repeat -= ev_now();

#ifdef DEBUG_TIMERS
    warn(DBG, "%s alarm in %f sec on %s conn %s", type, c->rec.ld_alarm.repeat,
         conn_type(c), cid2str(c->scid));
#endif
    if (c->rec.ld_alarm.repeat <= 0)
        ev_feed_event(&c->rec.ld_alarm, true);
    else
        ev_timer_again(&c->rec.ld_alarm);
}


void congestion_event(struct q_conn * const c, const ev_tstamp sent_t)
{
    // see CongestionEvent() pseudo code

    if (in_cong_recovery(c, sent_t))
        return;

    c->rec.rec_start_t = ev_now();
    c->rec.cwnd /= kLossReductionDivisor;
    c->rec.ssthresh = c->rec.cwnd = MAX(c->rec.cwnd, kMinimumWindow);
}


static bool __attribute__((nonnull))
in_persistent_cong(struct pn_space * const pn __attribute__((unused)),
                   const uint64_t lg_lost __attribute__((unused)))
{
    // struct q_conn * const c = pn->c;

    // // see InPersistentCongestion() pseudo code
    // const ev_tstamp cong_period =
    //     kPersistentCongestionThreshold *
    //     (c->rec.srtt + MAX(4 * c->rec.rttvar, kGranularity) +
    //      (ev_tstamp)c->tp_out.max_ack_del / MSECS_PER_SEC);

    // const struct ival * const i = diet_find(&pn->lost, lg_lost);
    // warn(DBG,
    //      "lg_lost_ival %" PRIu64 "-%" PRIu64 ", lg_lost %" PRIu64 ", period
    //      %f", i->lo, i->hi, lg_lost, cong_period);
    // return i->lo + cong_period < lg_lost;
    return false;
}


static void remove_from_in_flight(const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    c->rec.in_flight -= m->udp_len;
    if (m->ack_eliciting)
        c->rec.ae_in_flight--;
}


void on_pkt_lost(struct pkt_meta * const m)
{
    struct pn_space * const pn = m->pn;
    struct q_conn * const c = pn->c;

    if (m->in_flight)
        remove_from_in_flight(m);

    // rest of function is not from pseudo code

    diet_insert(&pn->acked_or_lost, m->hdr.nr, (ev_tstamp)NAN);

    // if we lost connection or stream control frames, possibly RTX them

    // static const struct frames conn_ctrl =
    //     bitset_t_initializer(1 << FRM_TOK | 1 << FRM_CDB | 1 << FRM_SBB |
    //                          1 << FRM_SBU | 1 << FRM_CID | 1 << FRM_RTR);
    static const struct frames all_ctrl =
        bitset_t_initializer(1 << FRM_RST | 1 << FRM_STP | 1 << FRM_TOK |
                             1 << FRM_CDB | 1 << FRM_SDB | 1 << FRM_SBB |
                             1 << FRM_SBU | 1 << FRM_CID | 1 << FRM_RTR);
    if (bit_overlap(FRM_MAX, &all_ctrl, &m->frms))
        for (uint32_t i = 0; i < FRM_MAX; i++)
            if (has_frm(m->frms, i) && bit_isset(FRM_MAX, i, &all_ctrl)) {
                warn(DBG, "%s pkt %" PRIu64 " CONTROL LOST: 0x%02x",
                     pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.nr, i);
                switch (i) {
                case FRM_CID:
                    c->max_cid_seq_out = m->min_cid_seq - 1;
                    break;
                case FRM_CDB:
                case FRM_SDB:
                    // DATA_BLOCKED and STREAM_DATA_BLOCKED RTX'ed automatically
                    break;
                default:
                    warn(CRT, "unhandled RTX of 0x%02x frame", i);
                }
            }

    static const struct frames strm_ctrl =
        // FRM_SDB is automatically RTX'ed XXX fix this mess
        bitset_t_initializer(1 << FRM_RST | 1 << FRM_STP /*| 1 << FRM_SDB*/);
    if (bit_overlap(FRM_MAX, &strm_ctrl, &m->frms))
        need_ctrl_update(m->strm);

    m->lost = true;
    if (m->strm)
        m->strm->lost_cnt++;
    pm_by_nr_del(pn->sent_pkts, m);
}


#ifndef NDEBUG
#define DEBUG_diet_insert diet_insert
#define DEBUG_ensure ensure
#else
#define DEBUG_diet_insert(...)
#define DEBUG_ensure(...)
#endif


static void __attribute__((nonnull))
detect_lost_pkts(struct pn_space * const pn, const bool do_cc)
{
    if (unlikely(pn->sent_pkts == 0))
        // abandoned PN
        return;

    struct q_conn * const c = pn->c;
    pn->loss_t = 0;

    // Minimum time of kGranularity before packets are deemed lost.
    const ev_tstamp loss_del =
        MAX(kGranularity, kTimeThreshold * MAX(c->rec.latest_rtt, c->rec.srtt));

    // Packets sent before this time are deemed lost.
    const ev_tstamp lost_send_t = ev_now() - loss_del;

#ifndef NDEBUG
    struct diet lost = diet_initializer(lost);
#endif
    uint64_t lg_lost = UINT64_MAX;
    ev_tstamp lg_lost_tx_t = 0;
    bool in_flight_lost = false;
    struct pkt_meta * m;
    kh_foreach_value(pn->sent_pkts, m, {
        // TODO these ensures should not execute for release builds
        DEBUG_ensure(m->acked == false,
                     "%s ACKed %s pkt %" PRIu64 " in sent_pkts", conn_type(c),
                     pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.nr);
        DEBUG_ensure(m->lost == false,
                     "%s lost %s pkt %" PRIu64 " in sent_pkts", conn_type(c),
                     pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.nr);

        if (m->hdr.nr > pn->lg_acked)
            continue;

        // Mark packet as lost, or set time when it should be marked.
        if (m->tx_t <= lost_send_t ||
            pn->lg_acked >= m->hdr.nr + kPacketThreshold) {
            m->lost = true;
            in_flight_lost |= m->in_flight;
            c->i.pkts_out_lost++;
            if (unlikely(lg_lost == UINT64_MAX) || m->hdr.nr > lg_lost) {
                // cppcheck-suppress unreadVariable
                lg_lost = m->hdr.nr;
                lg_lost_tx_t = m->tx_t;
            }
        } else {
            if (unlikely(is_zero(pn->loss_t)))
                pn->loss_t = m->tx_t + loss_del;
            else
                pn->loss_t = MIN(pn->loss_t, m->tx_t + loss_del);
        }

        // OnPacketsLost
        if (m->lost) {
            DEBUG_diet_insert(&lost, m->hdr.nr, (ev_tstamp)NAN);
            on_pkt_lost(m);
            if (m->strm == 0 || m->has_rtx)
                free_iov(w_iov(c->w, pm_idx(m)), m);
        }
    });

#ifndef NDEBUG
    char buf[512];
    int pos = 0;
    struct ival * i = 0;
    diet_foreach (i, diet, &lost) {
        if ((size_t)pos >= sizeof(buf)) {
            buf[sizeof(buf) - 2] = buf[sizeof(buf) - 3] = buf[sizeof(buf) - 4] =
                '.';
            buf[sizeof(buf) - 1] = 0;
            break;
        }

        if (i->lo == i->hi)
            pos +=
                snprintf(&buf[pos], sizeof(buf) - (size_t)pos, FMT_PNR_OUT "%s",
                         i->lo, splay_next(diet, &lost, i) ? ", " : "");
        else
            pos += snprintf(&buf[pos], sizeof(buf) - (size_t)pos,
                            FMT_PNR_OUT ".." FMT_PNR_OUT "%s", i->lo, i->hi,
                            splay_next(diet, &lost, i) ? ", " : "");
    }
    diet_free(&lost);

    if (pos)
        warn(DBG, "%s %s lost: %s", conn_type(c), pn_type_str(pn->type), buf);
#endif

    // OnPacketsLost
    if (do_cc && in_flight_lost) {
        congestion_event(c, lg_lost_tx_t);
        if (in_persistent_cong(pn, lg_lost))
            c->rec.cwnd = kMinimumWindow;
    }

    log_cc(c);
    maybe_tx(c);
}


static void __attribute__((nonnull))
on_ld_timeout(ev_timer * const w, int direct)
{
    struct q_conn * const c = w->data;
    ev_timer_stop(&c->rec.ld_alarm);

    // see OnLossDetectionTimeout pseudo code
    struct pn_space * const pn = earliest_loss_t_pn(c);

    if (pn && !is_zero(pn->loss_t)) {
#ifdef DEBUG_TIMERS
        warn(DBG, "%s TT alarm on %s conn %s", pn_type_str(pn->type),
             conn_type(c), cid2str(c->scid));
#endif
        detect_lost_pkts(pn, true);
    } else if (have_unacked_crypto_data(c)) {
#ifdef DEBUG_TIMERS
        warn(DBG, "crypto RTX #%u on %s conn %s", c->rec.crypto_cnt + 1,
             conn_type(c), cid2str(c->scid));
#endif
        detect_lost_pkts(&c->pns[pn_init], false);
        detect_lost_pkts(&c->pns[pn_hshk], false);
        detect_lost_pkts(&c->pns[pn_data], false);
        if (c->rec.crypto_cnt++ >= 2 && c->sockopt.enable_ecn) {
            warn(NTE, "turning off ECN for %s conn %s", conn_type(c),
                 cid2str(c->scid));
            c->sockopt.enable_ecn = false;
            w_set_sockopt(c->sock, &c->sockopt);
        }
        ev_feed_event(&c->tx_w, 0);
        c->i.pto_cnt++;

    } else if (have_keys(c, pn_data) == false) {
#ifdef DEBUG_TIMERS
        warn(DBG, "anti-deadlock RTX #%u on %s conn %s", c->rec.crypto_cnt + 1,
             conn_type(c), cid2str(c->scid));
#endif

        // XXX this doesn't quite implement the pseudo code
        ev_feed_event(&c->tx_w, 1);
        c->rec.crypto_cnt++;

    } else {
#ifdef DEBUG_TIMERS
        warn(DBG, "PTO alarm #%u on %s conn %s", c->rec.pto_cnt, conn_type(c),
             cid2str(c->scid));
#endif
        c->rec.pto_cnt++;
        c->i.pto_cnt++;
        ev_feed_event(&c->tx_w, 2);
    }

    if (!direct)
        // we were called via set_ld_timer, so don't call it again
        set_ld_timer(c);
}


static void __attribute__((nonnull))
track_acked_pkts(struct w_iov * const v, struct pkt_meta * const m)
{
    adj_iov_to_start(v, m);
    const uint8_t * pos = v->buf + m->ack_frm_pos;
    const uint8_t * const end = v->buf + v->len;

    // this is a similar loop as in dec_ack_frame() - keep changes in sync
    uint64_t lg_ack_in_block = m->lg_acked;
    for (uint64_t n = m->ack_rng_cnt + 1; n > 0; n--) {
        uint64_t ack_block_len = 0;
        decv(&ack_block_len, &pos, end);
        diet_remove_ival(
            &m->pn->recv,
            &(const struct ival){.lo = lg_ack_in_block - ack_block_len,
                                 .hi = lg_ack_in_block});
        if (n > 1) {
            uint64_t gap = 0;
            decv(&gap, &pos, end);
            lg_ack_in_block -= ack_block_len + gap + 2;
        }
    }

    adj_iov_to_data(v, m);
}


void on_pkt_sent(struct pkt_meta * const m)
{
    m->txed = true;

    // see OnPacketSent() pseudo code

    const ev_tstamp now = ev_now();
    pm_by_nr_ins(m->pn->sent_pkts, m);
    // nr is set in enc_pkt()
    m->tx_t = now;
    // ack_eliciting is set in enc_pkt()
    m->in_flight = m->ack_eliciting || has_frm(m->frms, FRM_PAD);
    // size is set in enc_pkt()

    struct q_conn * const c = m->pn->c;
    if (likely(m->in_flight)) {
        if (unlikely(is_crypto_pkt(m)))
            c->rec.last_sent_crypto_t = now;
        if (likely(m->ack_eliciting)) {
            c->rec.last_sent_ack_elicit_t = now;
            c->rec.ae_in_flight++;
        }

        // OnPacketSentCC
        c->rec.in_flight += m->udp_len;
    }

    // we call set_ld_timer(c) once for a TX'ed burst in do_tx() instead of here
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
    ack_del = MIN(ack_del, (ev_tstamp)c->tp_out.max_ack_del / MSECS_PER_SEC);

    const ev_tstamp adj_rtt = c->rec.latest_rtt > c->rec.min_rtt + ack_del
                                  ? c->rec.latest_rtt - ack_del
                                  : c->rec.latest_rtt;

    c->rec.rttvar = .75 * c->rec.rttvar + .25 * fabs(c->rec.srtt - adj_rtt);
    c->rec.srtt = .875 * c->rec.srtt + .125 * adj_rtt;
}


void on_ack_received_1(struct pkt_meta * const lg_ack, const uint64_t ack_del)
{
    // see OnAckReceived() pseudo code
    struct pn_space * const pn = lg_ack->pn;
    struct q_conn * const c = pn->c;
    pn->lg_acked = unlikely(pn->lg_acked == UINT64_MAX)
                       ? lg_ack->hdr.nr
                       : MAX(pn->lg_acked, lg_ack->hdr.nr);

    if (is_ack_eliciting(&lg_ack->pn->tx_frames)) {
        c->rec.latest_rtt = ev_now() - lg_ack->tx_t;
        update_rtt(c, (ev_tstamp)ack_del / USECS_PER_SEC);
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
}


static void __attribute__((nonnull))
on_pkt_acked_cc(const struct pkt_meta * const m)
{
    // OnPacketAckedCC
    remove_from_in_flight(m);

    struct q_conn * const c = m->pn->c;
    if (in_cong_recovery(c, m->tx_t))
        return;

    // TODO: IsAppLimited check

    if (c->rec.cwnd < c->rec.ssthresh)
        c->rec.cwnd += m->udp_len;
    else
        c->rec.cwnd += (kMaxDatagramSize * m->udp_len) / c->rec.cwnd;
}


void on_pkt_acked(struct w_iov * const v, struct pkt_meta * m)
{
    // see OnPacketAcked() pseudo code
    struct pn_space * const pn = m->pn;
    struct q_conn * const c = pn->c;
    if (m->in_flight && m->lost == false)
        on_pkt_acked_cc(m);
    diet_insert(&pn->acked_or_lost, m->hdr.nr, (ev_tstamp)NAN);
    pm_by_nr_del(pn->sent_pkts, m);

    // rest of function is not from pseudo code

    // stop ACK'ing packets contained in the ACK frame of this packet
    if (has_frm(m->frms, FRM_ACK))
        track_acked_pkts(v, m);

    struct pkt_meta * const m_rtx = sl_first(&m->rtx);
    if (unlikely(m_rtx)) {
        // this ACKs a pkt with prior or later RTXs
        if (m->has_rtx) {
            // this ACKs a pkt that was since (again) RTX'ed
            warn(DBG, "%s %s pkt " FMT_PNR_OUT " was RTX'ed as " FMT_PNR_OUT,
                 conn_type(c), pkt_type_str(m->hdr.flags, &m->hdr.vers),
                 m->hdr.nr, m_rtx->hdr.nr);
#ifndef NDEBUG
            ensure(sl_next(m_rtx, rtx_next) == 0, "RTX chain corrupt");
#endif
            if (m_rtx->acked == false) {
                // treat RTX'ed data as ACK'ed; use stand-in w_iov for RTX info
                const uint64_t acked_nr = m->hdr.nr;
                pm_by_nr_del(pn->sent_pkts, m_rtx);
                m->hdr.nr = m_rtx->hdr.nr;
                m_rtx->hdr.nr = acked_nr;
                pm_by_nr_ins(pn->sent_pkts, m);
                m = m_rtx;
                // XXX caller will not be aware that we mucked around with m!
            }
        } else {
            // this ACKs the last ("real") RTX of a packet
            warn(CRT, "pkt nr=%" PRIu64 " was earlier TX'ed as %" PRIu64,
                 has_pkt_nr(m->hdr.flags, m->hdr.vers) ? m->hdr.nr : 0,
                 has_pkt_nr(m_rtx->hdr.flags, m_rtx->hdr.vers) ? m_rtx->hdr.nr
                                                               : 0);
        }
    }

    m->acked = true;

    struct q_stream * const s = m->strm;
    if (s && m->has_rtx == false) {
        // if this ACKs its stream's out_una, move that forward
        struct w_iov * tmp;
        sq_foreach_from_safe (s->out_una, &s->out, next, tmp) {
            struct pkt_meta * const mou = &meta(s->out_una);
            if (mou->acked == false)
                break;
            // if this ACKs a crypto packet, we can free it
            if (unlikely(s->id < 0 && mou->lost == false)) {
                sq_remove(&s->out, s->out_una, w_iov, next);
                free_iov(s->out_una, mou);
            }
        }

        if (s->id >= 0 && s->out_una == 0) {
            if (unlikely(m->is_fin || c->did_0rtt)) {
                // this ACKs a FIN
                c->have_new_data = true;
                strm_to_state(s, s->state == strm_hcrm ? strm_clsd : strm_hclo);
            }
            if (c->did_0rtt)
                maybe_api_return(q_connect, c, 0);
        }

    } else
        free_iov(v, m);
}


void init_rec(struct q_conn * const c)
{
    if (ev_is_active(&c->rec.ld_alarm))
        ev_timer_stop(&c->rec.ld_alarm);

    // zero all, then reset
    memset(&c->rec, 0, sizeof(c->rec));

    c->rec.cwnd = kInitialWindow;
    c->rec.ssthresh =
#ifndef PARTICLE
        UINT64_MAX;
#else
        UINT32_MAX;
#endif
    c->rec.min_rtt = HUGE_VAL;
    c->rec.ld_alarm.data = c;
    ev_init(&c->rec.ld_alarm, on_ld_timeout);
}
