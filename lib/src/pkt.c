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

#include <inttypes.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

// IWYU pragma: no_include <picotls/../picotls.h>

#include <picotls.h> // IWYU pragma: keep
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


#define MAX_PKT_NR_LEN 4 ///< Maximum packet number length allowed by spec.


#ifndef NDEBUG
// local version of cid2str that is just hex2str (omits the seq)
#define c2s(i) hex2str((i)->id, (i)->len)

void log_pkt(const char * const dir,
             const struct w_iov * const v,
             const struct sockaddr * const addr,
             const struct cid * const odcid,
             const uint8_t * const tok,
             const uint16_t tok_len)
{
    if (util_dlevel < NTE)
        return;

    char ip[NI_MAXHOST];
    char port[NI_MAXSERV];
    ensure(getnameinfo(addr, sizeof(*addr), ip, sizeof(ip), port, sizeof(port),
                       NI_NUMERICHOST | NI_NUMERICSERV) == 0,
           "getnameinfo");

    const struct pkt_meta * const m = &meta(v); // meta use OK
    if (*dir == 'R') {
        if (is_lh(m->hdr.flags)) {
            if (m->hdr.vers == 0)
                twarn(NTE,
                      BLD BLU "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU
                              "%s " NRM "vers=0x%08x dcid=%s scid=%s",
                      ip, port, v->len, m->hdr.flags,
                      pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid));
            else if (m->hdr.type == LH_RTRY)
                twarn(NTE,
                      BLD BLU "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU
                              "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s odcid=%s tok=%s",
                      ip, port, v->len, m->hdr.flags,
                      pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid), c2s(odcid),
                      hex2str(tok, tok_len));
            else if (m->hdr.type == LH_INIT)
                twarn(NTE,
                      BLD BLU
                      "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s tok=%s len=%u nr=" BLU
                      "%" PRIu64,
                      ip, port, v->len, m->hdr.flags,
                      pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid),
                      hex2str(tok, tok_len), m->hdr.len, m->hdr.nr);
            else
                twarn(NTE,
                      BLD BLU
                      "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s len=%u nr=" BLU "%" PRIu64,
                      ip, port, v->len, m->hdr.flags,
                      pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid), m->hdr.len,
                      m->hdr.nr);
        } else
            twarn(NTE,
                  BLD BLU "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU "%s " NRM
                          "kyph=%u spin=%u dcid=%s nr=" BLU "%" PRIu64,
                  ip, port, v->len, m->hdr.flags,
                  pkt_type_str(m->hdr.flags, &m->hdr.vers),
                  is_set(SH_KYPH, m->hdr.flags), is_set(SH_SPIN, m->hdr.flags),
                  c2s(&m->hdr.dcid), m->hdr.nr);

    } else {
        // on TX, v->len is not yet final/correct, so don't print it
        if (is_lh(m->hdr.flags)) {
            if (m->hdr.vers == 0)
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s",
                      ip, port, m->hdr.flags,
                      pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid));
            else if (m->hdr.type == LH_RTRY)
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s odcid=%s tok=%s",
                      ip, port, m->hdr.flags,
                      pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid), c2s(odcid),
                      hex2str(tok, tok_len));
            else if (m->hdr.type == LH_INIT)
                twarn(NTE,
                      BLD GRN
                      "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s tok=%s len=%u nr=" GRN
                      "%" PRIu64,
                      ip, port, m->hdr.flags,
                      pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid),
                      hex2str(tok, tok_len), m->hdr.len, m->hdr.nr);
            else
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s len=%u nr=" GRN
                              "%" PRIu64,
                      ip, port, m->hdr.flags,
                      pkt_type_str(m->hdr.flags, &m->hdr.vers), m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid), m->hdr.len,
                      m->hdr.nr);
        } else
            twarn(NTE,
                  BLD GRN "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                          "kyph=%u spin=%u dcid=%s nr=" GRN "%" PRIu64,
                  ip, port, m->hdr.flags,
                  pkt_type_str(m->hdr.flags, &m->hdr.vers),
                  is_set(SH_KYPH, m->hdr.flags), is_set(SH_SPIN, m->hdr.flags),
                  c2s(&m->hdr.dcid), m->hdr.nr);
    }
}
#endif


static bool __attribute__((const))
can_coalesce_pkt_types(const uint8_t a, const uint8_t b)
{
    return (a == LH_INIT && (b == LH_0RTT || b == LH_HSHK)) ||
           (a == LH_HSHK && b == SH) || (a == LH_0RTT && b == LH_HSHK);
}


void coalesce(struct w_iov_sq * const q)
{
    struct w_iov * v = sq_first(q);
    while (v) {
        struct w_iov * next = sq_next(v, next);
        struct w_iov * prev = v;
        while (next) {
            struct w_iov * const next_next = sq_next(next, next);
            // do we have space? do the packet types make sense to coalesce?
            if (v->len + next->len <= kMaxDatagramSize &&
                can_coalesce_pkt_types(pkt_type(*v->buf),
                                       pkt_type(*next->buf))) {
                // we can coalesce
                warn(DBG, "coalescing %u-byte %s pkt behind %u-byte %s pkt",
                     next->len, pkt_type_str(*next->buf, next->buf + 1), v->len,
                     pkt_type_str(*v->buf, v->buf + 1));
                memcpy(v->buf + v->len, next->buf, next->len);
                v->len += next->len;
                sq_remove_after(q, prev, next);
                // warn(CRT, "w_free_iov idx %u (avail %" PRIu64 ")",
                //      w_iov_idx(next), sq_len(&next->w->iov) + 1);
                w_free_iov(next);
            } else
                prev = next;
            next = next_next;
        }
        v = sq_next(v, next);
    }
}


static inline uint8_t __attribute__((const))
needed_pkt_nr_len(const uint64_t lg_acked, const uint64_t n)
{
    const uint64_t d =
        (n - (unlikely(lg_acked == UINT64_MAX) ? 0 : lg_acked)) * 2;
    if (d <= UINT8_MAX)
        return 1;
    if (d <= UINT16_MAX)
        return 2;
    if (d <= (UINT32_MAX >> 8))
        return 3;
    return 4;
}


uint16_t enc_lh_cids(const struct cid * const dcid,
                     const struct cid * const scid,
                     struct w_iov * const v,
                     struct pkt_meta * const m,
                     const uint16_t pos)
{
    cid_cpy(&m->hdr.dcid, dcid);
    if (scid)
        cid_cpy(&m->hdr.scid, scid);
    const uint8_t cil =
        (uint8_t)((m->hdr.dcid.len ? m->hdr.dcid.len - 3 : 0) << 4) |
        (uint8_t)(m->hdr.scid.len ? m->hdr.scid.len - 3 : 0);
    uint16_t i = enc(v->buf, v->len, pos, &cil, sizeof(cil), 0, "0x%02x");
    if (m->hdr.dcid.len)
        i = enc_buf(v->buf, v->len, i, &m->hdr.dcid.id, m->hdr.dcid.len);
    if (m->hdr.scid.len)
        i = enc_buf(v->buf, v->len, i, &m->hdr.scid.id, m->hdr.scid.len);
    return i;
}


static bool __attribute__((nonnull)) can_enc(const struct pkt_meta * const m,
                                             const uint8_t type,
                                             const bool one_per_pkt,
                                             const uint16_t pos,
                                             const uint16_t limit)
{
    const bool has_space = limit == 0 || pos + max_frame_len(type) < limit;
    // if (has_space == false)
    //     warn(DBG, "missing %u bytes to encode 0x%02x frame",
    //          pos + max_frame_len(type) - limit, type);
    return (one_per_pkt == false || has_frame(m, type) == false) && has_space;
}


static uint16_t __attribute__((nonnull))
enc_other_frames(struct w_iov * const v,
                 struct pkt_meta * const m,
                 const uint16_t pos,
                 const uint16_t lim)
{
    uint16_t i = pos;
    struct q_conn * const c = m->pn->c;

    // encode connection control frames
    if (!c->is_clnt && c->tok_len && can_enc(m, FRM_TOK, true, i, lim)) {
        i = enc_new_token_frame(v, m, i);
        c->tok_len = 0;
    }

    if (c->tx_path_resp && can_enc(m, FRM_PRP, true, i, lim)) {
        i = enc_path_response_frame(v, m, i);
        c->tx_path_resp = false;
    }

    if (c->tx_retire_cid && can_enc(m, FRM_RTR, true, i, lim)) {
        struct cid * rcid = splay_min(cids_by_seq, &c->dcids_by_seq);
        while (rcid && rcid->seq < c->dcid->seq) {
            struct cid * const next =
                splay_next(cids_by_seq, &c->dcids_by_seq, rcid);
            if (rcid->retired) {
                i = enc_retire_cid_frame(v, m, i, rcid);
                free_dcid(c, rcid);
            }
            rcid = next;
        }
    }

    if (c->tx_path_chlg && can_enc(m, FRM_PCL, true, i, lim))
        i = enc_path_challenge_frame(v, m, i);

    while (c->tx_ncid && can_enc(m, FRM_CID, false, i, lim)) {
        i = enc_new_cid_frame(v, m, i);
        c->tx_ncid = needs_more_ncids(c);
    }

    if (c->blocked && can_enc(m, FRM_CDB, true, i, lim))
        i = enc_data_blocked_frame(v, m, i);

    if (c->tx_max_data && can_enc(m, FRM_MCD, true, i, lim))
        i = enc_max_data_frame(v, m, i);

    if (c->sid_blocked_bidi && can_enc(m, FRM_SBB, true, i, lim))
        i = enc_streams_blocked_frame(v, m, i, true);

    if (c->sid_blocked_uni && can_enc(m, FRM_SBU, true, i, lim))
        i = enc_streams_blocked_frame(v, m, i, false);

    if (c->tx_max_sid_bidi && can_enc(m, FRM_MSB, true, i, lim))
        i = enc_max_streams_frame(v, m, i, true);

    if (c->tx_max_sid_uni && can_enc(m, FRM_MSU, true, i, lim))
        i = enc_max_streams_frame(v, m, i, false);

    while (!sl_empty(&c->need_ctrl)) {
        // XXX this assumes we can encode all the ctrl frames
        struct q_stream * const s = sl_first(&c->need_ctrl);
        sl_remove_head(&c->need_ctrl, node_ctrl);
        s->in_ctrl = false;
        // encode stream control frames
        if (s->blocked && can_enc(m, FRM_SDB, true, i, lim))
            i = enc_stream_data_blocked_frame(s, v, m, i);
        if (s->tx_max_stream_data && can_enc(m, FRM_MSD, true, i, lim))
            i = enc_max_stream_data_frame(s, v, m, i);
    }

    return i;
}


bool enc_pkt(struct q_stream * const s,
             const bool rtx,
             const bool enc_data,
             const bool tx_ack_eliciting,
             struct w_iov * const v,
             struct pkt_meta * const m)
{

    if (likely(enc_data))
        // prepend the header by adjusting the buffer offset
        adj_iov_to_start(v, m);

    struct q_conn * const c = s->c;
    uint16_t i = 0;
    uint16_t len_pos = 0;

    const epoch_t epoch = strm_epoch(s);
    struct pn_space * const pn = m->pn = pn_for_epoch(c, epoch);

    if (unlikely(c->tx_rtry))
        m->hdr.nr = 0;
    else if (unlikely(pn->lg_sent == UINT64_MAX))
        // next pkt nr
        m->hdr.nr = pn->lg_sent = 0;
    else
        m->hdr.nr = ++pn->lg_sent;

    switch (epoch) {
    case ep_init:
        m->hdr.type = unlikely(c->tx_rtry) ? LH_RTRY : LH_INIT;
        m->hdr.flags =
            LH | m->hdr.type | (unlikely(c->tx_rtry) ? c->odcid.len - 3 : 0);
        break;
    case ep_0rtt:
        if (c->is_clnt) {
            m->hdr.type = LH_0RTT;
            m->hdr.flags = LH | m->hdr.type;
        } else
            m->hdr.type = m->hdr.flags = SH;
        break;
    case ep_hshk:
        m->hdr.type = LH_HSHK;
        m->hdr.flags = LH | m->hdr.type;
        break;
    case ep_data:
        if (pn == &c->pn_data.pn) {
            m->hdr.type = m->hdr.flags = SH;
            m->hdr.flags |= c->pn_data.out_kyph ? SH_KYPH : 0;
        } else {
            m->hdr.type = LH_HSHK;
            m->hdr.flags = LH | m->hdr.type;
        }
        break;
    }

    if (c->spin_enabled && likely(is_lh(m->hdr.flags) == false) && c->spin)
        m->hdr.flags |= SH_SPIN;

    ensure(m->hdr.nr < (1ULL << 62) - 1, "packet number overflow");

    const uint8_t pnl = needed_pkt_nr_len(pn->lg_acked, m->hdr.nr);
    m->hdr.flags |= (pnl - 1);

    i = enc(v->buf, v->len, 0, &m->hdr.flags, sizeof(m->hdr.flags), 0,
            "0x%02x");

    if (unlikely(is_lh(m->hdr.flags))) {
        m->hdr.vers = c->vers;
        i = enc(v->buf, v->len, i, &c->vers, sizeof(c->vers), 0, "0x%08x");
        i = enc_lh_cids(c->dcid, c->scid, v, m, i);

        if (m->hdr.type == LH_RTRY)
            i = enc_buf(v->buf, v->len, i, &c->odcid.id, c->odcid.len);

        if (m->hdr.type == LH_INIT) {
            const uint64_t tl = c->is_clnt ? c->tok_len : 0;
            i = enc(v->buf, v->len, i, &tl, 0, 0, "%" PRIu64);
        }

        if (((c->is_clnt && m->hdr.type == LH_INIT) ||
             m->hdr.type == LH_RTRY) &&
            c->tok_len)
            i = enc_buf(v->buf, v->len, i, c->tok, c->tok_len);

        if (m->hdr.type != LH_RTRY) {
            // leave space for length field (2 bytes is enough)
            len_pos = i;
            i += 2;
        }

    } else {
        cid_cpy(&m->hdr.dcid, c->dcid);
        i = enc_buf(v->buf, v->len, i, &m->hdr.dcid.id, m->hdr.dcid.len);
    }

    uint16_t pkt_nr_pos = 0;
    if (likely(m->hdr.type != LH_RTRY)) {
        pkt_nr_pos = i;
        i = enc(v->buf, v->len, i, &m->hdr.nr, pnl, 0, GRN "%u" NRM);
    }

    m->hdr.hdr_len = i;
    v->addr = unlikely(c->tx_path_chlg) ? c->migr_peer : c->peer;

    log_pkt("TX", v, (struct sockaddr *)&v->addr,
            m->hdr.type == LH_RTRY ? &c->odcid : 0, c->tok, c->tok_len);

    // sanity check
    if (unlikely(m->hdr.hdr_len >=
                 DATA_OFFSET + (is_lh(m->hdr.flags) ? c->tok_len + 16 : 0))) {
        warn(ERR, "pkt header %u >= offset %u", m->hdr.hdr_len,
             DATA_OFFSET + (is_lh(m->hdr.flags) ? c->tok_len + 16 : 0));
        return false;
    }

    if (unlikely(m->hdr.type == LH_RTRY))
        goto tx;

    if (needs_ack(pn) != no_ack)
        i = enc_ack_frame(pn, v, m, i);

    if (unlikely(c->state == conn_clsg))
        i = enc_close_frame(v, m, i);
    else if (epoch == ep_data || (!c->is_clnt && epoch == ep_0rtt))
        i = enc_other_frames(v, m, i, m->stream_data_start);

    if (unlikely(rtx)) {
        ensure(has_stream_data(m), "is rtxable");

        // this is a RTX, pad out until beginning of stream header
        enc_padding_frame(v, m, i, m->stream_header_pos - i);
        i = m->stream_data_start + m->stream_data_len;
        log_stream_or_crypto_frame(true, v, s->id, false, "");

    } else if (likely(enc_data)) {
        // this is a fresh data/crypto or pure stream FIN packet
        // pad out until stream_data_start and add a stream frame header
        enc_padding_frame(v, m, i, m->stream_data_start - i);
        i = enc_stream_or_crypto_frame(s, v, m, i, s->id >= 0);
    }

    if (unlikely(i < MAX_PKT_LEN - AEAD_LEN && (enc_data || rtx) &&
                 (epoch == ep_data || (!c->is_clnt && epoch == ep_0rtt)))) {
        // we can try to stick some more frames in after the stream frame
        v->len = MAX_PKT_LEN - AEAD_LEN;
        i = enc_other_frames(v, m, i, v->len);
    }

    if (c->is_clnt && enc_data) {
        if (unlikely(c->try_0rtt == false && m->hdr.type == LH_INIT))
            i = enc_padding_frame(v, m, i, MIN_INI_LEN - i - AEAD_LEN);
        if (unlikely(c->try_0rtt == true && m->hdr.type == LH_0RTT &&
                     s->id >= 0))
            // if we pad the first 0-RTT pkt, peek at txq to get the CI length
            i = enc_padding_frame(
                v, m, i,
                MIN_INI_LEN - i - AEAD_LEN -
                    (sq_first(&c->txq) ? sq_first(&c->txq)->len : 0));
    }

    m->ack_eliciting = is_ack_eliciting(&m->frames);
    if (unlikely(tx_ack_eliciting) && m->ack_eliciting == false)
        // we can only do this for SH pkts
        if (m->hdr.type == SH) {
            i = enc_ping_frame(v, m, i);
            m->ack_eliciting = true;
        }

    ensure(i > m->hdr.hdr_len, "would have sent %s pkt w/o frames",
           pkt_type_str(m->hdr.flags, &m->hdr.vers));

tx:;
    // make sure we have enough frame bytes for the header protection sample
    const uint16_t pnp_dist = i - pkt_nr_pos;
    if (unlikely(pnp_dist < 4))
        i = enc_padding_frame(v, m, i, 4 - pnp_dist);

    // for LH pkts, now encode the length
    m->hdr.len = i + AEAD_LEN - pkt_nr_pos;
    if (unlikely(len_pos)) {
        const uint64_t len = m->hdr.len;
        enc(v->buf, v->len, len_pos, &len, 0, 2, "%" PRIu64);
    }

    v->len = i;

    // alloc directly from warpcore for crypto TX - no need for metadata alloc
    struct w_iov * const xv = w_alloc_iov(c->w, 0, 0);
    ensure(xv, "w_alloc_iov failed");
    // warn(CRT, "w_alloc_iov idx %u (avail %" PRIu64 ") len %u", w_iov_idx(xv),
    //      sq_len(&c->w->iov), xv->len);

    if (unlikely(m->hdr.type == LH_RTRY)) {
        memcpy(xv->buf, v->buf, v->len); // copy data
        xv->len = v->len;
    } else {
        const uint16_t ret = enc_aead(c, v, m, xv, pkt_nr_pos);
        if (unlikely(ret == 0)) {
            adj_iov_to_start(v, m);
            return false;
        }
    }

    if (!c->is_clnt)
        xv->addr = v->addr;

    // track the flags manually, since warpcore sets them on the xv and it'd
    // require another loop to copy them over
    xv->flags = v->flags |= likely(c->sockopt.enable_ecn) ? IPTOS_ECN_ECT0 : 0;

    sq_insert_tail(&c->txq, xv, next);
    m->udp_len = xv->len;
    c->out_data += m->udp_len;

    if (unlikely(m->hdr.type == LH_INIT && c->is_clnt && m->stream_data_len))
        // adjust v->len to exclude the post-stream padding for CI
        v->len = m->stream_data_start + m->stream_data_len;

    if (likely(enc_data)) {
        adj_iov_to_data(v, m);
        // XXX not clear if changing the len before calling on_pkt_sent is ok
        v->len = m->stream_data_len;
    }

    if (unlikely(rtx))
        // we did an RTX and this is no longer lost
        m->is_lost = false;

    on_pkt_sent(m);

    if (c->is_clnt) {
        if (is_lh(m->hdr.flags) == false)
            maybe_flip_keys(c, true);
        if (unlikely(m->hdr.type == LH_HSHK && c->cstreams[ep_init]))
            abandon_pn(c, ep_init);
    }

    return true;
}


#define dec_chk(dst, buf, buf_len, pos, dst_len, ...)                          \
    __extension__({                                                            \
        const uint16_t _i =                                                    \
            dec((dst), (buf), (buf_len), (pos), (dst_len), __VA_ARGS__);       \
        if (unlikely(_i == UINT16_MAX))                                        \
            return false;                                                      \
        _i;                                                                    \
    })


#define dec_chk_buf(dst, buf, buf_len, pos, dst_len)                           \
    __extension__({                                                            \
        const uint16_t _i =                                                    \
            dec_buf((dst), (buf), (buf_len), (pos), (dst_len));                \
        if (unlikely(_i == UINT16_MAX))                                        \
            return false;                                                      \
        _i;                                                                    \
    })


bool dec_pkt_hdr_beginning(struct w_iov * const xv,
                           struct w_iov * const v,
                           struct pkt_meta * const m,
                           const bool is_clnt,
                           struct cid * const odcid,
                           uint8_t * const tok,
                           uint16_t * const tok_len,
                           const uint8_t dcid_len)

{
    m->udp_len = xv->len;

    dec_chk(&m->hdr.flags, xv->buf, xv->len, 0, 1, "0x%02x");
    m->hdr.type = pkt_type(*xv->buf);

    if (unlikely(is_lh(m->hdr.flags))) {
        dec_chk(&m->hdr.vers, xv->buf, xv->len, 1, 4, "0x%08x");

        m->hdr.hdr_len =
            dec_chk(&m->hdr.dcid.len, xv->buf, xv->len, 5, 1, "0x%02x");
        m->hdr.scid.len = m->hdr.dcid.len;
        m->hdr.dcid.len >>= 4;
        m->hdr.scid.len &= 0x0f;

        if (m->hdr.dcid.len) {
            m->hdr.dcid.len += 3;
            m->hdr.hdr_len = dec_chk_buf(&m->hdr.dcid.id, xv->buf, xv->len, 6,
                                         m->hdr.dcid.len);
        }

        if (m->hdr.scid.len) {
            m->hdr.scid.len += 3;
            m->hdr.hdr_len = dec_chk_buf(&m->hdr.scid.id, xv->buf, xv->len,
                                         m->hdr.hdr_len, m->hdr.scid.len);
        }

        // if this is a CI, the dcid len must be >= 8 bytes
        if (is_clnt == false &&
            unlikely(m->hdr.type == LH_INIT && m->hdr.dcid.len < 8)) {
            warn(DBG, "dcid len %u too short", m->hdr.dcid.len);
            return false;
        }

        if (m->hdr.vers == 0) {
            // version negotiation packet - copy raw
            memcpy(v->buf, xv->buf, xv->len);
            v->len = xv->len;
            return true;
        }

        if (m->hdr.type == LH_RTRY) {
            // decode odcid
            odcid->len = (m->hdr.flags & 0x0f) + 3;
            m->hdr.hdr_len = dec_chk_buf(&odcid->id, xv->buf, xv->len,
                                         m->hdr.hdr_len, odcid->len);
        }

        if (m->hdr.type == LH_INIT) {
            // decode token
            uint64_t tl = 0;
            m->hdr.hdr_len =
                dec_chk(&tl, xv->buf, xv->len, m->hdr.hdr_len, 0, "%" PRIu64);
            *tok_len = (uint16_t)tl;
            if (is_clnt && *tok_len) {
                // server initial pkts must have no tokens
                warn(ERR, "tok (len %u) present in serv initial", *tok_len);
                return false;
            }
        } else if (m->hdr.type == LH_RTRY)
            *tok_len = xv->len - m->hdr.hdr_len;

        if (*tok_len) {
            if (unlikely(*tok_len >= MAX_TOK_LEN ||
                         *tok_len + m->hdr.hdr_len > xv->len)) {
                // corrupt token len
                warn(DBG, "tok_len %u invalid (max %u)", *tok_len, MAX_TOK_LEN);
                return false;
            }
            m->hdr.hdr_len =
                dec_chk_buf(tok, xv->buf, xv->len, m->hdr.hdr_len, *tok_len);
        }

        if (m->hdr.type != LH_RTRY) {
            uint64_t len = 0;
            m->hdr.hdr_len =
                dec_chk(&len, xv->buf, xv->len, m->hdr.hdr_len, 0, "%" PRIu64);
            if (unlikely(m->hdr.hdr_len == UINT16_MAX))
                return false;
            m->hdr.len = (uint16_t)len;

            // sanity check len
            if (unlikely(m->hdr.len + m->hdr.hdr_len > xv->len)) {
                warn(DBG, "len %u invalid", m->hdr.len);
                return false;
            }
        }
        return true;
    }

    // this logic depends on picking a SCID with a known length during handshake
    m->hdr.dcid.len = dcid_len;
    m->hdr.hdr_len =
        dec_chk_buf(&m->hdr.dcid.id, xv->buf, xv->len, 1, m->hdr.dcid.len);
    return true;
}


bool xor_hp(struct w_iov * const xv,
            const struct pkt_meta * const m,
            const struct cipher_ctx * const ctx,
            const uint16_t pkt_nr_pos,
            const bool is_enc)
{
    const uint16_t off = pkt_nr_pos + MAX_PKT_NR_LEN;
    const uint16_t len =
        is_lh(m->hdr.flags) ? pkt_nr_pos + m->hdr.len : xv->len;
    if (unlikely(off + AEAD_LEN > len))
        return false;

    ptls_cipher_init(ctx->header_protection, &xv->buf[off]);
    uint8_t mask[MAX_PKT_NR_LEN + 1] = {0};
    ptls_cipher_encrypt(ctx->header_protection, mask, mask, sizeof(mask));

    const uint8_t orig_flags = xv->buf[0];
    xv->buf[0] ^= mask[0] & (unlikely(is_lh(m->hdr.flags)) ? 0x0f : 0x1f);
    const uint8_t pnl = pkt_nr_len(is_enc ? orig_flags : xv->buf[0]);
    for (uint8_t i = 0; i < pnl; i++)
        xv->buf[pkt_nr_pos + i] ^= mask[1 + i];

#ifdef DEBUG_MARSHALL
    warn(DBG, "%s HP over [0, %u..%u] w/sample off %u",
         is_enc ? "apply" : "undo", pkt_nr_pos, pkt_nr_pos + pnl - 1, off);
#endif

    return true;
}


static bool undo_hp(struct w_iov * const xv,
                    struct pkt_meta * const m,
                    const struct cipher_ctx * const ctx)
{
    // m->hdr.hdr_len holds the offset of the pnr field
    const uint16_t pnp = m->hdr.hdr_len;

    // undo HP and update meta
    if (unlikely(xor_hp(xv, m, ctx, pnp, false) == false))
        return false;

    m->hdr.flags = xv->buf[0];
    m->hdr.type = pkt_type(xv->buf[0]);

    const uint8_t pnl = pkt_nr_len(xv->buf[0]);
    struct pn_space * const pn = pn_for_pkt_type(m->pn->c, m->hdr.type);

    uint64_t nr = 0;
    dec_chk(&nr, xv->buf, xv->len, pnp, pnl, "%u");
    m->hdr.hdr_len += pnl;

    const uint64_t expected_pn = diet_max(&pn->recv) + 1;
    const uint64_t pn_win = UINT64_C(1) << (pnl * 8);
    const uint64_t pn_hwin = pn_win / 2;
    const uint64_t pn_mask = pn_win - 1;

    m->hdr.nr = (expected_pn & ~pn_mask) | nr;
    if (m->hdr.nr + pn_hwin <= expected_pn)
        m->hdr.nr += pn_win;
    else if (m->hdr.nr > expected_pn + pn_hwin && m->hdr.nr > pn_win)
        m->hdr.nr -= pn_win;

    return true;
}


static const struct cipher_ctx * __attribute__((nonnull))
which_cipher_ctx_in(struct q_conn * const c,
                    const uint8_t flags,
                    struct pkt_meta * const m)
{
    switch (pkt_type(flags)) {
    case LH_INIT:
    case LH_RTRY:
        m->pn = &c->pn_init.pn;
        return &c->pn_init.in;
    case LH_0RTT:
        m->pn = &c->pn_data.pn;
        return &c->pn_data.in_0rtt;
    case LH_HSHK:
        m->pn = &c->pn_hshk.pn;
        return &c->pn_hshk.in;
    default:
        // warn(ERR, "in cipher for kyph %u", is_set(SH_KYPH, flags));
        m->pn = &c->pn_data.pn;
        return &c->pn_data.in_1rtt[is_set(SH_KYPH, flags)];
    }
}


struct q_conn * is_srt(const struct w_iov * const xv, struct pkt_meta * const m)
{
    if ((m->hdr.flags & LH) != HEAD_FIXD || xv->len < 23 + SRT_LEN)
        return 0;

    uint8_t * const srt = &xv->buf[xv->len - SRT_LEN];
    struct q_conn * const c = get_conn_by_srt(srt);

    if (c && c->state != conn_drng) {
        m->is_reset = true;
        warn(DBG, "stateless reset for %s conn %s", conn_type(c),
             cid2str(c->scid));
        conn_to_state(c, conn_drng);
        enter_closing(c);
        return c;
    }
    return 0;
}


bool dec_pkt_hdr_remainder(struct w_iov * const xv,
                           struct w_iov * const v,
                           struct pkt_meta * const m,
                           struct q_conn * const c,
                           struct w_iov_sq * const x,
                           bool * const decoal)
{
    *decoal = false;
    const struct cipher_ctx * ctx = which_cipher_ctx_in(
        c,
        // the pp context does not depend on the SH kyph bit
        is_lh(m->hdr.flags) ? m->hdr.flags : m->hdr.flags & ~SH_KYPH, m);
    if (unlikely(ctx->header_protection == 0))
        return false;

    // we can now undo the packet protection
    if (unlikely(undo_hp(xv, m, ctx) == false))
        return is_srt(xv, m);

    // we can now try and decrypt the packet
    if (likely(is_lh(m->hdr.flags) == false) &&
        unlikely(is_set(SH_KYPH, m->hdr.flags) != c->pn_data.in_kyph)) {
        if (c->pn_data.out_kyph == c->pn_data.in_kyph)
            // this is a peer-initiated key phase flip
            flip_keys(c, false);
        else
            // the peer switched to a key phase that we flipped
            c->pn_data.in_kyph = c->pn_data.out_kyph;
    }

    ctx = which_cipher_ctx_in(c, m->hdr.flags, m);
    if (unlikely(ctx->aead == 0))
        return is_srt(xv, m);

    const uint16_t pkt_len = is_lh(m->hdr.flags) ? m->hdr.hdr_len + m->hdr.len -
                                                       pkt_nr_len(m->hdr.flags)
                                                 : xv->len;
    const uint16_t ret = dec_aead(xv, v, m, pkt_len, ctx);

    if (unlikely(ret == 0))
        return is_srt(xv, m);

    const uint8_t rsvd_bits =
        m->hdr.flags & (is_lh(m->hdr.flags) ? LH_RSVD_MASK : SH_RSVD_MASK);
    if (unlikely(rsvd_bits)) {
        err_close(c, ERR_PROTOCOL_VIOLATION, 0,
                  "reserved %s bits are 0x%02x (= non-zero)",
                  is_lh(m->hdr.flags) ? "LH" : "SH", rsvd_bits);
        return false;
    }

    if (unlikely(is_lh(m->hdr.flags))) {
        // check for coalesced packet
        if (unlikely(pkt_len < xv->len)) {
            *decoal = true;
            // allocate new w_iov for coalesced packet and copy it over
            struct w_iov * const dup = w_iov_dup(xv, &(struct pkt_meta *){0});
            dup->buf += pkt_len;
            dup->len -= pkt_len;
            // adjust length of first packet
            xv->len = pkt_len;
            // rx() has already removed xv from x, so just insert dup at head
            sq_insert_head(x, dup, next);
            warn(DBG, "split out coalesced %u-byte %s pkt", dup->len,
                 pkt_type_str(*dup->buf, &dup->buf[1]));
        }

    } else {
        // check if a key phase flip has been verified
        const bool v_kyph = is_set(SH_KYPH, m->hdr.flags);
        if (unlikely(v_kyph != c->pn_data.in_kyph))
            c->pn_data.in_kyph = v_kyph;

        if (c->spin_enabled && m->hdr.nr > diet_max(&(c->pn_data.pn.recv_all)))
            // short header, spin the bit
            c->spin = (is_set(SH_SPIN, m->hdr.flags) == !c->is_clnt);
    }

    v->len = xv->len - AEAD_LEN;

    if (!c->is_clnt &&
        unlikely(m->hdr.type == LH_HSHK && c->cstreams[ep_init])) {
        abandon_pn(c, ep_init);

        // server can assume path is validated
        warn(DBG, "clnt path validated");
        c->path_val_win = UINT64_MAX;
    }

    // packet protection verified OK
    struct pn_space * const pn = pn_for_pkt_type(c, m->hdr.type);
    if (diet_find(&pn->recv_all, m->hdr.nr))
        return is_srt(xv, m);

    return true;
}
