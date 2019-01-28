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

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>


#include <ev.h>
#include <picotls.h>
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


#ifndef NDEBUG
// local version of cid2str that is just hex2str (omits the seq)
#define c2s(i) hex2str((i)->id, (i)->len)

void log_pkt(const char * const dir,
             const struct w_iov * const v,
             const uint32_t ip,
             const uint16_t port,
             const struct cid * const odcid,
             const uint8_t * const tok,
             const uint16_t tok_len)
{
    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, addr, INET_ADDRSTRLEN);
    const uint16_t prt = ntohs(port);
    if (*dir == 'R') {
        if (is_lh(meta(v).hdr.flags)) {
            if (meta(v).hdr.vers == 0)
                twarn(NTE,
                      BLD BLU "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU
                              "%s " NRM "vers=0x%08x dcid=%s scid=%s",
                      addr, prt, v->len, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid));
            else if (meta(v).hdr.type == LH_RTRY)
                twarn(
                    NTE,
                    BLD BLU "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU "%s " NRM
                            "vers=0x%08x dcid=%s scid=%s odcid=%s tok=%s",
                    addr, prt, v->len, meta(v).hdr.flags,
                    pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                    meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                    c2s(&meta(v).hdr.scid), c2s(odcid), hex2str(tok, tok_len));
            else if (meta(v).hdr.type == LH_INIT)
                twarn(NTE,
                      BLD BLU
                      "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s tok=%s len=%u nr=" BLU
                      "%" PRIu64,
                      addr, prt, v->len, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), hex2str(tok, tok_len),
                      meta(v).hdr.len, meta(v).hdr.nr);
            else
                twarn(NTE,
                      BLD BLU
                      "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s len=%u nr=" BLU "%" PRIu64,
                      addr, prt, v->len, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), meta(v).hdr.len, meta(v).hdr.nr);
        } else
            twarn(NTE,
                  BLD BLU "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU "%s " NRM
                          "kyph=%u spin=%u dcid=%s nr=" BLU "%" PRIu64,
                  addr, prt, v->len, meta(v).hdr.flags,
                  pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                  is_set(SH_KYPH, meta(v).hdr.flags),
                  is_set(SH_SPIN, meta(v).hdr.flags), c2s(&meta(v).hdr.dcid),
                  meta(v).hdr.nr);

    } else {
        // on TX, v->len is not yet final/correct, so don't print it
        if (is_lh(meta(v).hdr.flags)) {
            if (meta(v).hdr.vers == 0)
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s",
                      addr, prt, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid));
            else if (meta(v).hdr.type == LH_RTRY)
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s odcid=%s tok=%s",
                      addr, prt, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), c2s(odcid),
                      hex2str(tok, tok_len));
            else if (meta(v).hdr.type == LH_INIT)
                twarn(NTE,
                      BLD GRN
                      "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s tok=%s len=%u nr=" GRN
                      "%" PRIu64,
                      addr, prt, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), hex2str(tok, tok_len),
                      meta(v).hdr.len, meta(v).hdr.nr);
            else
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s len=%u nr=" GRN
                              "%" PRIu64,
                      addr, prt, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), meta(v).hdr.len, meta(v).hdr.nr);
        } else
            twarn(NTE,
                  BLD GRN "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                          "kyph=%u spin=%u dcid=%s nr=" GRN "%" PRIu64,
                  addr, prt, meta(v).hdr.flags,
                  pkt_type_str(meta(v).hdr.flags, &meta(v).hdr.vers),
                  is_set(SH_KYPH, meta(v).hdr.flags),
                  is_set(SH_SPIN, meta(v).hdr.flags), c2s(&meta(v).hdr.dcid),
                  meta(v).hdr.nr);
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


static uint16_t __attribute__((nonnull))
enc_lh_cids(const struct cid * const dcid,
            const struct cid * const scid,
            struct w_iov * const v,
            const uint16_t pos)
{
    cid_cpy(&meta(v).hdr.dcid, dcid);
    cid_cpy(&meta(v).hdr.scid, scid);
    const uint8_t cil =
        (uint8_t)((meta(v).hdr.dcid.len ? meta(v).hdr.dcid.len - 3 : 0) << 4) |
        (uint8_t)(meta(v).hdr.scid.len ? meta(v).hdr.scid.len - 3 : 0);
    uint16_t i = enc(v->buf, v->len, pos, &cil, sizeof(cil), 0, "0x%02x");
    if (meta(v).hdr.dcid.len)
        i = enc_buf(v->buf, v->len, i, &meta(v).hdr.dcid.id,
                    meta(v).hdr.dcid.len);
    if (meta(v).hdr.scid.len)
        i = enc_buf(v->buf, v->len, i, &meta(v).hdr.scid.id,
                    meta(v).hdr.scid.len);
    return i;
}


static bool __attribute__((const))
have_space_for(const uint8_t type, const uint16_t pos, const uint16_t limit)
{
    const bool have_space = limit == 0 || pos + max_frame_len(type) < limit;
    // if (have_space == false)
    //     warn(DBG, "missing %u bytes to encode 0x%02x frame",
    //          pos + max_frame_len(type) - limit, type);
    return have_space;
}


static uint16_t __attribute__((nonnull))
enc_other_frames(struct q_conn * const c,
                 struct w_iov * const v,
                 const uint16_t pos,
                 const uint16_t lim)
{
    uint16_t i = pos;

    // encode connection control frames
    if (!c->is_clnt && c->tok_len && have_space_for(FRM_TOK, i, lim)) {
        i = enc_new_token_frame(c, v, i);
        c->tok_len = 0;
    }

    if (c->tx_path_resp && have_space_for(FRM_PRP, i, lim)) {
        i = enc_path_response_frame(c, v, i);
        c->tx_path_resp = false;
    }

    if (c->tx_retire_cid && have_space_for(FRM_RTR, i, lim)) {
        struct cid * rcid = splay_min(cids_by_seq, &c->dcids_by_seq);
        while (rcid && rcid->seq < c->dcid->seq) {
            struct cid * const next =
                splay_next(cids_by_seq, &c->dcids_by_seq, rcid);
            if (rcid->retired) {
                i = enc_retire_cid_frame(c, v, i, rcid);
                free_dcid(c, rcid);
            }
            rcid = next;
        }
    }

    if (c->tx_path_chlg && have_space_for(FRM_PCL, i, lim))
        i = enc_path_challenge_frame(c, v, i);

    if (c->tx_ncid && have_space_for(FRM_CID, i, lim))
        i = enc_new_cid_frame(c, v, i);

    if (c->blocked && have_space_for(FRM_CDB, i, lim))
        i = enc_data_blocked_frame(c, v, i);

    if (c->tx_max_data && have_space_for(FRM_MCD, i, lim))
        i = enc_max_data_frame(c, v, i);

    if (c->sid_blocked_bidi && have_space_for(FRM_SBB, i, lim))
        i = enc_streams_blocked_frame(c, v, i, true);

    if (c->sid_blocked_uni && have_space_for(FRM_SBU, i, lim))
        i = enc_streams_blocked_frame(c, v, i, false);

    if (c->tx_max_sid_bidi && have_space_for(FRM_MSB, i, lim))
        i = enc_max_streams_frame(c, v, i, true);

    if (c->tx_max_sid_uni && have_space_for(FRM_MSU, i, lim))
        i = enc_max_streams_frame(c, v, i, false);

    while (!sl_empty(&c->need_ctrl)) {
        // XXX this assumes we can encode all the ctrl frames
        struct q_stream * const s = sl_first(&c->need_ctrl);
        sl_remove_head(&c->need_ctrl, node_ctrl);
        s->in_ctrl = false;
        // encode stream control frames
        if (s->blocked && have_space_for(FRM_SDB, i, lim))
            i = enc_stream_data_blocked_frame(s, v, i);
        if (s->tx_max_stream_data && have_space_for(FRM_MSD, i, lim))
            i = enc_max_stream_data_frame(s, v, i);
    }

    return i;
}


bool enc_pkt(struct q_stream * const s,
             const bool rtx,
             const bool enc_data,
             struct w_iov * const v)
{
    if (likely(enc_data))
        // prepend the header by adjusting the buffer offset
        adj_iov_to_start(v);

    struct q_conn * const c = s->c;
    uint16_t i = 0, len_pos = 0;

    const epoch_t epoch = strm_epoch(s);
    struct pn_space * const pn = meta(v).pn = pn_for_epoch(c, epoch);

    if (unlikely(c->tx_rtry))
        meta(v).hdr.nr = 0;
    else if (unlikely(pn->lg_sent == UINT64_MAX))
        // next pkt nr
        meta(v).hdr.nr = pn->lg_sent = 0;
    else
        meta(v).hdr.nr = ++pn->lg_sent;

    switch (epoch) {
    case ep_init:
        meta(v).hdr.type = unlikely(c->tx_rtry) ? LH_RTRY : LH_INIT;
        meta(v).hdr.flags = LH | meta(v).hdr.type |
                            (unlikely(c->tx_rtry) ? c->odcid.len - 3 : 0);
        break;
    case ep_0rtt:
        if (c->is_clnt) {
            meta(v).hdr.type = LH_0RTT;
            meta(v).hdr.flags = LH | meta(v).hdr.type;
        } else
            meta(v).hdr.type = meta(v).hdr.flags = SH;
        break;
    case ep_hshk:
        meta(v).hdr.type = LH_HSHK;
        meta(v).hdr.flags = LH | meta(v).hdr.type;
        break;
    case ep_data:
        if (pn == &c->pn_data.pn) {
            meta(v).hdr.type = meta(v).hdr.flags = SH;
            meta(v).hdr.flags |= c->pn_data.out_kyph ? SH_KYPH : 0;
        } else {
            meta(v).hdr.type = LH_HSHK;
            meta(v).hdr.flags = LH | meta(v).hdr.type;
        }
        break;
    }

    if (c->spinbit_enabled && likely(is_lh(meta(v).hdr.flags) == false) &&
        c->next_spin)
        meta(v).hdr.flags |= SH_SPIN;

    ensure(meta(v).hdr.nr < (1ULL << 62) - 1, "packet number overflow");

    const uint8_t pnl = needed_pkt_nr_len(pn->lg_acked, meta(v).hdr.nr);
    meta(v).hdr.flags |= (pnl - 1);

    i = enc(v->buf, v->len, 0, &meta(v).hdr.flags, sizeof(meta(v).hdr.flags), 0,
            "0x%02x");

    if (unlikely(is_lh(meta(v).hdr.flags))) {
        meta(v).hdr.vers = c->vers;
        i = enc(v->buf, v->len, i, &c->vers, sizeof(c->vers), 0, "0x%08x");
        i = enc_lh_cids(c->dcid, c->scid, v, i);

        if (meta(v).hdr.type == LH_RTRY)
            i = enc_buf(v->buf, v->len, i, &c->odcid.id, c->odcid.len);

        if (meta(v).hdr.type == LH_INIT) {
            const uint64_t tl = c->is_clnt ? c->tok_len : 0;
            i = enc(v->buf, v->len, i, &tl, 0, 0, "%" PRIu64);
        }

        if (((c->is_clnt && meta(v).hdr.type == LH_INIT) ||
             meta(v).hdr.type == LH_RTRY) &&
            c->tok_len)
            i = enc_buf(v->buf, v->len, i, c->tok, c->tok_len);

        if (meta(v).hdr.type != LH_RTRY) {
            // leave space for length field (2 bytes is enough)
            len_pos = i;
            i += 2;
        }

    } else {
        cid_cpy(&meta(v).hdr.dcid, c->dcid);
        i = enc_buf(v->buf, v->len, i, &meta(v).hdr.dcid.id,
                    meta(v).hdr.dcid.len);
    }

    uint16_t pkt_nr_pos = 0;
    if (likely(meta(v).hdr.type != LH_RTRY)) {
        pkt_nr_pos = i;
        i = enc(v->buf, v->len, i, &meta(v).hdr.nr, pnl, 0, GRN "%u" NRM);
    }

    meta(v).hdr.hdr_len = i;
    log_pkt("TX", v, c->peer.sin_addr.s_addr, c->peer.sin_port,
            meta(v).hdr.type == LH_RTRY ? &c->odcid : 0, c->tok, c->tok_len);

    if (unlikely(meta(v).hdr.type == LH_RTRY))
        goto tx;

    if (needs_ack(pn) != no_ack)
        i = enc_ack_frame(c, pn, v, i);

    if (unlikely(c->state == conn_clsg)) {
        i = enc_close_frame(c, v, i);
        goto tx;
    }

    if (epoch == ep_data || (!c->is_clnt && epoch == ep_0rtt))
        i = enc_other_frames(c, v, i, meta(v).stream_data_start);

    if (unlikely(rtx)) {
        ensure(is_rtxable(&meta(v)), "is rtxable");

        // this is a RTX, pad out until beginning of stream header
        enc_padding_frame(v, i, meta(v).stream_header_pos - i);
        i = meta(v).stream_data_start + meta(v).stream_data_len;
        log_stream_or_crypto_frame(true, v, false, "");

    } else if (likely(enc_data)) {
        // this is a fresh data/crypto or pure stream FIN packet
        // pad out until stream_data_start and add a stream frame header
        enc_padding_frame(v, i, meta(v).stream_data_start - i);
        i = enc_stream_or_crypto_frame(s, v, i, s->id >= 0);
    }

    if (unlikely(i < MAX_PKT_LEN - AEAD_LEN && (enc_data || rtx) &&
                 (epoch == ep_data || (!c->is_clnt && epoch == ep_0rtt)))) {
        // we can try to stick some more frames in after the stream frame
        v->len = MAX_PKT_LEN - AEAD_LEN;
        i = enc_other_frames(c, v, i, v->len);
    }

    if (c->is_clnt && enc_data) {
        if (unlikely(c->try_0rtt == false && meta(v).hdr.type == LH_INIT))
            i = enc_padding_frame(v, i, MIN_INI_LEN - i - AEAD_LEN);
        if (unlikely(c->try_0rtt == true && meta(v).hdr.type == LH_0RTT &&
                     s->id >= 0))
            // if we pad the first 0-RTT pkt, peek at txq to get the CI length
            i = enc_padding_frame(
                v, i,
                MIN_INI_LEN - i - AEAD_LEN -
                    (sq_first(&c->txq) ? sq_first(&c->txq)->len : 0));
    }

    if (likely(meta(v).hdr.type != LH_RTRY))
        ensure(i > meta(v).hdr.hdr_len, "would have sent pkt w/o frames");

tx:
    // for LH pkts, now encode the length
    meta(v).hdr.len = i + AEAD_LEN - pkt_nr_pos;
    if (unlikely(len_pos)) {
        const uint64_t len = meta(v).hdr.len;
        enc(v->buf, v->len, len_pos, &len, 0, 2, "%" PRIu64);
    }

    v->len = i;

    // alloc directly from warpcore for crypto TX - no need for metadata alloc
    struct w_iov * const xv = w_alloc_iov(c->w, 0, 0);
    ensure(xv, "w_alloc_iov failed");
    // warn(CRT, "w_alloc_iov idx %u (avail %" PRIu64 ") len %u", w_iov_idx(xv),
    //      sq_len(&c->w->iov), xv->len);

    if (unlikely(meta(v).hdr.type == LH_RTRY)) {
        memcpy(xv->buf, v->buf, v->len); // copy data
        xv->len = v->len;
    } else {
        xv->len = enc_aead(c, v, xv, pkt_nr_pos);
        if (unlikely(xv->len == 0)) {
            adj_iov_to_start(v);
            return false;
        }
    }

    if (!c->is_clnt) {
        xv->ip = c->peer.sin_addr.s_addr;
        xv->port = c->peer.sin_port;
    }
    // track the flags manually, since warpcore sets them on the xv and it'd
    // require another loop to copy them over
    xv->flags = v->flags |= likely(c->sockopt.enable_ecn) ? IPTOS_ECN_ECT0 : 0;

    sq_insert_tail(&c->txq, xv, next);
    meta(v).udp_len = xv->len;
    c->out_data += meta(v).udp_len;

    if (unlikely(meta(v).hdr.type == LH_INIT && c->is_clnt &&
                 meta(v).stream_data_len))
        // adjust v->len to exclude the post-stream padding for CI
        v->len = meta(v).stream_data_start + meta(v).stream_data_len;

    if (likely(enc_data)) {
        adj_iov_to_data(v);
        // XXX not clear if changing the len before calling on_pkt_sent is ok
        v->len = meta(v).stream_data_len;
    }

    if (unlikely(rtx))
        // we did an RTX and this is no longer lost
        meta(v).is_lost = false;

    on_pkt_sent(s, v);

    if (c->is_clnt) {
        if (is_lh(meta(v).hdr.flags) == false)
            maybe_flip_keys(c, true);
        if (unlikely(meta(v).hdr.type == LH_HSHK && c->cstreams[ep_init]))
            abandon_pn(c, ep_init);
    } else if (unlikely(meta(v).hdr.type == LH_HSHK && c->cstreams[ep_init])) {
        // server can assume path is validated
        warn(DBG, "clnt path validated");
        c->path_val_win = UINT64_MAX;
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
                           const bool is_clnt,
                           struct cid * const odcid,
                           uint8_t * const tok,
                           uint16_t * const tok_len)

{
    meta(v).udp_len = xv->len;

    dec_chk(&meta(v).hdr.flags, xv->buf, xv->len, 0, 1, "0x%02x");
    meta(v).hdr.type = pkt_type(*xv->buf);

    if (unlikely(is_lh(meta(v).hdr.flags))) {
        dec_chk(&meta(v).hdr.vers, xv->buf, xv->len, 1, 4, "0x%08x");

        meta(v).hdr.hdr_len =
            dec_chk(&meta(v).hdr.dcid.len, xv->buf, xv->len, 5, 1, "0x%02x");
        meta(v).hdr.scid.len = meta(v).hdr.dcid.len;
        meta(v).hdr.dcid.len >>= 4;
        meta(v).hdr.scid.len &= 0x0f;

        if (meta(v).hdr.dcid.len) {
            meta(v).hdr.dcid.len += 3;
            meta(v).hdr.hdr_len = dec_chk_buf(&meta(v).hdr.dcid.id, xv->buf,
                                              xv->len, 6, meta(v).hdr.dcid.len);
        }

        // if this is a CI, the dcid len must be >= 8 bytes
        if (is_clnt == false &&
            unlikely(meta(v).hdr.type == LH_INIT && meta(v).hdr.dcid.len < 8)) {
            warn(DBG, "dcid len %u too short", meta(v).hdr.dcid.len);
            return false;
        }

        if (meta(v).hdr.scid.len) {
            meta(v).hdr.scid.len += 3;
            meta(v).hdr.hdr_len =
                dec_chk_buf(&meta(v).hdr.scid.id, xv->buf, xv->len,
                            meta(v).hdr.hdr_len, meta(v).hdr.scid.len);
        }

        if (meta(v).hdr.vers == 0) {
            // version negotiation packet - copy raw
            memcpy(v->buf, xv->buf, xv->len);
            v->len = xv->len;
            return true;
        }

        if (meta(v).hdr.type == LH_RTRY) {
            // decode odcid
            odcid->len = (meta(v).hdr.flags & 0x0f) + 3;
            meta(v).hdr.hdr_len = dec_chk_buf(&odcid->id, xv->buf, xv->len,
                                              meta(v).hdr.hdr_len, odcid->len);
        }

        if (meta(v).hdr.type == LH_INIT) {
            // decode token
            uint64_t tl = 0;
            meta(v).hdr.hdr_len = dec_chk(&tl, xv->buf, xv->len,
                                          meta(v).hdr.hdr_len, 0, "%" PRIu64);
            *tok_len = (uint16_t)tl;
            if (is_clnt && *tok_len) {
                // server initial pkts must have no tokens
                warn(ERR, "tok (len %u) present in serv initial", *tok_len);
                return false;
            }
        } else if (meta(v).hdr.type == LH_RTRY)
            *tok_len = xv->len - meta(v).hdr.hdr_len;

        if (*tok_len) {
            if (unlikely(*tok_len + meta(v).hdr.hdr_len > xv->len)) {
                // corrupt token len
                warn(DBG, "tok_len %u invalid", *tok_len);
                return false;
            }
            meta(v).hdr.hdr_len = dec_chk_buf(tok, xv->buf, xv->len,
                                              meta(v).hdr.hdr_len, *tok_len);
        }

        if (meta(v).hdr.type != LH_RTRY) {
            uint64_t len = 0;
            meta(v).hdr.hdr_len = dec_chk(&len, xv->buf, xv->len,
                                          meta(v).hdr.hdr_len, 0, "%" PRIu64);
            if (unlikely(meta(v).hdr.hdr_len == UINT16_MAX))
                return false;
            meta(v).hdr.len = (uint16_t)len;

            // sanity check len
            if (unlikely(meta(v).hdr.len + meta(v).hdr.hdr_len > xv->len)) {
                warn(DBG, "len %u invalid", meta(v).hdr.len);
                return false;
            }
        }
        return true;
    }

    // this logic depends on picking a SCID with a known length during handshake
    meta(v).hdr.dcid.len = (is_clnt ? CLNT_SCID_LEN : SERV_SCID_LEN);
    meta(v).hdr.hdr_len = dec_chk_buf(&meta(v).hdr.dcid.id, xv->buf, xv->len, 1,
                                      meta(v).hdr.dcid.len);
    return true;
}


bool xor_hp(const struct w_iov * const xv,
            const struct w_iov * const v,
            const struct cipher_ctx * const ctx,
            const uint16_t pkt_nr_pos,
            const bool is_enc)
{
    const uint16_t off = pkt_nr_pos + MAX_PKT_NR_LEN;
    const uint16_t len =
        is_lh(meta(v).hdr.flags) ? pkt_nr_pos + meta(v).hdr.len : xv->len;
    if (unlikely(off > len))
        return false;

    uint8_t sample[AEAD_LEN] = {0};
    const uint16_t sample_len =
        unlikely(off + AEAD_LEN > len) ? len - off : AEAD_LEN;
    memcpy(sample, &xv->buf[off], sample_len);
    ptls_cipher_init(ctx->header_protection, sample);

    uint8_t mask[MAX_PKT_NR_LEN + 1] = {0};
    ptls_cipher_encrypt(ctx->header_protection, mask, mask, sizeof(mask));

    const uint8_t orig_flags = xv->buf[0];
    xv->buf[0] ^= mask[0] & (unlikely(is_lh(meta(v).hdr.flags)) ? 0x0f : 0x1f);
    const uint8_t pnl = pkt_nr_len(is_enc ? orig_flags : xv->buf[0]);
    for (uint8_t i = 0; i < pnl; i++)
        xv->buf[pkt_nr_pos + i] ^= mask[1 + i];

#ifdef DEBUG_MARSHALL
    warn(DBG, "%s HP over [0, %u..%u] w/sample off %u (len %u)",
         is_enc ? "apply" : "undo", pkt_nr_pos, pkt_nr_pos + pnl - 1, off,
         sample_len);
#endif

    return true;
}


static bool undo_hp(const struct w_iov * const xv,
                    const struct w_iov * const v,
                    struct q_conn * const c,
                    const struct cipher_ctx * const ctx)
{
    // meta(v).hdr.hdr_len holds the offset of the pnr field
    const uint16_t pnp = meta(v).hdr.hdr_len;

    // undo HP and update meta(v)
    if (unlikely(xor_hp(xv, v, ctx, pnp, false) == false))
        return false;

    meta(v).hdr.flags = xv->buf[0];
    meta(v).hdr.type = pkt_type(xv->buf[0]);

    const uint8_t pnl = pkt_nr_len(xv->buf[0]);
    struct pn_space * const pn = pn_for_pkt_type(c, meta(v).hdr.type);

    uint64_t nr = 0;
    dec_chk(&nr, xv->buf, xv->len, pnp, pnl, "%u");
    meta(v).hdr.hdr_len += pnl;

    const uint64_t expected_pn = diet_max(&pn->recv) + 1;
    const uint64_t pn_win = UINT64_C(1) << (pnl * 8);
    const uint64_t pn_hwin = pn_win / 2;
    const uint64_t pn_mask = pn_win - 1;

    meta(v).hdr.nr = (expected_pn & ~pn_mask) | nr;
    if (meta(v).hdr.nr + pn_hwin <= expected_pn)
        meta(v).hdr.nr += pn_win;
    else if (meta(v).hdr.nr > expected_pn + pn_hwin && meta(v).hdr.nr > pn_win)
        meta(v).hdr.nr -= pn_win;

    return true;
}


static const struct cipher_ctx * __attribute__((nonnull))
which_cipher_ctx_in(const struct q_conn * const c, const uint8_t flags)
{
    switch (pkt_type(flags)) {
    case LH_INIT:
    case LH_RTRY:
        return &c->pn_init.in;
    case LH_0RTT:
        return &c->pn_data.in_0rtt;
    case LH_HSHK:
        return &c->pn_hshk.in;
    default:
        // warn(ERR, "in cipher for kyph %u", is_set(SH_KYPH, flags));
        return &c->pn_data.in_1rtt[is_set(SH_KYPH, flags)];
    }
}


bool dec_pkt_hdr_remainder(struct w_iov * const xv,
                           struct w_iov * const v,
                           struct q_conn * const c,
                           struct w_iov_sq * const x,
                           bool * const decoal)
{
    *decoal = false;
    const struct cipher_ctx * ctx = which_cipher_ctx_in(
        c,
        // the pp context does not depend on the SH kyph bit
        is_lh(meta(v).hdr.flags) ? meta(v).hdr.flags
                                 : meta(v).hdr.flags & ~SH_KYPH);
    if (unlikely(ctx->header_protection == 0))
        return false;

    // we can now undo the packet protection
    if (unlikely(undo_hp(xv, v, c, ctx) == false))
        goto check_if_reset;

    // we can now try and decrypt the packet
    if (likely(is_lh(meta(v).hdr.flags) == false) &&
        unlikely(is_set(SH_KYPH, meta(v).hdr.flags) != c->pn_data.in_kyph)) {
        if (c->pn_data.out_kyph == c->pn_data.in_kyph)
            // this is a peer-initiated key phase flip
            flip_keys(c, false);
        else
            // the peer switched to a key phase that we flipped
            c->pn_data.in_kyph = c->pn_data.out_kyph;
    }

    ctx = which_cipher_ctx_in(c, meta(v).hdr.flags);
    if (unlikely(ctx->aead == 0))
        goto check_if_reset;

    const uint16_t pkt_len = is_lh(meta(v).hdr.flags)
                                 ? meta(v).hdr.hdr_len + meta(v).hdr.len -
                                       pkt_nr_len(meta(v).hdr.flags)
                                 : xv->len;
    const uint16_t ret = dec_aead(c, xv, v, pkt_len, ctx);

    if (unlikely(ret == 0)) {
    check_if_reset:
        // AEAD failed; this might be a stateless reset
        if ((meta(v).hdr.flags & LH) == HEAD_FIXD &&
            xv->len >= 23 + sizeof(c->dcid->srt) &&
            memcmp(&xv->buf[xv->len - sizeof(c->dcid->srt)], c->dcid->srt,
                   sizeof(c->dcid->srt)) == 0) {
            if (c->state != conn_drng)
                conn_to_state(c, conn_drng);
            meta(v).is_reset = true;
            return true;
        }
        return false;
    }

    const uint8_t rsvd_bits =
        meta(v).hdr.flags &
        (is_lh(meta(v).hdr.flags) ? LH_RSVD_MASK : SH_RSVD_MASK);
    if (unlikely(rsvd_bits)) {
        warn(ERR, "reserved %s bits are 0x%02x (= non-zero)",
             is_lh(meta(v).hdr.flags) ? "LH" : "SH", rsvd_bits);
        return false;
    }

    if (unlikely(is_lh(meta(v).hdr.flags))) {
        // check for coalesced packet
        if (unlikely(pkt_len < xv->len)) {
            *decoal = true;
            // allocate new w_iov for coalesced packet and copy it over
            struct w_iov * const dup = w_iov_dup(xv);
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
        const bool v_kyph = is_set(SH_KYPH, meta(v).hdr.flags);
        if (unlikely(v_kyph != c->pn_data.in_kyph))
            c->pn_data.in_kyph = v_kyph;

        if (c->spinbit_enabled &&
            meta(v).hdr.nr > diet_max(&(c->pn_data.pn.recv_all)))
            // short header, spin the bit
            c->next_spin = (is_set(SH_SPIN, meta(v).hdr.flags) == !c->is_clnt);
    }

    v->len = xv->len - AEAD_LEN;

    if (!c->is_clnt &&
        unlikely(meta(v).hdr.type == LH_HSHK && c->cstreams[ep_init]))
        abandon_pn(c, ep_init);

    // packet protection verified OK
    struct pn_space * const pn = pn_for_pkt_type(c, meta(v).hdr.type);
    if (diet_find(&pn->recv_all, meta(v).hdr.nr)) {
        warn(ERR, "duplicate pkt nr " FMT_PNR_IN ", ignoring", meta(v).hdr.nr);
        return false;
    }

    diet_insert(&pn->recv, meta(v).hdr.nr, ev_now(loop));
    diet_insert(&pn->recv_all, meta(v).hdr.nr, ev_now(loop));

    return true;
}


void tx_vneg_resp(const struct w_sock * const ws, const struct w_iov * const v)
{
    if (unlikely(v->ip == 0 && v->port == 0)) {
        warn(ERR, "no destination info in orig w_iov");
        return;
    }

    struct w_iov * const xv = alloc_iov(ws->w, 0, 0);
    struct w_iov_sq q = w_iov_sq_initializer(q);
    sq_insert_head(&q, xv, next);

    warn(INF, "sending vneg serv response");
    meta(xv).hdr.flags = HEAD_FORM | (uint8_t)w_rand();
    uint16_t i = enc(xv->buf, xv->len, 0, &meta(xv).hdr.flags,
                     sizeof(meta(xv).hdr.flags), 0, "0x%02x");

    i = enc(xv->buf, xv->len, i, &meta(xv).hdr.vers, sizeof(meta(xv).hdr.vers),
            0, "0x%08x");

    i = enc_lh_cids(&meta(v).hdr.scid, &meta(v).hdr.dcid, xv, i);

    for (uint8_t j = 0; j < ok_vers_len; j++)
        if (!is_force_vneg_vers(ok_vers[j]))
            i = enc(xv->buf, xv->len, i, &ok_vers[j], sizeof(ok_vers[j]), 0,
                    "0x%08x");

    xv->len = i;
    xv->ip = v->ip;
    xv->port = v->port;
    xv->flags = v->flags;
    log_pkt("TX", xv, xv->ip, xv->port, 0, 0, 0);

    w_tx(ws, &q);
    while (w_tx_pending(&q))
        w_nic_tx(ws->w);

    q_free(&q);
}


uint32_t clnt_vneg(const uint8_t * const buf, const uint16_t len)
{
    uint16_t pos = 0;
    for (uint8_t i = 0; i < ok_vers_len; i++) {
        if (is_rsvd_vers(ok_vers[i]) || is_force_vneg_vers(ok_vers[i]))
            // skip over reserved and vneg-trigger versions in our local list
            continue;

        for (uint8_t j = 0; j < len - pos; j += sizeof(ok_vers[0])) {
            uint32_t vers = 0;
            dec(&vers, buf, len, pos + j, sizeof(vers), "0x%08x");

            if (is_rsvd_vers(vers) || is_force_vneg_vers(vers))
                // skip over reserved and vneg-trigger versions in server's list
                continue;

            warn(DBG, "serv prio %ld = 0x%08x; our prio %u = 0x%08x",
                 j / sizeof(vers), vers, i, ok_vers[i]);
            if (ok_vers[i] == vers)
                return vers;
        }
    }

    // we're out of matching candidates
    warn(INF, "no vers in common with serv");
    return 0;
}
