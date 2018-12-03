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

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

// IWYU pragma: no_include <picotls/../picotls.h>

#include <ev.h>
#include <picotls.h> // IWYU pragma: keep
#include <picotls/openssl.h>
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
static const char * __attribute__((const))
pkt_type_str(const uint8_t flags, const uint8_t * const vers)
{
    if (is_set(F_LONG_HDR, flags)) {
        if (vers[0] == 0 && vers[1] == 0 && vers[2] == 0 && vers[3] == 0)
            return "Version Negotiation";
        switch (pkt_type(flags)) {
        case F_LH_INIT:
            return "Initial";
        case F_LH_RTRY:
            return "Retry";
        case F_LH_HSHK:
            return "Handshake";
        case F_LH_0RTT:
            return "0-RTT Protected";
        }
    } else if (is_set(F_SH, flags & F_SH_MASK))
        return "Short";
    return RED "Unknown" NRM;
}


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
        if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
            if (meta(v).hdr.vers == 0)
                twarn(NTE,
                      BLD BLU "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU
                              "%s " NRM "vers=0x%08x dcid=%s scid=%s",
                      addr, prt, v->len, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags,
                                   (uint8_t *)&meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid));
            else if (meta(v).hdr.type == F_LH_RTRY)
                twarn(
                    NTE,
                    BLD BLU "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU "%s " NRM
                            "vers=0x%08x dcid=%s scid=%s odcid=%s tok=%s",
                    addr, prt, v->len, meta(v).hdr.flags,
                    pkt_type_str(meta(v).hdr.flags,
                                 (uint8_t *)&meta(v).hdr.vers),
                    meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                    c2s(&meta(v).hdr.scid), c2s(odcid), hex2str(tok, tok_len));
            else if (meta(v).hdr.type == F_LH_INIT)
                twarn(NTE,
                      BLD BLU
                      "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s tok=%s len=%u nr=" BLU
                      "%" PRIu64,
                      addr, prt, v->len, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags,
                                   (uint8_t *)&meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), hex2str(tok, tok_len),
                      meta(v).hdr.len, meta(v).hdr.nr);
            else
                twarn(NTE,
                      BLD BLU
                      "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s len=%u nr=" BLU "%" PRIu64,
                      addr, prt, v->len, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags,
                                   (uint8_t *)&meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), meta(v).hdr.len, meta(v).hdr.nr);
        } else
            twarn(NTE,
                  BLD BLU "RX" NRM " from=%s:%u len=%u 0x%02x=" BLU "%s " NRM
                          "kyph=%u dcid=%s nr=" BLU "%" PRIu64,
                  addr, prt, v->len, meta(v).hdr.flags,
                  pkt_type_str(meta(v).hdr.flags, (uint8_t *)&meta(v).hdr.vers),
                  is_set(F_SH_KYPH, meta(v).hdr.flags), c2s(&meta(v).hdr.dcid),
                  meta(v).hdr.nr);

    } else {
        // on TX, v->len is not yet final/correct, so don't print it
        if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
            if (meta(v).hdr.vers == 0)
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s",
                      addr, prt, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags,
                                   (uint8_t *)&meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid));
            else if (meta(v).hdr.type == F_LH_RTRY)
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s odcid=%s tok=%s",
                      addr, prt, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags,
                                   (uint8_t *)&meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), c2s(odcid),
                      hex2str(tok, tok_len));
            else if (meta(v).hdr.type == F_LH_INIT)
                twarn(NTE,
                      BLD GRN
                      "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s tok=%s len=%u nr=" GRN
                      "%" PRIu64,
                      addr, prt, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags,
                                   (uint8_t *)&meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), hex2str(tok, tok_len),
                      meta(v).hdr.len, meta(v).hdr.nr);
            else
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s len=%u nr=" GRN
                              "%" PRIu64,
                      addr, prt, meta(v).hdr.flags,
                      pkt_type_str(meta(v).hdr.flags,
                                   (uint8_t *)&meta(v).hdr.vers),
                      meta(v).hdr.vers, c2s(&meta(v).hdr.dcid),
                      c2s(&meta(v).hdr.scid), meta(v).hdr.len, meta(v).hdr.nr);
        } else
            twarn(NTE,
                  BLD GRN "TX" NRM " to=%s:%u 0x%02x=" GRN "%s " NRM
                          "kyph=%u dcid=%s nr=" GRN "%" PRIu64,
                  addr, prt, meta(v).hdr.flags,
                  pkt_type_str(meta(v).hdr.flags, (uint8_t *)&meta(v).hdr.vers),
                  is_set(F_SH_KYPH, meta(v).hdr.flags), c2s(&meta(v).hdr.dcid),
                  meta(v).hdr.nr);
    }
}
#endif


static bool __attribute__((const))
can_coalesce_pkt_types(const uint8_t a, const uint8_t b)
{
    return (a == F_LH_INIT && (b == F_LH_0RTT || b == F_LH_HSHK)) ||
           (a == F_LH_HSHK && b == F_SH) || (a == F_LH_0RTT && b == F_LH_HSHK);
}


void coalesce(struct w_iov_sq * const q)
{
    struct w_iov * v = sq_first(q);
    while (v) {
        struct w_iov * next = sq_next(v, next);
        uint8_t cur_flags = *v->buf;

        struct w_iov * prev = v;
        while (next) {
            struct w_iov * const next_next = sq_next(next, next);

            // do we have space? do the packet types make sense to coalesce?
            if (v->len + next->len <= kMaxDatagramSize &&
                can_coalesce_pkt_types(pkt_type(cur_flags),
                                       pkt_type(*next->buf))) {
                // we can coalesce
                warn(DBG, "coalescing 0x%02x len %u behind 0x%02x len %u",
                     *next->buf, next->len, cur_flags, v->len);
                memcpy(v->buf + v->len, next->buf, next->len);
                v->len += next->len;
                cur_flags = *next->buf;
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


static uint8_t __attribute__((nonnull))
needed_pkt_nr_len(struct pn_space * const pn, const uint64_t n)
{
    const uint64_t d =
        (n - (unlikely(pn->lg_acked == UINT64_MAX) ? 0 : pn->lg_acked)) * 2;
    if (d <= 0x7F)
        return 1;
    if (d <= 0x3FFF)
        return 2;
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
enc_other_frames(struct q_stream * const s,
                 struct w_iov * const v,
                 const uint16_t pos,
                 const uint16_t lim)
{
    struct q_conn * const c = s->c;
    uint16_t i = pos;

    // encode connection control frames
    if (!c->is_clnt && c->tok_len &&
        have_space_for(FRAM_TYPE_NEW_TOKN, i, lim)) {
        i = enc_new_token_frame(c, v, i);
        c->tok_len = 0;
    }

    if (c->tx_path_resp && have_space_for(FRAM_TYPE_PATH_RESP, i, lim)) {
        i = enc_path_response_frame(c, v, i);
        c->tx_path_resp = false;
    }

    if (c->tx_retire_cid && have_space_for(FRAM_TYPE_RTIR_CID, i, lim)) {
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

    if (c->tx_path_chlg && have_space_for(FRAM_TYPE_PATH_CHLG, i, lim))
        i = enc_path_challenge_frame(c, v, i);

    if (c->tx_ncid && have_space_for(FRAM_TYPE_NEW_CID, i, lim))
        i = enc_new_cid_frame(c, v, i);

    if (c->blocked && have_space_for(FRAM_TYPE_BLCK, i, lim))
        i = enc_blocked_frame(c, v, i);

    if (c->tx_max_data && have_space_for(FRAM_TYPE_MAX_DATA, i, lim))
        i = enc_max_data_frame(c, v, i);

    if (c->sid_blocked_bidi && have_space_for(FRAM_TYPE_SID_BLCK, i, lim))
        i = enc_stream_id_blocked_frame(c, v, i, true);

    if (c->sid_blocked_uni && have_space_for(FRAM_TYPE_SID_BLCK, i, lim))
        i = enc_stream_id_blocked_frame(c, v, i, false);

    if (c->tx_max_sid_bidi && have_space_for(FRAM_TYPE_MAX_SID, i, lim))
        i = enc_max_stream_id_frame(c, v, i, true);

    if (c->tx_max_sid_uni && have_space_for(FRAM_TYPE_MAX_SID, i, lim))
        i = enc_max_stream_id_frame(c, v, i, false);

    if (s->id >= 0) {
        // encode stream control frames
        if (s->blocked && have_space_for(FRAM_TYPE_SID_BLCK, i, lim))
            i = enc_stream_blocked_frame(s, v, i);

        if (s->tx_max_stream_data &&
            have_space_for(FRAM_TYPE_MAX_STRM_DATA, i, lim))
            i = enc_max_stream_data_frame(s, v, i);
    }

    return i;
}


bool enc_pkt(struct q_stream * const s,
             const bool rtx,
             const bool enc_data,
             struct w_iov * const v)
{
    if (enc_data)
        // prepend the header by adjusting the buffer offset
        adj_iov_to_start(v);

    struct q_conn * const c = s->c;
    uint16_t i = 0, len_pos = 0;

    const epoch_t epoch = strm_epoch(s);
    struct pn_space * const pn = pn_for_epoch(c, epoch);
    meta(v).pn = pn;

    if (c->tx_rtry)
        meta(v).hdr.nr = 0;
    else if (pn->lg_sent == UINT64_MAX)
        // next pkt nr
        meta(v).hdr.nr = pn->lg_sent = 0;
    else
        meta(v).hdr.nr = ++pn->lg_sent;

    switch (epoch) {
    case ep_init:
        meta(v).hdr.type = c->tx_rtry ? F_LH_RTRY : F_LH_INIT;
        meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;

        if (c->is_clnt == false && rtx == false) {
            // this is a new connection; server picks a new random cid
            struct cid nscid = {.len = SERV_SCID_LEN};
            ptls_openssl_random_bytes(nscid.id, nscid.len);
            ptls_openssl_random_bytes(nscid.srt, sizeof(nscid.srt));
            warn(NTE, "hshk switch to scid %s for %s conn (was %s)",
                 cid2str(&nscid), conn_type(c), cid2str(c->scid));
            cid_cpy(&c->odcid, c->scid);
            update_act_scid(c, &nscid);
        }
        break;
    case ep_0rtt:
        if (c->is_clnt) {
            meta(v).hdr.type = F_LH_0RTT;
            meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        } else
            meta(v).hdr.type = meta(v).hdr.flags = F_SH;
        break;
    case ep_hshk:
        meta(v).hdr.type = F_LH_HSHK;
        meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        break;
    case ep_data:
        if (pn == &c->pn_data.pn) {
            meta(v).hdr.type = meta(v).hdr.flags = F_SH;
            meta(v).hdr.flags |= c->pn_data.out_kyph ? F_SH_KYPH : 0;
        } else {
            meta(v).hdr.type = F_LH_HSHK;
            meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        }
        break;
    }

    if (is_set(F_LONG_HDR, meta(v).hdr.flags) == false) {
#ifdef SPINBIT
        // clear spin/vec
        meta(v).hdr.flags &= ~F_SH_EXP_MASK;

        // set spin bit
        if (c->next_spin)
            meta(v).hdr.flags |= F_SH_SPIN;

        warn(DBG, "setting spin bit to %02x",
             meta(v).hdr.flags & F_SH_EXP_MASK);
#else
        // for giggles, randomize the reserved bits in the short header
        // this doesn't need to be cryptographically random
        meta(v).hdr.flags |= (w_rand() & F_SH_EXP_MASK);
#endif
    }

    ensure(meta(v).hdr.nr < (1ULL << 62) - 1, "packet number overflow");

    i = enc(v->buf, v->len, 0, &meta(v).hdr.flags, sizeof(meta(v).hdr.flags), 0,
            "0x%02x");

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        meta(v).hdr.vers = c->vers;
        i = enc(v->buf, v->len, i, &c->vers, sizeof(c->vers), 0, "0x%08x");
        i = enc_lh_cids(c->dcid, c->scid, v, i);

        if (meta(v).hdr.type == F_LH_RTRY) {
            // don't need cryptographically random bit here
            const uint8_t odcil = (uint8_t)((w_rand() & 0xf) << 4) |
                                  (c->odcid.len ? c->odcid.len - 3 : 0);
            i = enc(v->buf, v->len, i, &odcil, sizeof(odcil), 0, "0x%02x");
            if (c->odcid.len)
                i = enc_buf(v->buf, v->len, i, &c->odcid.id, c->odcid.len);
        }

        if (meta(v).hdr.type == F_LH_INIT) {
            const uint64_t tl = c->is_clnt ? c->tok_len : 0;
            i = enc(v->buf, v->len, i, &tl, 0, 0, "%" PRIu64);
        }

        if (((c->is_clnt && meta(v).hdr.type == F_LH_INIT) ||
             meta(v).hdr.type == F_LH_RTRY) &&
            c->tok_len)
            i = enc_buf(v->buf, v->len, i, c->tok, c->tok_len);

        if (meta(v).hdr.type != F_LH_RTRY) {
            // leave space for length field (2 bytes is enough)
            len_pos = i;
            i += 2;
        }

    } else {
        cid_cpy(&meta(v).hdr.dcid, c->dcid);
        i = enc_buf(v->buf, v->len, i, &meta(v).hdr.dcid.id,
                    meta(v).hdr.dcid.len);
    }

    if (meta(v).hdr.type != F_LH_RTRY) {
        meta(v).pkt_nr_pos = i;
        meta(v).pkt_nr_len = needed_pkt_nr_len(pn, meta(v).hdr.nr);
        i = enc_pnr(v->buf, v->len, i, &meta(v).hdr.nr, meta(v).pkt_nr_len,
                    "%u");
    }

    meta(v).hdr.hdr_len = i;
    log_pkt("TX", v, c->peer.sin_addr.s_addr, c->peer.sin_port,
            meta(v).hdr.type == F_LH_RTRY ? &c->odcid : 0, c->tok, c->tok_len);

    if (meta(v).hdr.type == F_LH_RTRY)
        goto tx;

    if (needs_ack(pn))
        i = enc_ack_frame(c, pn, v, i);

    if (c->state == conn_clsg) {
        i = enc_close_frame(c, v, i);
        goto tx;
    }

    if (epoch == ep_data || (!c->is_clnt && epoch == ep_0rtt))
        i = enc_other_frames(s, v, i, meta(v).stream_data_start);

    if (rtx) {
        ensure(is_rtxable(&meta(v)), "is rtxable");

        // this is a RTX, pad out until beginning of stream header
        enc_padding_frame(v, i, meta(v).stream_header_pos - i);
        i = meta(v).stream_data_start + meta(v).stream_data_len;
        log_stream_or_crypto_frame(true, v, false, "");

    } else if (enc_data) {
        // this is a fresh data/crypto or pure stream FIN packet
        // pad out until stream_data_start and add a stream frame header
        enc_padding_frame(v, i, meta(v).stream_data_start - i);
        i = enc_stream_or_crypto_frame(s, v, i, s->id >= 0);
    }

    if (i < MAX_PKT_LEN - AEAD_LEN && (enc_data || rtx) &&
        (epoch == ep_data || (!c->is_clnt && epoch == ep_0rtt))) {
        // we can try to stick some more frames in after the stream frame
        v->len = MAX_PKT_LEN - AEAD_LEN;
        i = enc_other_frames(s, v, i, v->len);
    }

    if (c->is_clnt && enc_data) {
        if (c->try_0rtt == false && meta(v).hdr.type == F_LH_INIT)
            i = enc_padding_frame(v, i, MIN_INI_LEN - i - AEAD_LEN);
        if (c->try_0rtt == true && meta(v).hdr.type == F_LH_0RTT && s->id >= 0)
            // if we pad the first 0-RTT pkt, peek at txq to get the CI length
            i = enc_padding_frame(
                v, i,
                MIN_INI_LEN - i - AEAD_LEN -
                    (sq_first(&c->txq) ? sq_first(&c->txq)->len : 0));
    }

    if (meta(v).hdr.type != F_LH_RTRY)
        ensure(i > meta(v).hdr.hdr_len, "would have sent pkt w/o frames");

tx:
    // for LH pkts, now encode the length
    meta(v).hdr.len = i + AEAD_LEN - meta(v).pkt_nr_pos;
    if (len_pos) {
        const uint64_t len = meta(v).hdr.len;
        enc(v->buf, v->len, len_pos, &len, 0, 2, "%" PRIu64);
    }

    v->len = i;

    // alloc directly from warpcore for crypto TX - no need for metadata alloc
    struct w_iov * const x = w_alloc_iov(c->w, 0, 0);
    ensure(x, "w_alloc_iov failed");
    // warn(CRT, "w_alloc_iov idx %u (avail %" PRIu64 ") len %u", w_iov_idx(x),
    //      sq_len(&c->w->iov), x->len);

    if (meta(v).hdr.type == F_LH_RTRY) {
        memcpy(x->buf, v->buf, v->len); // copy data
        x->len = v->len;
    } else {
        x->len = enc_aead(c, v, x);
        if (unlikely(x->len == 0)) {
            adj_iov_to_start(v);
            return false;
        }
    }

    if (!c->is_clnt) {
        x->ip = c->peer.sin_addr.s_addr;
        x->port = c->peer.sin_port;
    }
    x->flags = v->flags;

    sq_insert_tail(&c->txq, x, next);
    meta(v).tx_len = x->len;

    if (unlikely(meta(v).hdr.type == F_LH_INIT && c->is_clnt &&
                 meta(v).stream_data_len))
        // adjust v->len to exclude the post-stream padding for CI
        v->len = meta(v).stream_data_start + meta(v).stream_data_len;

    if (enc_data) {
        adj_iov_to_data(v);
        // XXX not clear if changing the len before calling on_pkt_sent is ok
        v->len = meta(v).stream_data_len;
    }

    if (unlikely(rtx))
        // we did an RTX and this is no longer lost
        meta(v).is_lost = false;

    on_pkt_sent(s, v);
    if (c->is_clnt && is_set(F_LONG_HDR, meta(v).hdr.flags) == false)
        maybe_flip_keys(c, true);
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
        const uint16_t _i = dec_buf((dst), (buf), (buf_len), (pos), dst_len);  \
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
    // remember original datagram len (unless already set during decoalescing)
    if (likely(xv->user_data == 0))
        xv->user_data = xv->len;

    dec_chk(&meta(v).hdr.flags, xv->buf, xv->len, 0, 1, "0x%02x");
    meta(v).hdr.type = pkt_type(*xv->buf);

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        dec_chk(&meta(v).hdr.vers, xv->buf, xv->len, 1, 4, "0x%08x");

        // check if the packet type/version combo makes sense
        if (meta(v).hdr.vers &&
            (meta(v).hdr.type > F_LH_INIT || meta(v).hdr.type < F_LH_0RTT)) {
            warn(DBG, "illegal LH pkt type 0x%02x", meta(v).hdr.type);
            return false;
        }


        meta(v).hdr.hdr_len =
            dec_chk(&meta(v).hdr.dcid.len, xv->buf, xv->len, 5, 1, "0x%02x");

        meta(v).hdr.dcid.len >>= 4;
        if (meta(v).hdr.dcid.len) {
            meta(v).hdr.dcid.len += 3;
            meta(v).hdr.hdr_len = dec_chk_buf(&meta(v).hdr.dcid.id, xv->buf,
                                              xv->len, 6, meta(v).hdr.dcid.len);
        }

        // if this is a CI, the dcid len must be >= 8 bytes
        if (is_clnt == false && unlikely(meta(v).hdr.type == F_LH_INIT &&
                                         meta(v).hdr.dcid.len < 8)) {
            warn(DBG, "dcid len %u too short", meta(v).hdr.dcid.len);
            return false;
        }

        dec(&meta(v).hdr.scid.len, xv->buf, xv->len, 5, 1, "0x%02x");
        meta(v).hdr.scid.len &= 0x0f;
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

        if (meta(v).hdr.type == F_LH_RTRY) {
            // decode odcid
            meta(v).hdr.hdr_len = dec(&odcid->len, xv->buf, xv->len,
                                      meta(v).hdr.hdr_len, 1, "0x%02x");
            odcid->len = (odcid->len & 0x0f) + 3;
            meta(v).hdr.hdr_len = dec_chk_buf(&odcid->id, xv->buf, xv->len,
                                              meta(v).hdr.hdr_len, odcid->len);
        }

        if (meta(v).hdr.type == F_LH_INIT) {
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
        } else if (meta(v).hdr.type == F_LH_RTRY)
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

        if (meta(v).hdr.type != F_LH_RTRY) {
            uint64_t len = 0;
            meta(v).hdr.hdr_len =
                dec(&len, xv->buf, xv->len, meta(v).hdr.hdr_len, 0, "%" PRIu64);
            if (unlikely(meta(v).hdr.hdr_len == UINT16_MAX))
                return false;
            meta(v).hdr.len = (uint16_t)len;

            // the len cannot be larger than the rx'ed pkt
            if (unlikely(meta(v).hdr.len + meta(v).hdr.hdr_len > xv->len)) {
                warn(DBG, "len %u invalid", meta(v).hdr.len);
                return false;
            }
        }

        return true;
    }

    // this is possibly a short-header packet
    if (unlikely(is_set(F_SH, meta(v).hdr.flags & F_SH_MASK) == false)) {
        warn(DBG, "illegal SH pkt type 0x%02x", meta(v).hdr.flags);
        return false;
    }

    // this logic depends on picking a SCID with a known length during handshake
    meta(v).hdr.dcid.len = (is_clnt ? CLNT_SCID_LEN : SERV_SCID_LEN);
    meta(v).hdr.hdr_len = dec_chk_buf(&meta(v).hdr.dcid.id, xv->buf, xv->len, 1,
                                      meta(v).hdr.dcid.len);
    return true;
}


static bool dec_pne(struct w_iov * const xv,
                    struct w_iov * const v,
                    struct q_conn * const c,
                    const struct cipher_ctx * const ctx,
                    uint8_t pn_enc[MAX_PKT_NR_LEN])
{
    // meta(v).hdr.hdr_len holds the offset of the pnr field
    meta(v).pkt_nr_pos = meta(v).hdr.hdr_len;
    uint16_t off = meta(v).pkt_nr_pos + MAX_PKT_NR_LEN;
    const uint16_t len = is_set(F_LONG_HDR, meta(v).hdr.flags)
                             ? meta(v).pkt_nr_pos + meta(v).hdr.len + AEAD_LEN
                             : xv->len;
    if (unlikely(off + AEAD_LEN > len))
        off = len - AEAD_LEN;

    ptls_cipher_init(ctx->pne, &xv->buf[off]);
    uint8_t dec_nr[MAX_PKT_NR_LEN];
    ptls_cipher_encrypt(ctx->pne, dec_nr, &xv->buf[meta(v).pkt_nr_pos],
                        sizeof(dec_nr));

    struct pn_space * const pn = pn_for_pkt_type(c, meta(v).hdr.type);
    const uint64_t next = diet_max(&pn->recv) + 1;
    uint64_t nr = next;
    meta(v).pkt_nr_len =
        (uint8_t)dec_pnr(&nr, dec_nr, sizeof(dec_nr), 0, FMT_PNR_IN);
    if (unlikely(meta(v).pkt_nr_len > MAX_PKT_NR_LEN)) {
        warn(DBG, "can't undo PNE");
        return false;
    }

    // save the raw pkt nr data, in case we need to retry
    memcpy(pn_enc, &xv->buf[meta(v).pkt_nr_pos], MAX_PKT_NR_LEN);

    // now overwrite with decoded data
    memcpy(&xv->buf[meta(v).pkt_nr_pos], &dec_nr, meta(v).pkt_nr_len);

    const uint8_t lens[] = {0xff, 7, 14, 0xff, 30};
    const uint64_t alt = nr + (UINT64_C(1) << lens[meta(v).pkt_nr_len]);
    const uint64_t d1 = next >= nr ? next - nr : nr - next;
    const uint64_t d2 = next >= alt ? next - alt : alt - next;
    meta(v).hdr.nr = d1 < d2 ? nr : alt;
    meta(v).hdr.hdr_len += meta(v).pkt_nr_len;

#ifdef DEBUG_MARSHALL
    warn(DBG, "dec PNE over [%u..%u] w/off %u = " FMT_PNR_IN,
         meta(v).pkt_nr_pos, meta(v).pkt_nr_pos + meta(v).pkt_nr_len - 1, off,
         meta(v).hdr.nr);
#endif

    return true;
}


static const struct cipher_ctx * __attribute__((nonnull))
which_cipher_ctx_in(const struct q_conn * const c, const uint8_t flags)
{
    switch (pkt_type(flags)) {
    case F_LH_INIT:
    case F_LH_RTRY:
        return &c->pn_init.in;
    case F_LH_0RTT:
        return &c->pn_data.in_0rtt;
    case F_LH_HSHK:
        return &c->pn_hshk.in;
    default:
        return &c->pn_data.in_1rtt[is_set(F_SH_KYPH, flags)];
    }
}


bool dec_pkt_hdr_remainder(struct w_iov * const xv,
                           struct w_iov * const v,
                           struct q_conn * const c,
                           struct w_iov_sq * const x)
{
    const struct cipher_ctx * ctx = which_cipher_ctx_in(c, meta(v).hdr.flags);
    if (unlikely(ctx->pne == 0 || ctx->aead == 0)) {
        if (is_set(F_LONG_HDR, meta(v).hdr.flags) == false &&
            is_set(F_SH_KYPH, meta(v).hdr.flags) != c->pn_data.in_kyph) {
            // this might be the first key phase flip
            flip_keys(c, false);
            ctx = which_cipher_ctx_in(c, meta(v).hdr.flags);
            if (unlikely(ctx->pne == 0 || ctx->aead == 0))
                return false;
        } else
            return false;
    }

    bool first_try = true;
    uint8_t pn_enc[MAX_PKT_NR_LEN]; // raw (encrypted) packet number data

try_again:
    if (unlikely(dec_pne(xv, v, c, ctx, pn_enc) == false))
        return false;

    // we can now try and verify the packet protection
    const uint16_t pkt_len =
        is_set(F_LONG_HDR, meta(v).hdr.flags)
            ? meta(v).hdr.hdr_len + meta(v).hdr.len - meta(v).pkt_nr_len
            : xv->len;
    const uint16_t ret = dec_aead(c, xv, v, pkt_len, ctx);

    if (unlikely(ret == 0)) {
        if (likely(is_set(F_LONG_HDR, meta(v).hdr.flags) == false)) {

            // AEAD failed; this might be a stateless reset
            if (xv->len > sizeof(c->dcid->srt)) {
                // TODO: srt should have > 20 bytes of random prefix
                if (memcmp(&xv->buf[xv->len - sizeof(c->dcid->srt)],
                           c->dcid->srt, sizeof(c->dcid->srt)) == 0) {
                    warn(INF, BLU BLD "STATELESS RESET" NRM " token=%s",
                         hex2str(c->dcid->srt, sizeof(c->dcid->srt)));
                    conn_to_state(c, conn_drng);
                    return true;
                }
            }

            // AEAD failed; this might be due to a key phase flip
            if (likely(first_try == true)) {
                // check if the key phase may have changed
                const bool v_kyph = is_set(F_SH_KYPH, meta(v).hdr.flags);
                if (unlikely(v_kyph != c->pn_data.in_kyph)) {
                    // this packet has a different key phase than we saw before,
                    // so undo PNE decryption and retry with flipped keys
                    memcpy(&xv->buf[meta(v).pkt_nr_pos], pn_enc,
                           sizeof(pn_enc));
                    flip_keys(c, false);
                    meta(v).hdr.hdr_len = meta(v).pkt_nr_pos;
                    first_try = false;
                    goto try_again;
                }
            }
        }
        return false;
    }

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        // check for coalesced packet
        if (pkt_len < xv->len) {
            // TODO check that dcid in split-out version matches orig

            // allocate new w_iov for coalesced packet and copy it over
            struct w_iov * const dup = w_iov_dup(xv);
            dup->buf += pkt_len;
            dup->len -= pkt_len;
            // remember coalesced datagram len
            dup->user_data = xv->len;
            // adjust length of first packet
            xv->len = pkt_len;
            // rx() has already removed xv from x, so just insert dup at head
            sq_insert_head(x, dup, next);
            warn(DBG, "split out coalesced %s pkt of len %u",
                 pkt_type_str(*dup->buf, &dup->buf[1]), dup->len);
        }

    } else {
        // check if a key phase flip has been verified
        const bool v_kyph = is_set(F_SH_KYPH, meta(v).hdr.flags);
        if (unlikely(v_kyph != c->pn_data.in_kyph))
            c->pn_data.in_kyph = v_kyph;

#ifdef SPINBIT
        // short header, spin the bit
        if (meta(v).hdr.nr > diet_max(&(c->pn_data.pn.recv_all))) {
            c->next_spin = ((meta(v).hdr.flags & F_SH_SPIN) == !c->is_clnt);
            warn(DBG, "%sing spin to 0x%02x", c->is_clnt ? "invert" : "reflect",
                 c->next_spin);
        } else
            warn(DBG, "not updating next_spin: %" PRIu64 " <= %" PRIu64,
                 meta(v).hdr.nr, diet_max(&(c->pn_data.pn.recv_all)));
#endif
    }

    v->len = xv->len - AEAD_LEN;

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

    struct w_iov * const x = alloc_iov(ws->w, 0, 0);
    struct w_iov_sq q = w_iov_sq_initializer(q);
    sq_insert_head(&q, x, next);

    warn(INF, "sending vers neg serv response");
    meta(x).hdr.flags = F_LONG_HDR | (uint8_t)w_rand();
    uint16_t i = enc(x->buf, x->len, 0, &meta(x).hdr.flags,
                     sizeof(meta(x).hdr.flags), 0, "0x%02x");

    i = enc(x->buf, x->len, i, &meta(x).hdr.vers, sizeof(meta(x).hdr.vers), 0,
            "0x%08x");

    i = enc_lh_cids(&meta(v).hdr.scid, &meta(v).hdr.dcid, x, i);

    for (uint8_t j = 0; j < ok_vers_len; j++)
        if (!is_force_neg_vers(ok_vers[j]))
            i = enc(x->buf, x->len, i, &ok_vers[j], sizeof(ok_vers[j]), 0,
                    "0x%08x");

    x->len = i;
    x->ip = v->ip;
    x->port = v->port;
    x->flags = v->flags;
    log_pkt("TX", x, x->ip, x->port, 0, 0, 0);

    w_tx(ws, &q);
    while (w_tx_pending(&q))
        w_nic_tx(ws->w);

    q_free(&q);
}
