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

#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <picotls.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"
#include "tls.h"


#ifndef NDEBUG
static const char * pkt_type_str(const struct w_iov * const v)
{
    if (is_set(F_LONG_HDR, v->buf[0])) {
        if (meta(v).hdr.vers == 0)
            return "Version Negotiation";
        switch (meta(v).hdr.type) {
        case F_LH_INIT:
            return "Initial";
        case F_LH_RTRY:
            return "Retry";
        case F_LH_HSHK:
            return "Handshake";
        case F_LH_0RTT:
            return "0-RTT Protected";
        }
    } else
        return "Short";
    return RED "Unknown" NRM;
}


void log_pkt(const char * const dir, const struct w_iov * const v)
{
    const char * col_dir = *dir == 'R' ? BLD BLU : BLD GRN;
    const char * col_nr = *dir == 'R' ? BLU : GRN;

    if (is_set(F_LONG_HDR, v->buf[0])) {
        if (meta(v).hdr.vers == 0)
            twarn(NTE,
                  BLD "%s%s" NRM " len=%u 0x%02x=%s%s " NRM
                      "vers=0x%08x dcid=%s scid=%s",
                  col_dir, dir, v->len, v->buf[0], col_dir, pkt_type_str(v),
                  meta(v).hdr.vers, cid2str(&meta(v).hdr.dcid),
                  cid2str(&meta(v).hdr.scid));
        else
            twarn(NTE,
                  BLD "%s%s" NRM " len=%u 0x%02x=%s%s " NRM
                      "vers=0x%08x dcid=%s scid=%s len=%u nr=%s%" PRIu64,
                  col_dir, dir, v->len, v->buf[0], col_dir, pkt_type_str(v),
                  meta(v).hdr.vers, cid2str(&meta(v).hdr.dcid),
                  cid2str(&meta(v).hdr.scid), meta(v).hdr.len, col_nr,
                  meta(v).hdr.nr);
    } else
        twarn(NTE,
              BLD "%s%s" NRM " len=%u 0x%02x=%s%s " NRM "dcid=%s nr=%s%" PRIu64,
              col_dir, dir, v->len, v->buf[0], col_dir, pkt_type_str(v),
              cid2str(&meta(v).hdr.dcid), col_nr, meta(v).hdr.nr);
}
#endif


static uint8_t __attribute__((nonnull))
needed_pkt_nr_len(struct q_conn * const c, const uint64_t n)
{
    const uint64_t d = (n - c->rec.lg_acked) * 2;
    if (d <= 0x7F)
        return 1;
    if (d <= 0x3FFF)
        return 2;
    return 4;
}


static uint16_t
enc_lh_cids(struct q_conn * const c, struct w_iov * const v, const uint16_t pos)
{
    cid_cpy(&meta(v).hdr.dcid, act_dcid(c));
    cid_cpy(&meta(v).hdr.scid, act_scid(c));
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


bool enc_pkt(struct q_stream * const s,
             const bool rtx,
             struct w_iov * const v,
             struct w_iov_sq * const q)
{
    // prepend the header by adjusting the buffer offset
    adj_iov_to_start(v);

    struct q_conn * const c = s->c;
    uint16_t i = 0, nr_pos = 0, len_pos = 0;
    uint8_t nr_len = 0;

    if (c->state == CONN_STAT_VERS_NEG) {
        warn(INF, "sending vers neg serv response");
        meta(v).hdr.type = (uint8_t)w_rand();
        meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        i = enc(v->buf, v->len, 0, &meta(v).hdr.flags,
                sizeof(meta(v).hdr.flags), 0, "0x%02x");
        i = enc(v->buf, v->len, i, &meta(v).hdr.vers, sizeof(meta(v).hdr.vers),
                0, "0x%08x");
        i = enc_lh_cids(c, v, i);
        for (uint8_t j = 0; j < ok_vers_len; j++)
            if (!is_force_neg_vers(ok_vers[j]))
                i = enc(v->buf, v->len, i, &ok_vers[j], sizeof(ok_vers[j]), 0,
                        "0x%08x");
        meta(v).hdr.hdr_len = v->len = i;
        log_pkt("TX", v);
        goto tx;
    }

    if (c->state == CONN_STAT_SEND_RTRY)
        meta(v).hdr.nr = 0;
    else if (c->rec.lg_sent == UINT64_MAX)
        // next pkt nr
        meta(v).hdr.nr = c->rec.lg_sent = 0;
    else
        meta(v).hdr.nr = ++c->rec.lg_sent;

    switch (c->state) {
    case CONN_STAT_IDLE:
    case CONN_STAT_RTRY:
    case CONN_STAT_CH_SENT:
        meta(v).hdr.type = (s->id == 0 ? F_LH_INIT : F_LH_0RTT);
        meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        break;
    case CONN_STAT_SEND_RTRY:
        meta(v).hdr.type = F_LH_RTRY;
        meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        break;
    case CONN_STAT_SH:
    case CONN_STAT_HSHK_DONE:
    case CONN_STAT_HSHK_FAIL:
        meta(v).hdr.type = F_LH_HSHK;
        meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        break;
    case CONN_STAT_ESTB:
    case CONN_STAT_CLNG:
    case CONN_STAT_DRNG:
        if (c->tls.out_pp.one_rtt[0].aead)
            meta(v).hdr.flags = F_SH;
        else {
            meta(v).hdr.type = F_LH_HSHK;
            meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        }
        break;
    default:
        die("unknown conn state %u", c->state);
    }

    if (is_set(F_LONG_HDR, meta(v).hdr.flags) == false)
        // for giggles, randomize the reserved bits in the short header
        meta(v).hdr.flags |= arc4random_uniform(F_SH_EXP_MASK);

    ensure(meta(v).hdr.nr < (1ULL << 62) - 1, "packet number overflow");

    i = enc(v->buf, v->len, 0, &meta(v).hdr.flags, sizeof(meta(v).hdr.flags), 0,
            "0x%02x");

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        meta(v).hdr.vers = c->vers;
        i = enc(v->buf, v->len, i, &c->vers, sizeof(c->vers), 0, "0x%08x");
        i = enc_lh_cids(c, v, i);
        // leave space for length field (2 bytes is enough)
        len_pos = i;
        i += 2;
    } else {
        cid_cpy(&meta(v).hdr.dcid, act_dcid(c));
        i = enc_buf(v->buf, v->len, i, &meta(v).hdr.dcid.id,
                    meta(v).hdr.dcid.len);
    }
    nr_pos = i;
    nr_len = needed_pkt_nr_len(c, meta(v).hdr.nr);
    i = enc_pnr(v->buf, v->len, i, &meta(v).hdr.nr, nr_len, GRN "%u" NRM);

    meta(v).hdr.hdr_len = i;
    log_pkt("TX", v);

    if (!splay_empty(&c->recv) && c->state >= CONN_STAT_SEND_RTRY) {
        i = enc_ack_frame(c, v, i);
    } else
        meta(v).ack_header_pos = 0;

    if (c->tx_path_resp) {
        i = enc_path_response_frame(c, v, i);
        c->tx_path_resp = false;
    }

    if (c->tx_path_chlg)
        i = enc_path_challenge_frame(c, v, i);

    if (c->tx_ncid)
        i = enc_new_cid_frame(c, v, i);

    if (c->state == CONN_STAT_ESTB) {
        // XXX rethink this - there needs to be a list of which streams are
        // blocked or need their window opened
        struct q_stream * t = 0;
        splay_foreach (t, stream, &c->streams) {
            if (t->blocked)
                i = enc_stream_blocked_frame(t, v, i);
            if (t->tx_max_stream_data) {
                i = enc_max_stream_data_frame(t, v, i);
                t->tx_max_stream_data = false;
            }
        }

        if (c->blocked)
            i = enc_blocked_frame(c, v, i);

        if (c->tx_max_data) {
            i = enc_max_data_frame(c, v, i);
            c->tx_max_data = false;
        }

        if (c->stream_id_blocked) {
            i = enc_stream_id_blocked_frame(c, v, i);
            c->stream_id_blocked = false;
        }

        if (c->tx_max_stream_id) {
            i = enc_max_stream_id_frame(c, v, i);
            c->tx_max_stream_id = false;
        }
    }

    // TODO: need to RTX most recent MAX_STREAM_DATA and MAX_DATA on RTX

    if (c->state == CONN_STAT_CLNG || c->state == CONN_STAT_HSHK_FAIL) {
        i = enc_close_frame(v, i, FRAM_TYPE_CONN_CLSE, c->err_code,
                            c->err_reason);
        goto tx;
    }

    if (rtx) {
        ensure(is_rtxable(&meta(v)), "is rtxable");

        // this is a RTX, pad out until beginning of stream header
        enc_padding_frame(v, i, meta(v).stream_header_pos - i);
        i = meta(v).stream_data_end;

#ifndef NDEBUG
        // duplicate the logging that enc_stream_frame() does for a fresh TX
        const uint8_t type = v->buf[meta(v).stream_header_pos];
        warn(INF,
             FRAM_OUT "STREAM" NRM " 0x%02x=%s%s%s%s%s id=" FMT_SID "/%" PRIu64
                      " cdata=%" PRIu64 "/%" PRIu64 " off=%" PRIu64 "/%" PRIu64
                      " len=%u " REV BLD GRN "[RTX]",
             type, is_set(F_STREAM_FIN, type) ? "FIN" : "",
             is_set(F_STREAM_FIN, type) &&
                     (is_set(F_STREAM_LEN, type) || is_set(F_STREAM_OFF, type))
                 ? "|"
                 : "",
             is_set(F_STREAM_LEN, type) ? "LEN" : "",
             is_set(F_STREAM_LEN, type) && is_set(F_STREAM_OFF, type) ? "|"
                                                                      : "",
             is_set(F_STREAM_OFF, type) ? "OFF" : "", s->id, max_strm_id(s),
             s->c->out_data, s->c->tp_peer.max_data, meta(v).stream_off,
             s->out_data_max, stream_data_len(v));
#endif

    } else if (v->len > Q_OFFSET || s->state == STRM_STAT_HCLO ||
               s->state == STRM_STAT_CLSD) {
        // this is a fresh data or pure FIN packet
        // pad out rest of Q_OFFSET and add a stream frame header
        enc_padding_frame(v, i, Q_OFFSET - i);
        i = enc_stream_frame(s, v, i);
    }

    if ((c->state == CONN_STAT_IDLE || c->state == CONN_STAT_RTRY ||
         c->state == CONN_STAT_CH_SENT) &&
        meta(v).hdr.type != F_LH_0RTT) {
        i = enc_padding_frame(v, i, MIN_INI_LEN - i - AEAD_LEN);
        conn_to_state(c, CONN_STAT_CH_SENT);
    }

    ensure(i > meta(v).hdr.hdr_len, "would have sent pkt w/o frames");

tx:
    // for LH pkts, now encode the length
    meta(v).hdr.len = i + AEAD_LEN - nr_pos;
    if (len_pos) {
        const uint64_t len = meta(v).hdr.len;
        enc(v->buf, v->len, len_pos, &len, 0, 2, "%" PRIu64);
    }

    v->len = i;

    // alloc a new buffer to encrypt/sign into for TX
    struct w_iov * const x = q_alloc_iov(c->w, MAX_PKT_LEN, 0);
    x->ip = v->ip;
    x->port = v->port;
    x->flags = v->flags;

    if (c->state == CONN_STAT_VERS_NEG) {
        memcpy(x->buf, v->buf, v->len); // copy data
        x->len = v->len;
        conn_to_state(c, CONN_STAT_VERS_NEG_SENT);
    } else
        x->len = enc_aead(c, v, x, nr_pos);

    if (!c->is_clnt) {
        x->ip = c->peer.sin_addr.s_addr;
        x->port = c->peer.sin_port;
    }

    sq_insert_tail(q, x, next);
    meta(v).tx_len = x->len;

    if (c->state == CONN_STAT_IDLE || c->state == CONN_STAT_RTRY)
        // adjust v->len to end of stream data (excl. padding)
        v->len = meta(v).stream_data_end;

    adj_iov_to_data(v);
    return true;
}


bool dec_pkt_hdr_initial(const struct w_iov * const v, const bool is_clnt)
{
    uint16_t ret = dec(&meta(v).hdr.flags, v->buf, v->len, 0, 1, "0x%02x");
    if (unlikely(ret == UINT16_MAX))
        return false;
    meta(v).hdr.type = pkt_type(*v->buf);

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        ret = dec(&meta(v).hdr.vers, v->buf, v->len, 1, 4, "0x%08x");
        if (unlikely(ret == UINT16_MAX))
            return false;
        meta(v).hdr.hdr_len = ret;

        // check if the packet type/version combo makes sense
        if (meta(v).hdr.vers &&
            (meta(v).hdr.type > F_LH_INIT || meta(v).hdr.type < F_LH_0RTT))
            return false;

        ret = dec(&meta(v).hdr.dcid.len, v->buf, v->len, 5, 1, "0x%02x");
        if (unlikely(ret == UINT16_MAX))
            return false;
        meta(v).hdr.hdr_len = ret;

        meta(v).hdr.dcid.len >>= 4;
        if (meta(v).hdr.dcid.len) {
            meta(v).hdr.dcid.len += 3;
            ret = dec_buf(&meta(v).hdr.dcid.id, v->buf, v->len, 6,
                          meta(v).hdr.dcid.len);
            if (unlikely(ret == UINT16_MAX))
                return false;
            meta(v).hdr.hdr_len += meta(v).hdr.dcid.len;
        }

        dec(&meta(v).hdr.scid.len, v->buf, v->len, 5, 1, "0x%02x");
        meta(v).hdr.scid.len &= 0x0f;
        if (meta(v).hdr.scid.len) {
            meta(v).hdr.scid.len += 3;
            ret = dec_buf(&meta(v).hdr.scid.id, v->buf, v->len,
                          meta(v).hdr.hdr_len, meta(v).hdr.scid.len);
            if (unlikely(ret == UINT16_MAX))
                return false;
            meta(v).hdr.hdr_len += meta(v).hdr.scid.len;
        }

        if (meta(v).hdr.vers == 0)
            // version negotiation packet
            return true;

        uint64_t len = 0;
        meta(v).hdr.hdr_len =
            dec(&len, v->buf, v->len, meta(v).hdr.hdr_len, 0, "%" PRIu64);
        meta(v).hdr.len = (uint16_t)len;
        return true;
    }

    meta(v).hdr.hdr_len = 1;

    // this logic depends on picking a SCID with a known length during handshake
    meta(v).hdr.dcid.len = (is_clnt ? CLNT_SCID_LEN : SERV_SCID_LEN);

    ret =
        dec_buf(&meta(v).hdr.dcid.id, v->buf, v->len, 1, meta(v).hdr.dcid.len);
    if (unlikely(ret == UINT16_MAX))
        return false;
    meta(v).hdr.hdr_len += meta(v).hdr.dcid.len;
    return true;
}


bool dec_pkt_hdr_remainder(struct w_iov * const v,
                           struct q_conn * const c,
                           struct w_iov_sq * const i)
{
    // meta(v).hdr.hdr_len holds the offset of the pnr field
    const uint16_t nr_pos = meta(v).hdr.hdr_len;
    uint16_t off = nr_pos + 4;
    const uint16_t len = is_set(F_LONG_HDR, meta(v).hdr.flags)
                             ? nr_pos + meta(v).hdr.len + AEAD_LEN - 1
                             : v->len;
    if (off + AEAD_LEN > len)
        off = len - AEAD_LEN;

    const struct cipher_ctx * const ctx = which_cipher_ctx(c, v, true);
    ensure(ctx, "cipher context is null");
    ptls_cipher_init(ctx->pne, &v->buf[off]);
    uint8_t enc_nr[4];
    ptls_cipher_encrypt(ctx->pne, enc_nr, &v->buf[nr_pos], sizeof(enc_nr));

    const uint64_t next = diet_max(&c->recv) + 1;
    uint64_t nr = next;
    const uint16_t nr_len = dec_pnr(&nr, enc_nr, sizeof(enc_nr), 0, "%u");
    if (unlikely(nr_len == UINT16_MAX))
        return false;

    memcpy(&v->buf[nr_pos], &enc_nr, nr_len);

    warn(DBG, "removed PNE over [%u..%u] based on off %u", nr_pos,
         nr_pos + nr_len - 1, off);

    const uint64_t alt = nr + (UINT64_C(1) << (nr_len * 8));
    const uint64_t d1 = next >= nr ? next - nr : nr - next;
    const uint64_t d2 = next >= alt ? next - alt : alt - next;
    meta(v).hdr.nr = d1 < d2 ? nr : alt;
    meta(v).hdr.hdr_len += nr_len;

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        // check for coalesced packet
        const uint16_t pkt_len = meta(v).hdr.hdr_len + meta(v).hdr.len - nr_len;
        if (pkt_len < v->len) {
            // allocate new w_iov for coalesced packet and copy it over
            struct w_iov * const vdup = w_iov_dup(v);
            vdup->buf += pkt_len;
            vdup->len -= pkt_len;
            // adjust original length
            v->len = pkt_len;
            // rx() has already removed v from i, so just insert vdup at head
            sq_insert_head(i, vdup, next);
            warn(DBG, "split out 0x%02x-type coalesced pkt of len %u",
                 pkt_type(*vdup->buf), vdup->len);
        }
    }
    return true;
}
