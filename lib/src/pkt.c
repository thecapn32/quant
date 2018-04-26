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
#include <stdio.h>
#include <string.h>

#include <quant/quant.h> // IWYU pragma: keep
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
    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
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
        switch (meta(v).hdr.type) {
        case F_SH_1OCT:
            return "Short(1)";
        case F_SH_2OCT:
            return "Short(2)";
        case F_SH_4OCT:
            return "Short(4)";
        }
    return ("Unknown");
}


void log_pkt(const char * const dir,
             const struct w_iov * const v,
             const struct q_conn * const c __attribute__((unused)),
             const uint16_t add_len)
{
    const char * col_dir = *dir == 'R' ? BLD BLU : BLD GRN;
    const char * col_nr = *dir == 'R' ? BLU : GRN;

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        if (meta(v).hdr.vers == 0)
            twarn(NTE,
                  BLD "%s%s" NRM " len=%u 0x%02x=%s%s " NRM
                      "vers=0x%08x dcid=%s scid=%s",
                  col_dir, dir, v->len + add_len, meta(v).hdr.flags, col_dir,
                  pkt_type_str(v), meta(v).hdr.vers, cid2str(&meta(v).hdr.dcid),
                  cid2str(&meta(v).hdr.scid));
        else
            twarn(NTE,
                  BLD "%s%s" NRM " len=%u 0x%02x=%s%s " NRM
                      "vers=0x%08x dcid=%s scid=%s plen=%u nr=%s%" PRIu64,
                  col_dir, dir, v->len + add_len, meta(v).hdr.flags, col_dir,
                  pkt_type_str(v), meta(v).hdr.vers, cid2str(&meta(v).hdr.dcid),
                  cid2str(&meta(v).hdr.scid), meta(v).hdr.plen, col_nr,
                  meta(v).hdr.nr);
        //  else if (is_set(F_SH_OMIT_CID, meta(v).hdr.flags))
        //     twarn(NTE,
        //           BLD "%s%s" NRM " len=%u 0x%02x=%s%s" NRM "|omit_cid(%s" NRM
        //               ") nr=%s%" PRIu64,
        //           col_dir, dir, v->len + add_len, meta(v).hdr.flags, col_dir,
        //           pkt_type_str(v), cid, col_nr, meta(v).hdr.nr);
        // else
        //     twarn(NTE,
        //           BLD "%s%s" NRM " len=%u 0x%02x=%s%s" NRM " cid=" NRM
        //               " nr=%s%" PRIu64,
        //           col_dir, dir, v->len + add_len, meta(v).hdr.flags, col_dir,
        //           pkt_type_str(v), pkt_cid(v->buf, v->len + add_len), col_nr,
        //           meta(v).hdr.nr);
    }
}
#endif


static const uint8_t pkt_type[] = {0xff, F_SH_1OCT, F_SH_2OCT, 0xff, F_SH_4OCT};


static uint8_t __attribute__((nonnull))
needed_pkt_nr_len(struct q_conn * const c, const uint64_t n)
{
    const uint64_t d = (n - c->rec.lg_acked) * 2;
    if (d < UINT8_MAX)
        return 1;
    if (d < UINT16_MAX)
        return 2;
    return 4;
}


static uint16_t enc_lh_cid(struct w_iov * const v,
                           const uint16_t pos,
                           const struct cid * const id)
{
    warn(DBG, "enc cid = %s into %u byte%s at v->buf[%u..%u]", cid2str(id),
         id->len, plural(id->len), pos, pos + id->len - 1);
    memcpy(&v->buf[pos], id->id, id->len);
    return pos + id->len;
}


static uint16_t
enc_lh_cids(struct q_conn * const c, struct w_iov * const v, const uint16_t pos)
{
    meta(v).hdr.dcid = c->dcid;
    meta(v).hdr.scid = c->scid;
    const uint8_t cil = (uint8_t)((c->dcid.len ? c->dcid.len - 3 : 0) << 4) |
                        (uint8_t)(c->scid.len ? c->scid.len - 3 : 0);
    uint16_t i = enc(v->buf, v->len, pos, &cil, sizeof(cil), "0x%02x");
    if (c->dcid.len)
        i = enc_lh_cid(v, i, &c->dcid);
    if (c->scid.len)
        i = enc_lh_cid(v, i, &c->scid);
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
    uint16_t i = 0;

    if (c->state == CONN_STAT_VERS_NEG) {
        warn(INF, "sending vers neg serv response");
        meta(v).hdr.type = (uint8_t)w_rand();
        meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        i = enc(v->buf, v->len, 0, &meta(v).hdr.flags,
                sizeof(meta(v).hdr.flags), "0x%02x");
        i = enc(v->buf, v->len, i, &meta(v).hdr.vers, sizeof(meta(v).hdr.vers),
                "0x%08x");
        i = enc_lh_cids(c, v, i);
        for (uint8_t j = 0; j < ok_vers_len; j++)
            if (!is_force_neg_vers(ok_vers[j]))
                i = enc(v->buf, v->len, i, &ok_vers[j], sizeof(ok_vers[j]),
                        "0x%08x");
        meta(v).hdr.hdr_len = v->len = i;
        log_pkt("TX", v, c, 0);
        goto tx;
    }

    if (c->state == CONN_STAT_SEND_RTRY) {
        // echo pkt nr of client initial
        meta(v).hdr.nr = diet_min(&c->recv);
        // TODO: randomize a new CID
        // arc4random_buf(&c->id, sizeof(c->id));
    } else
        // next pkt nr
        meta(v).hdr.nr = ++c->rec.lg_sent;

    uint8_t pkt_nr_len = 0;
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
        if (likely(c->tls.enc_1rtt)) {
            pkt_nr_len = needed_pkt_nr_len(c, meta(v).hdr.nr);
            meta(v).hdr.type = (c->omit_cid ? F_SH_OMIT_CID : 0);
            meta(v).hdr.flags = pkt_type[pkt_nr_len] | meta(v).hdr.type;
        } else {
            meta(v).hdr.type = F_LH_HSHK;
            meta(v).hdr.flags = F_LONG_HDR | meta(v).hdr.type;
        }
        break;
    default:
        die("unknown conn state %u", c->state);
    }

    ensure(meta(v).hdr.nr < (1ULL << 62) - 1, "packet number overflow");

    i = enc(v->buf, v->len, 0, &meta(v).hdr.flags, sizeof(meta(v).hdr.flags),
            "0x%02x");

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        meta(v).hdr.vers = c->vers;
        i = enc(v->buf, v->len, i, &c->vers, sizeof(c->vers), "0x%08x");
    }

    if (is_set(F_LONG_HDR, meta(v).hdr.flags) ||
        !is_set(F_SH_OMIT_CID, meta(v).hdr.flags))
        i = enc_lh_cids(c, v, i);

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        uint64_t plen = v->len + AEAD_LEN - i - sizeof(uint32_t);
        const uint64_t plen_len = varint_size_needed(plen);
        plen -= plen_len - (varint_size_needed(plen) -
                            varint_size_needed(plen - plen_len));
        i = enc(v->buf, v->len, i, &plen, 0, "%" PRIu64);
        i = enc(v->buf, v->len, i, &meta(v).hdr.nr, sizeof(uint32_t),
                GRN "%u" NRM);
    } else
        i = enc(v->buf, v->len, i, &meta(v).hdr.nr, pkt_nr_len, GRN "%u" NRM);

    log_pkt("TX", v, c, AEAD_LEN);
    meta(v).hdr.hdr_len = i;

    if (!splay_empty(&c->recv) && c->state >= CONN_STAT_SH) {
        i = enc_ack_frame(c, v, i);
    } else
        meta(v).ack_header_pos = 0;

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
                     (is_set(F_STREAM_LEN, type) | is_set(F_STREAM_OFF, type))
                 ? "|"
                 : "",
             is_set(F_STREAM_LEN, type) ? "LEN" : "",
             is_set(F_STREAM_OFF, type) ? "|" : "",
             is_set(F_STREAM_OFF, type) ? "OFF" : "", s->id, max_strm_id(s),
             s->c->out_data, s->c->tp_peer.max_data, meta(v).stream_off,
             s->out_data_max, stream_data_len(v));
#endif

    } else {
        if (v->len > Q_OFFSET || s->state == STRM_STAT_HCLO ||
            s->state == STRM_STAT_CLSD) {

            if (c->state == CONN_STAT_SEND_RTRY) {
                enc_stream_frame(s, v);
                // retry packets must not have padding (as of 09), so move
                // the stream frame after the header (XXX ugly)
                memmove(&v->buf[meta(v).hdr.hdr_len],
                        &v->buf[meta(v).stream_header_pos],
                        v->len - meta(v).stream_header_pos);
                const uint16_t offset =
                    meta(v).stream_header_pos - meta(v).hdr.hdr_len;
                meta(v).stream_header_pos -= offset;
                meta(v).stream_data_start -= offset;
                meta(v).stream_data_end -= offset;
                i = v->len -= offset;
            } else {
                // this is a fresh data or pure FIN packet
                // add a stream frame header, after padding out rest of
                // Q_OFFSET
                enc_padding_frame(v, i, Q_OFFSET - i);
                i = enc_stream_frame(s, v);
            }
        }
    }

    if ((c->state == CONN_STAT_IDLE || c->state == CONN_STAT_RTRY ||
         c->state == CONN_STAT_CH_SENT) &&
        meta(v).hdr.type != F_LH_0RTT) {
        i = enc_padding_frame(v, i, MIN_INI_LEN - i - AEAD_LEN);
        conn_to_state(c, CONN_STAT_CH_SENT);
    }

    if (i == meta(v).hdr.hdr_len) {
        // we didn't add any frames to this packet, so let's not send it
        if (c->state != CONN_STAT_SEND_RTRY)
            c->rec.lg_sent--;
        warn(WRN, "this pkt will not be sent");
        return false;
    }

tx:
    v->len = i;

    // alloc a new buffer to encrypt/sign into for TX
    struct w_iov * const x = q_alloc_iov(w_engine(c->sock), MAX_PKT_LEN, 0);
    x->ip = v->ip;
    x->port = v->port;
    x->flags = v->flags;

    if (c->state == CONN_STAT_VERS_NEG) {
        memcpy(x->buf, v->buf, v->len); // copy data
        x->len = v->len;
        conn_to_state(c, CONN_STAT_VERS_NEG_SENT);
    } else
        x->len = enc_aead(c, v, x, meta(v).hdr.hdr_len);

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


/// Packet number lengths for different short-header packet types
static const uint8_t pkt_nr_lens[] = {sizeof(uint32_t), sizeof(uint16_t),
                                      sizeof(uint8_t)};


void dec_pkt_hdr(const struct w_iov * const v)
{
    meta(v).hdr.flags = *v->buf;
    meta(v).hdr.type = *v->buf & (is_set(F_LONG_HDR, *v->buf) ? ~0x80 : ~0xe0);

    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        meta(v).hdr.hdr_len =
            dec(&meta(v).hdr.vers, v->buf, v->len, 1, 4, "0x%08x");

        meta(v).hdr.hdr_len =
            dec(&meta(v).hdr.dcid.len, v->buf, v->len, 5, 1, "0x%02x");
        meta(v).hdr.dcid.len >>= 4;
        if (meta(v).hdr.dcid.len) {
            meta(v).hdr.dcid.len += 3;
            memcpy(&meta(v).hdr.dcid.id, &v->buf[6], meta(v).hdr.dcid.len);
            warn(
                DBG,
                "dec %u byte%s from v->buf[%u..%u] into &meta(v).hdr.dcid = %s",
                meta(v).hdr.dcid.len, plural(meta(v).hdr.dcid.len),
                meta(v).hdr.hdr_len,
                meta(v).hdr.hdr_len + meta(v).hdr.dcid.len - 1,
                cid2str(&meta(v).hdr.dcid));
            meta(v).hdr.hdr_len += meta(v).hdr.dcid.len;
        }

        dec(&meta(v).hdr.scid.len, v->buf, v->len, 5, 1, "0x%02x");
        meta(v).hdr.scid.len &= 0x0f;
        if (meta(v).hdr.scid.len) {
            meta(v).hdr.scid.len += 3;
            memcpy(&meta(v).hdr.scid.id, &v->buf[meta(v).hdr.hdr_len],
                   meta(v).hdr.scid.len);
            warn(
                DBG,
                "dec %u byte%s from v->buf[%u..%u] into &meta(v).hdr.scid = %s",
                meta(v).hdr.scid.len, plural(meta(v).hdr.scid.len),
                meta(v).hdr.hdr_len,
                meta(v).hdr.hdr_len + meta(v).hdr.scid.len - 1,
                cid2str(&meta(v).hdr.scid));
            meta(v).hdr.hdr_len += meta(v).hdr.scid.len;
        }

        if (meta(v).hdr.vers == 0)
            // version negotiation packet
            return;

        uint64_t plen = 0;
        meta(v).hdr.hdr_len =
            dec(&plen, v->buf, v->len, meta(v).hdr.hdr_len, 0, "%" PRIu64);
        meta(v).hdr.plen = (uint16_t)plen;

        return;
    }

    meta(v).hdr.hdr_len = 1;

    memcpy(&meta(v).hdr.dcid.id, &v->buf[1], meta(v).hdr.dcid.len);
    meta(v).hdr.hdr_len += meta(v).hdr.dcid.len;
}


void dec_pkt_nr(const struct w_iov * const v, struct q_conn * const c)
{
    if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
        uint32_t nr = 0;
        dec(&nr, v->buf, v->len, meta(v).hdr.hdr_len, 4, "%u");
        meta(v).hdr.nr = nr;
        meta(v).hdr.hdr_len += 4;
        return;
    }

    const uint64_t next = diet_max(&c->recv) + 1;
    const uint8_t nr_len = pkt_nr_lens[meta(v).hdr.type - F_SH_4OCT];
    uint64_t nr = next;
    dec(&nr, v->buf, v->len, meta(v).hdr.hdr_len, nr_len, "%u");
    const uint64_t alt = nr + (UINT64_C(1) << (nr_len * 8));
    const uint64_t d1 = next >= nr ? next - nr : nr - next;
    const uint64_t d2 = next >= alt ? next - alt : alt - next;
    meta(v).hdr.nr = d1 < d2 ? nr : alt;
}
