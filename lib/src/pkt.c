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
#define FMT_PNR32_OUT BLU "%u" NRM
#define FMT_PNR32_IN GRN "%u" NRM


static const char * pkt_type_str(const struct w_iov * const v)
{
    const uint8_t flags = pkt_flags(v->buf);
    if (is_set(F_LONG_HDR, flags)) {
        if (pkt_vers(v->buf, v->len) == 0)
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
    } else
        switch (pkt_type(flags)) {
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
             const uint64_t cid)
{
    const uint8_t flags = pkt_flags(v->buf);
    const char * col_dir = *dir == 'R' ? BLD BLU : BLD GRN;
    const char * col_nr = *dir == 'R' ? BLU : GRN;

    if (is_set(F_LONG_HDR, flags)) {
        const uint32_t vers = pkt_vers(v->buf, v->len);
        if (vers == 0)
            twarn(NTE,
                  BLD "%s%s" NRM " len=%u 0x%02x=%s%s " NRM "cid=" FMT_CID
                      " vers=0x%08x",
                  col_dir, dir, v->len, flags, col_dir, pkt_type_str(v),
                  pkt_cid(v->buf, v->len), vers);
        else
            twarn(NTE,
                  BLD "%s%s" NRM " len=%u 0x%02x=%s%s " NRM "cid=" FMT_CID
                      " vers=0x%08x nr=%s%" PRIu64,
                  col_dir, dir, v->len, flags, col_dir, pkt_type_str(v),
                  pkt_cid(v->buf, v->len), vers, col_nr, meta(v).nr);
    } else if (is_set(F_SH_OMIT_CID, flags))
        twarn(NTE,
              BLD "%s%s" NRM " len=%u 0x%02x=%s%s" NRM "|omit_cid(" FMT_CID
                  ") nr=%s%" PRIu64,
              col_dir, dir, v->len, flags, col_dir, pkt_type_str(v), cid,
              col_nr, meta(v).nr);
    else
        twarn(NTE,
              BLD "%s%s" NRM " len=%u 0x%02x=%s%s" NRM " cid=" FMT_CID
                  " nr=%s%" PRIu64,
              col_dir, dir, v->len, flags, col_dir, pkt_type_str(v),
              pkt_cid(v->buf, v->len), col_nr, meta(v).nr);
}
#endif


/// Packet number lengths for different short-header packet types
static const uint8_t pkt_nr_lens[] = {sizeof(uint32_t), sizeof(uint16_t),
                                      sizeof(uint8_t)};


uint16_t pkt_hdr_len(const uint8_t * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint16_t pos = 0;
    if (is_set(F_LONG_HDR, flags))
        if (pkt_vers(buf, len) == 0)
            pos = 13;
        else
            pos = 17;
    else {
        const uint8_t type = pkt_type(flags);
        if (type > F_SH_1OCT || type < F_SH_4OCT) {
            warn(ERR, "illegal pkt type 0x%02x", type);
            return UINT16_MAX;
        }
        pos = 1 + (is_set(F_SH_OMIT_CID, flags) ? 0 : 8) +
              pkt_nr_lens[type - F_SH_4OCT];
    }
    ensure(pos <= len, "payload position %u after end of packet %u", pos, len);
    return pos;
}


uint64_t pkt_cid(const uint8_t * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint64_t cid = 0;
    ensure(is_set(F_LONG_HDR, flags) || !is_set(F_SH_OMIT_CID, flags),
           "no connection ID in header");
    dec(&cid, buf, len, 1, sizeof(cid), FMT_CID);
    return cid;
}


uint64_t
pkt_nr(const uint8_t * const buf, const uint16_t len, struct q_conn * const c)
{
    const uint64_t next = diet_max(&c->recv) + 1;
    const uint8_t flags = pkt_flags(buf);
    const uint8_t nr_len = is_set(F_LONG_HDR, flags)
                               ? sizeof(uint32_t)
                               : pkt_nr_lens[pkt_type(flags) - F_SH_4OCT];

    uint64_t nr = next;
    dec(&nr, buf, len,
        is_set(F_LONG_HDR, flags) ? 13 : is_set(F_SH_OMIT_CID, flags) ? 1 : 9,
        nr_len, FMT_PNR32_IN);

    const uint64_t alt = nr + (UINT64_C(1) << (nr_len * 8));
    const uint64_t d1 = next >= nr ? next - nr : nr - next;
    const uint64_t d2 = next >= alt ? next - alt : alt - next;

    return d1 < d2 ? nr : alt;
}


uint32_t pkt_vers(const uint8_t * const buf, const uint16_t len)
{
    ensure(is_set(F_LONG_HDR, pkt_flags(buf)), "have long header");
    uint32_t vers = 0;
    dec(&vers, buf, len, 9, sizeof(vers), "0x%08x");
    return vers;
}


static const uint8_t pkt_type[] = {0xFF, F_SH_1OCT, F_SH_2OCT, 0xFF, F_SH_4OCT};


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


void enc_pkt(struct q_stream * const s,
             const bool rtx,
             struct w_iov * const v,
             struct w_iov_sq * const q)
{
    // prepend the header by adjusting the buffer offset
    adj_iov_to_start(v);

    struct q_conn * const c = s->c;
    uint8_t flags = 0;
    uint16_t hdr_len = 0;
    uint16_t i = 0;

    if (c->state == CONN_STAT_VERS_NEG) {
        warn(INF, "sending vers neg serv response");
        flags = F_LONG_HDR | (uint8_t)w_rand();
        i = enc(v->buf, v->len, 0, &flags, sizeof(flags), "0x%02x");
        i = enc(v->buf, v->len, i, &c->id, sizeof(c->id), FMT_CID);
        const uint32_t vers = 0;
        i = enc(v->buf, v->len, i, &vers, sizeof(c->vers), "0x%08x");
        for (uint8_t j = 0; j < ok_vers_len; j++)
            if (!is_force_neg_vers(ok_vers[j]))
                i = enc(v->buf, v->len, i, &ok_vers[j], sizeof(ok_vers[j]),
                        "0x%08x");
        hdr_len = v->len = i;
        log_pkt("TX", v, c->id);
        goto tx;
    }

    if (rtx)
        warn(DBG, "enc RTX 0x%02x-type " FMT_PNR_OUT, flags, meta(v).nr);

    if (c->state == CONN_STAT_SEND_RTRY) {
        // echo pkt nr of client initial
        meta(v).nr = diet_min(&c->recv);
        // randomize a new CID
        arc4random_buf(&c->id, sizeof(c->id));
    } else
        // next pkt nr
        meta(v).nr = ++c->rec.lg_sent;

    uint8_t pkt_nr_len = 0;
    switch (c->state) {
    case CONN_STAT_IDLE:
    case CONN_STAT_RTRY:
    case CONN_STAT_CH_SENT:
        flags = F_LONG_HDR | (s->id == 0 ? F_LH_INIT : F_LH_0RTT);
        break;
    case CONN_STAT_SEND_RTRY:
        flags = F_LONG_HDR | F_LH_RTRY;
        break;
    case CONN_STAT_SH:
    case CONN_STAT_HSHK_DONE:
    case CONN_STAT_HSHK_FAIL:
        flags = F_LONG_HDR | F_LH_HSHK;
        break;
    case CONN_STAT_ESTB:
    case CONN_STAT_CLNG:
    case CONN_STAT_DRNG:
        if (likely(c->tls.enc_1rtt)) {
            pkt_nr_len = needed_pkt_nr_len(c, meta(v).nr);
            flags = pkt_type[pkt_nr_len] | (c->omit_cid ? F_SH_OMIT_CID : 0);
        } else
            flags = F_LONG_HDR | F_LH_HSHK;
        break;
    default:
        die("unknown conn state %u", c->state);
    }

    ensure(meta(v).nr < (1ULL << 62) - 1, "packet number overflow");

    i = enc(v->buf, v->len, 0, &flags, sizeof(flags), "0x%02x");

    if (is_set(F_LONG_HDR, flags) || !is_set(F_SH_OMIT_CID, flags))
        i = enc(v->buf, v->len, i, &c->id, sizeof(c->id), FMT_CID);

    if (is_set(F_LONG_HDR, flags)) {
        i = enc(v->buf, v->len, i, &c->vers, sizeof(c->vers), "0x%08x");
        i = enc(v->buf, v->len, i, &meta(v).nr, sizeof(uint32_t),
                FMT_PNR32_OUT);
    } else
        i = enc(v->buf, v->len, i, &meta(v).nr, pkt_nr_len, FMT_PNR32_OUT);

    log_pkt("TX", v, c->id);

    hdr_len = i;

    if (!splay_empty(&c->recv) && c->state >= CONN_STAT_SH) {
        meta(v).ack_header_pos = i;
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
                      " len=%" PRIu64 REV BLD GRN "[RTX]",
             type, is_set(F_STREAM_FIN, type) ? "FIN" : "",
             is_set(F_STREAM_FIN, type) &&
                     (is_set(F_STREAM_LEN, type) | is_set(F_STREAM_OFF, type))
                 ? "|"
                 : "",
             is_set(F_STREAM_LEN, type) ? "LEN" : "",
             is_set(F_STREAM_OFF, type) ? "|" : "",
             is_set(F_STREAM_OFF, type) ? "OFF" : "", s->id, max_strm_id(s),
             s->c->out_data, s->c->tp_peer.max_data, s->out_off,
             s->out_data_max, stream_data_len(v));
#endif

    } else {
        if (v->len > Q_OFFSET || s->state == STRM_STAT_HCLO ||
            s->state == STRM_STAT_CLSD) {

            if (c->state == CONN_STAT_SEND_RTRY) {
                enc_stream_frame(s, v);
                // retry packets must not have padding (as of 09), so move the
                // stream frame after the header (XXX ugly)
                memmove(&v->buf[hdr_len], &v->buf[meta(v).stream_header_pos],
                        v->len - meta(v).stream_header_pos);
                const uint16_t offset = meta(v).stream_header_pos - hdr_len;
                meta(v).stream_header_pos -= offset;
                meta(v).stream_data_start -= offset;
                meta(v).stream_data_end -= offset;
                i = v->len -= offset;
            } else {
                // this is a fresh data or pure FIN packet
                // add a stream frame header, after padding out rest of Q_OFFSET
                enc_padding_frame(v, i, Q_OFFSET - i);
                i = enc_stream_frame(s, v);
            }
        }
    }

    if ((c->state == CONN_STAT_IDLE || c->state == CONN_STAT_RTRY ||
         c->state == CONN_STAT_CH_SENT) &&
        pkt_type(flags) != F_LH_0RTT) {
        i = enc_padding_frame(v, i, MIN_INI_LEN - i - AEAD_LEN);
        conn_to_state(c, CONN_STAT_CH_SENT);
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
        x->len = enc_aead(c, v, x, hdr_len);

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
}
