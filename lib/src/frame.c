// SPDX-License-Identifier: BSD-2-Clause
//
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

#include <bitstring.h>
#include <inttypes.h>
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
#include "pkt.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"

#define F_STREAM_FIN 0x01
#define F_STREAM_LEN 0x02
#define F_STREAM_OFF 0x04

#ifndef NDEBUG
#define FRAM_IN BLD BLU
#define FRAM_OUT BLD GRN
#endif


static uint16_t __attribute__((nonnull))
dec_stream_frame(struct q_conn * const c,
                 struct w_iov * const v,
                 const uint16_t pos)
{
    meta(v).stream_header_pos = pos;

    uint8_t type = 0;
    uint16_t i = dec(&type, v->buf, v->len, pos, sizeof(type), "0x%02x");

    uint64_t sid = 0;
    i = dec(&sid, v->buf, v->len, i, 0, FMT_SID);

    if (is_set(F_STREAM_OFF, type))
        i = dec(&meta(v).in_off, v->buf, v->len, i, 0, "%" PRIu64);

    uint64_t l;
    if (is_set(F_STREAM_LEN, type))
        i = dec(&l, v->buf, v->len, i, 0, "%" PRIu64);
    else
        // stream data extends to end of packet
        l = v->len - i;

    ensure(l || is_set(F_STREAM_FIN, type), "len %u > 0 or FIN", l);

    meta(v).stream_data_start = i;
    meta(v).stream_data_end = (uint16_t)l + i;

    // deliver data into stream
    struct q_stream * s = get_stream(c, sid);
    if (s == 0) {
        if (diet_find(&c->closed_streams, sid)) {
            warn(WRN,
                 "ignoring frame for closed str " FMT_SID
                 " on %s conn " FMT_CID,
                 sid, conn_type(c), c->id);
            goto done;
        }
        ensure(is_set(STRM_FL_INI_SRV, sid) == c->is_clnt,
               "got sid %" PRIu64 " but am %s", sid, conn_type(c));

        if (is_set(STRM_FL_DIR_UNI, sid)) {
            err_close(c, ERR_INTERNAL_ERR,
                      "TODO: unidirectional streams not supported yet");
            return 0;
        }
        s = new_stream(c, sid);
    }

    // best case: new in-order data
    if (meta(v).in_off == s->in_off) {
        warn(DBG,
             "%" PRIu64 " byte%s new data (off %" PRIu64 "-%" PRIu64
             ") on %s conn " FMT_CID " str " FMT_SID,
             l, plural(l), meta(v).in_off, meta(v).in_off + l, conn_type(c),
             c->id, sid);
        track_bytes_in(s, l);
        s->in_off += l;
        sq_insert_tail(&s->in, v, next);

        // check if a hole has been filled that lets us dequeue ooo data
        struct pkt_meta *p, *nxt;
        for (p = splay_min(pm_off_splay, &s->in_ooo);
             p && p->in_off == s->in_off; p = nxt) {
            nxt = splay_next(pm_off_splay, &s->in_ooo, p);
            l = p->stream_data_end;

            warn(DBG,
                 "deliver %u ooo byte%s (off %" PRIu64 "-%" PRIu64
                 ") on %s conn " FMT_CID " str " FMT_SID,
                 l, plural(l), p->in_off, p->in_off + l, conn_type(c), c->id,
                 sid);

            s->in_off += l;
            sq_insert_tail(&s->in, w_iov(w_engine(c->sock), pm_idx(p)), next);
            splay_remove(pm_off_splay, &s->in_ooo, p);
        }

        if (is_set(F_STREAM_FIN, type)) {
#ifndef NDEBUG
            const uint8_t old_state = s->state;
#endif
            s->state =
                s->state <= STRM_STAT_OPEN ? STRM_STAT_HCRM : STRM_STAT_CLSD;
            warn(DBG,
                 "received FIN on %s conn " FMT_CID " str " FMT_SID
                 ", state %u -> %u",
                 conn_type(c), c->id, s->id, old_state, s->state);
            if (s->id != 0 && splay_empty(&s->in_ooo))
                maybe_api_return(q_readall_str, s);
        }

        if (s->id != 0)
            maybe_api_return(q_read, s->c);
        goto done;
    }

    // data is a complete duplicate
    if (meta(v).in_off + l <= s->in_off) {
        warn(CRT,
             "%" PRIu64 " byte%s dup data (off %" PRIu64 "-%" PRIu64
             ") on %s conn " FMT_CID " str " FMT_SID,
             l, plural(l), meta(v).in_off, meta(v).in_off + l, conn_type(c),
             c->id, sid);
        goto done;
    }

    // data is out of order
    warn(DBG,
         "reordered data: %" PRIu64 " byte%s data (off %" PRIu64 "-%" PRIu64
         "), expected %" PRIu64 " on %s conn " FMT_CID " str " FMT_SID,
         l, plural(l), meta(v).in_off, meta(v).in_off + l, s->in_off,
         conn_type(c), c->id, sid);
    splay_insert(pm_off_splay, &s->in_ooo, &meta(v));
    track_bytes_in(s, l);

done:
    warn(INF,
         FRAM_IN "STREAM" NRM " 0x%02x=%s%s%s%s%s id=" FMT_SID " off=%" PRIu64
                 " len=%" PRIu64,
         type, is_set(F_STREAM_FIN, type) ? "FIN" : "",
         is_set(F_STREAM_FIN, type) && is_set(F_STREAM_LEN | F_STREAM_OFF, type)
             ? "|"
             : "",
         is_set(F_STREAM_LEN, type) ? "LEN" : "",
         is_set(F_STREAM_OFF, type) ? "|" : "",
         is_set(F_STREAM_OFF, type) ? "OFF" : "", sid, meta(v).in_off, l);
    return meta(v).stream_data_end;
}


uint64_t shorten_ack_nr(const uint64_t ack, const uint64_t diff)
{
    ensure(diff, "no diff between ACKs");

    uint64_t div = (uint64_t)(powl(ceill(log10l(diff)), 10));
    div = MAX(10, div);
    if ((ack - diff) % div + diff >= div)
        div *= 10;
    return ack % div;
}


uint16_t dec_ack_frame(
    struct q_conn * const c,
    const struct w_iov * const v,
    const uint16_t pos,
    void (*before_ack)(struct q_conn * const, const uint64_t, const uint64_t),
    void (*on_each_ack)(struct q_conn * const, const uint64_t),
    void (*after_ack)(struct q_conn * const))
{
    uint8_t type = 0;
    uint16_t i = dec(&type, v->buf, v->len, pos, sizeof(type), "0x%02x");

    uint64_t lg_ack = 0;
    i = dec(&lg_ack, v->buf, v->len, i, 0, FMT_PNR_OUT);

    uint64_t ack_delay_raw = 0;
    i = dec(&ack_delay_raw, v->buf, v->len, i, 0, "%" PRIu64);
    const uint64_t ack_delay = ack_delay_raw * (1 << c->peer_ack_del_exp);

    uint64_t num_blocks = 0;
    i = dec(&num_blocks, v->buf, v->len, i, 0, "%" PRIu64);

    uint64_t lg_ack_in_block = lg_ack;
    if (before_ack)
        before_ack(c, lg_ack_in_block, ack_delay);

    for (uint64_t n = num_blocks + 1; n > 0; n--) {
        uint64_t gap = 0;
        uint64_t ack_block_len = 0;
        i = dec(&ack_block_len, v->buf, v->len, i, 0, "%" PRIu64);

        if (ack_block_len == 0)
            if (n == num_blocks + 1)
                warn(INF,
                     FRAM_IN "ACK" NRM " lg=" FMT_PNR_OUT " delay=%" PRIu64
                             " (%" PRIu64 " usec) cnt=%" PRIu64
                             " block=%" PRIu64,
                     lg_ack, ack_delay_raw, ack_delay, num_blocks,
                     ack_block_len);
            else
                warn(INF,
                     FRAM_IN "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                             " [" FMT_PNR_OUT "]",
                     gap, ack_block_len, lg_ack_in_block);
        else if (n == num_blocks + 1)
            warn(INF,
                 FRAM_IN "ACK" NRM " lg=" FMT_PNR_OUT " delay=%" PRIu64
                         " (%" PRIu64 " usec) cnt=%" PRIu64 " block=%" PRIu64
                         " [" FMT_PNR_OUT ".." FMT_PNR_OUT "]",
                 lg_ack, ack_delay_raw, ack_delay, num_blocks, ack_block_len,
                 lg_ack_in_block - ack_block_len,
                 shorten_ack_nr(lg_ack_in_block, ack_block_len));
        else
            warn(INF,
                 FRAM_IN "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                         " [" FMT_PNR_OUT ".." FMT_PNR_OUT "]",
                 gap, ack_block_len, lg_ack_in_block - ack_block_len,
                 shorten_ack_nr(lg_ack_in_block, ack_block_len));

        uint64_t ack = lg_ack_in_block;
        while (ack + ack_block_len >= lg_ack_in_block) {
            on_each_ack(c, ack);
            if (likely(ack > 0))
                ack--;
            else
                break;
        }

        if (n > 1) {
            i = dec(&gap, v->buf, v->len, i, 0, "%" PRIu64);
            lg_ack_in_block = ack - gap - 1;
        }
    }

    if (after_ack)
        after_ack(c);
    return i;
}

#if 0
static uint16_t __attribute__((nonnull))
dec_reset_stream_frame(struct q_conn * const c,
                       const struct w_iov * const v,
                       const uint16_t pos)
{
    uint16_t i = pos + 1;

    uint32_t sid = 0;
    i = dec(&sid, v->buf, v->len, i, 0, FMT_SID);
    struct q_stream * const s = get_stream(c, sid);
    ensure(s, "have stream %u", sid);

    uint16_t err_code = 0;
    i = dec(&err_code, v->buf, v->len, i, 0, "0x%04x");

    uint64_t off = 0;
    i = dec(&off, v->buf, v->len, i, 0, "%" PRIu64);

    warn(CRT, "TODO: handle RST_STREAM");

    return i;
}
#endif

static uint16_t __attribute__((nonnull))
dec_close_frame(struct q_conn * const c,
                const struct w_iov * const v,
                const uint16_t pos)
{
    uint8_t type = 0;
    uint16_t i = dec(&type, v->buf, v->len, pos, sizeof(type), "0x%02x");

    uint16_t err_code = 0;
    i = dec(&err_code, v->buf, v->len, i, sizeof(err_code), "0x%04x");

    uint64_t reas_len = 0;
    i = dec(&reas_len, v->buf, v->len, i, 0, "%" PRIu64);
    ensure(reas_len + i <= v->len, "reason_len invalid");

    char reas_phr[UINT16_MAX];
    if (reas_len) {
        memcpy(reas_phr, &v->buf[i], reas_len);
        i += reas_len;
    }

    conn_to_state(c, c->state == CONN_STAT_HSHK_DONE ? CONN_STAT_HSHK_FAIL
                                                     : CONN_STAT_DRNG);

    warn(INF,
         FRAM_IN "CLOSE" NRM " err=" RED "0x%04x " NRM "rlen=%" PRIu64
                 " reason=" RED "%.*s" NRM,
         err_code, reas_len, reas_len, reas_phr);

    return i;
}

static uint16_t __attribute__((nonnull))
dec_max_stream_data_frame(struct q_conn * const c,
                          const struct w_iov * const v,
                          const uint16_t pos)
{
    uint64_t sid = 0;
    uint16_t i = dec(&sid, v->buf, v->len, pos + 1, 0, FMT_SID);
    struct q_stream * const s = get_stream(c, sid);
    ensure(s, "have stream %u", sid);
    i = dec(&s->out_data_max, v->buf, v->len, i, 0, "%" PRIu64);
    s->blocked = false;

    // TODO: we should only do this if TX is pending on this stream
    s->c->needs_tx = true;

    warn(INF, FRAM_IN "MAX_STREAM_DATA" NRM " id=" FMT_SID " max=%" PRIu64, sid,
         s->out_data_max);

    return i;
}


static uint16_t __attribute__((nonnull))
dec_max_stream_id_frame(struct q_conn * const c,
                        const struct w_iov * const v,
                        const uint16_t pos)
{
    uint64_t max = 0;
    const uint16_t i = dec(&max, v->buf, v->len, pos + 1, 0, "%" PRIu64);

    ensure(is_set(STRM_FL_INI_SRV, max) != c->is_clnt,
           "illegal MAX_STREAM_ID %u", max);

    if (is_set(STRM_FL_DIR_UNI, max)) {
        c->peer_max_strm_uni = max;
        warn(INF, FRAM_IN "MAX_STREAM_ID" NRM " max=%" PRIu64 " (unidir)",
             c->peer_max_strm_uni);
    } else {
        c->peer_max_strm_bidi = max;
        warn(INF, FRAM_IN "MAX_STREAM_ID" NRM " max=%" PRIu64 " (bidir)",
             c->peer_max_strm_bidi);
    }

    return i;
}


static uint16_t __attribute__((nonnull))
dec_max_data_frame(struct q_conn * const c,
                   const struct w_iov * const v,
                   const uint16_t pos)
{
    const uint16_t i =
        dec(&c->peer_max_data, v->buf, v->len, pos + 1, 0, "%" PRIu64);
    c->blocked = false;

    warn(INF, FRAM_IN "MAX_DATA" NRM " max=%" PRIu64, c->peer_max_data);

    return i;
}


static uint16_t __attribute__((nonnull))
dec_stream_blocked_frame(struct q_conn * const c,
                         const struct w_iov * const v,
                         const uint16_t pos)
{
    uint64_t sid = 0;
    const uint16_t i = dec(&sid, v->buf, v->len, pos + 1, 0, FMT_SID);
    struct q_stream * const s = get_stream(c, sid);
    ensure(s, "have stream %u", sid);

    warn(INF, FRAM_IN "STREAM_BLOCKED" NRM " id=" FMT_SID, sid);

    // open the stream window and send a frame
    s->open_win = true;

    return i;
}


static uint16_t __attribute__((nonnull))
dec_stop_sending_frame(struct q_conn * const c,
                       const struct w_iov * const v,
                       const uint16_t pos)
{
    uint64_t sid = 0;
    uint16_t i = dec(&sid, v->buf, v->len, pos + 1, 0, FMT_SID);
    struct q_stream * const s = get_stream(c, sid);
    ensure(s, "have stream %u", sid);

    uint16_t err_code = 0;
    i = dec(&err_code, v->buf, v->len, i, sizeof(err_code), "0x%04x");

    warn(INF, FRAM_IN "STOP_SENDING" NRM " id=" FMT_SID " err=0x%04x", sid,
         err_code);

    return i;
}


static uint16_t __attribute__((nonnull))
dec_ping_frame(struct q_conn * const c,
               const struct w_iov * const v,
               const uint16_t pos)
{
    uint8_t len = 0;
    uint16_t i = dec(&len, v->buf, v->len, pos + 1, sizeof(len), "%u");

    warn(INF, FRAM_IN "PING" NRM " len=%u data=%.*s", len, len, v->buf[i]);

    if (len)
        err_close(c, ERR_FRAME_ERR(FRAM_TYPE_PING),
                  "TODO: ping frame with data not supported");

    c->needs_tx = true;

    return i;
}


uint16_t dec_frames(struct q_conn * const c, struct w_iov * v)
{
    uint16_t i = pkt_hdr_len(v->buf, v->len);
    uint16_t pad_start = 0;

    while (i < v->len) {
        const uint8_t type = ((const uint8_t * const)(v->buf))[i];
        if (pad_start && (type != FRAM_TYPE_PAD || i == v->len - 1)) {
            warn(INF, FRAM_IN "PADDING" NRM " len=%u", i - pad_start);
            pad_start = 0;
        }

        if (is_set(FRAM_TYPE_STRM, type)) {
            bit_set(meta(v).frames, FRAM_TYPE_STRM);
            if (meta(v).stream_data_start) {
                // already had at least one stream frame in this packet,
                // generate (another) copy
                warn(DBG, "more than one stream frame in pkt, copy");
                struct w_iov * const vdup =
                    q_alloc_iov(w_engine(c->sock), MAX_PKT_LEN, Q_OFFSET);
                memcpy(vdup->buf, v->buf, v->len);
                meta(vdup) = meta(v);
                vdup->len = v->len;
                // adjust w_iov start and len to stream frame data
                v->buf = &v->buf[meta(v).stream_data_start];
                v->len = stream_data_len(v);
                // continue parsing in the copied w_iov
                v = vdup;
            }

            // this is the first stream frame in this packet
            i = dec_stream_frame(c, v, i);

        } else if (is_set(FRAM_TYPE_ACK, type)) {
            bit_set(meta(v).frames, FRAM_TYPE_ACK);
            i = dec_ack_frame(c, v, i, &on_ack_rx_1, &on_pkt_acked,
                              on_ack_rx_2);

        } else {
            switch (type) {
            case FRAM_TYPE_PAD:
                pad_start = pad_start ? pad_start : i;
                i++;
                break;
#if 0
            case FRAM_TYPE_RST_STRM:
                i = dec_reset_stream_frame(c, v, i);
                break;
#endif

            case FRAM_TYPE_CONN_CLSE:
            case FRAM_TYPE_APPL_CLSE:
                i = dec_close_frame(c, v, i);
                break;

            case FRAM_TYPE_PING:
                i = dec_ping_frame(c, v, i);
                break;

            case FRAM_TYPE_MAX_STRM_DATA:
                i = dec_max_stream_data_frame(c, v, i);
                break;

            case FRAM_TYPE_MAX_SID:
                i = dec_max_stream_id_frame(c, v, i);
                break;

            case FRAM_TYPE_MAX_DATA:
                i = dec_max_data_frame(c, v, i);
                c->blocked = false;
                // TODO: we should only do this if TX is pending on any stream
                c->needs_tx = true;
                break;

            case FRAM_TYPE_STRM_BLCK:
                i = dec_stream_blocked_frame(c, v, i);
                break;

            case FRAM_TYPE_BLCK:
                c->open_win = true;
                warn(INF, FRAM_IN "BLOCKED" NRM);
                i++;
                break;

            case FRAM_TYPE_STOP_SEND:
                i = dec_stop_sending_frame(c, v, i);
                break;

            default:
                err_close(c, ERR_FRAME_ERR(type), "unknown frame type 0x%02x",
                          type);
                i = 0;
            }
        }

        if (i == 0)
            // there was an error parsing a frame
            return 0;

        // record this frame type in the meta data
        bit_set(meta(v).frames, type);
    }
    if (meta(v).stream_data_start) {
        // adjust w_iov start and len to stream frame data
        v->buf = &v->buf[meta(v).stream_data_start];
        v->len = stream_data_len(v);
    }

    return i;
}


uint16_t enc_padding_frame(struct w_iov * const v,
                           const uint16_t pos,
                           const uint16_t len)
{
    warn(INF, FRAM_OUT "PADDING" NRM " len=%u", len);
    memset(&v->buf[pos], FRAM_TYPE_PAD, len);
    bit_set(meta(v).frames, FRAM_TYPE_PAD);
    return pos + len;
}


uint16_t enc_ack_frame(struct q_conn * const c,
                       struct w_iov * const v,
                       const uint16_t pos)
{
    const uint8_t type = FRAM_TYPE_ACK;
    bit_set(meta(v).frames, FRAM_TYPE_ACK);
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), "0x%02x");

    const uint64_t lg_recv = diet_max(&c->recv);
    i = enc(v->buf, v->len, i, &lg_recv, 0, FMT_PNR_IN);

    const uint64_t ack_delay =
        (uint64_t)((ev_now(loop) - c->lg_recv_t) * 1000000) /
        (1 << c->local_ack_del_exp);
    i = enc(v->buf, v->len, i, &ack_delay, 0, "%" PRIu64);

    const uint64_t block_cnt = diet_cnt(&c->recv) - 1;
    i = enc(v->buf, v->len, i, &block_cnt, 0, "%" PRIu64);

    struct ival * b = 0;
    uint64_t prev_lo = 0;
    splay_foreach_rev (b, diet, &c->recv) {
        uint64_t gap = 0;
        if (prev_lo) {
            gap = prev_lo - b->hi - 2;
            i = enc(v->buf, v->len, i, &gap, 0, "%" PRIu64);
        }
        const uint64_t ack_block = b->hi - b->lo;

        if (ack_block)
            if (prev_lo)
                warn(INF,
                     FRAM_OUT "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                              " [" FMT_PNR_IN ".." FMT_PNR_IN "]",
                     gap, ack_block, b->lo, shorten_ack_nr(b->hi, ack_block));
            else
                warn(INF,
                     FRAM_OUT "ACK" NRM " lg=" FMT_PNR_IN " delay=%" PRIu64
                              " (%" PRIu64 " usec) cnt=%" PRIu64
                              " block=%" PRIu64 " [" FMT_PNR_IN ".." FMT_PNR_IN
                              "]",
                     lg_recv, ack_delay,
                     ack_delay * (1 << c->local_ack_del_exp), block_cnt,
                     ack_block, b->lo, shorten_ack_nr(b->hi, ack_block));
        else if (prev_lo)
            warn(INF,
                 FRAM_OUT "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                          " [" FMT_PNR_IN "]",
                 gap, ack_block, b->hi);
        else
            warn(INF,
                 FRAM_OUT "ACK" NRM " lg=" FMT_PNR_IN " delay=%" PRIu64
                          " (%" PRIu64 " usec) cnt=%" PRIu64 " block=%" PRIu64,
                 lg_recv, ack_delay, ack_delay * (1 << c->local_ack_del_exp),
                 block_cnt, ack_block);

        i = enc(v->buf, v->len, i, &ack_block, 0, "%" PRIu64);
        prev_lo = b->lo;
    }
    return i;
}


uint16_t enc_stream_frame(struct q_stream * const s, struct w_iov * const v)
{
    bit_set(meta(v).frames, FRAM_TYPE_STRM);

    const uint64_t dlen = v->len - Q_OFFSET;
    ensure(dlen || s->state > STRM_STAT_OPEN,
           "no stream data or need to send FIN");

    uint8_t type = FRAM_TYPE_STRM | (dlen ? F_STREAM_LEN : 0) |
                   (s->out_off ? F_STREAM_OFF : 0);

    // if stream is closed locally and this is the last packet, include a FIN
    if ((s->state == STRM_STAT_HCLO || s->state == STRM_STAT_CLSD) &&
        v == sq_last(&s->out, w_iov, next)) {
        type |= F_STREAM_FIN;
        s->fin_sent = 1;
        maybe_api_return(q_close_stream, s);
    }

    // now that we know how long the stream frame header is, encode it
    uint16_t i = meta(v).stream_header_pos =
        Q_OFFSET - 1 - varint_sizeof(s->id) - (dlen ? varint_sizeof(dlen) : 0) -
        (s->out_off ? varint_sizeof(s->out_off) : 0);
    i = enc(v->buf, v->len, i, &type, sizeof(type), "0x%02x");
    i = enc(v->buf, v->len, i, &s->id, 0, FMT_SID);
    if (s->out_off)
        i = enc(v->buf, v->len, i, &s->out_off, 0, "%" PRIu64);
    if (dlen)
        enc(v->buf, v->len, i, &dlen, 0, "%u");

    warn(INF,
         FRAM_OUT "STREAM" NRM " 0x%02x=%s%s%s%s%s id=" FMT_SID " off=%" PRIu64
                  " len=%" PRIu64,
         type, is_set(F_STREAM_FIN, type) ? "FIN" : "",
         is_set(F_STREAM_FIN, type) && is_set(F_STREAM_LEN | F_STREAM_OFF, type)
             ? "|"
             : "",
         is_set(F_STREAM_LEN, type) ? "LEN" : "",
         is_set(F_STREAM_OFF, type) ? "|" : "",
         is_set(F_STREAM_OFF, type) ? "OFF" : "", s->id, s->out_off, dlen);

    track_bytes_out(s, dlen);
    s->out_off += dlen; // increase the stream data offset
    meta(v).str = s;    // remember stream this buf belongs to
    meta(v).stream_data_start = Q_OFFSET;
    meta(v).stream_data_end = Q_OFFSET + (uint16_t)dlen;

    return v->len;
}


uint16_t enc_close_frame(struct w_iov * const v,
                         const uint16_t pos,
                         const uint8_t type,
                         const uint16_t err_code,
                         const char * const reas)
{
    bit_set(meta(v).frames, type);

    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), "0x%02x");
    i = enc(v->buf, v->len, i, &err_code, sizeof(err_code), "0x%04x");

    const uint64_t rlen = reas ? MIN(strlen(reas), v->len - i) : 0;
    i = enc(v->buf, v->len, i, &rlen, 0, "%" PRIu64);

    if (reas) {
        memcpy(&v->buf[i], reas, rlen);
        warn(DBG, "enc %" PRIu64 "-byte reason phrase into [%u..%" PRIu64 "]",
             rlen, i, i + rlen - 1);

        warn(INF,
             FRAM_OUT "CLOSE" NRM " err=" RED "0x%04x" NRM " rlen=%" PRIu64
                      " reason=" RED "%.*s" NRM,
             err_code, rlen, rlen, reas);

    } else
        warn(INF, FRAM_OUT "CLOSE" NRM " err=" RED "0x%04x" NRM, err_code);

    return i + (uint16_t)rlen;
}


uint16_t enc_max_stream_data_frame(struct q_stream * const s,
                                   struct w_iov * const v,
                                   const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_MAX_STRM_DATA);

    const uint8_t type = FRAM_TYPE_MAX_STRM_DATA;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), "0x%02x");
    i = enc(v->buf, v->len, i, &s->id, 0, FMT_SID);
    i = enc(v->buf, v->len, i, &s->in_data_max, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "MAX_STREAM_DATA" NRM " id=" FMT_SID " max=%" PRIu64,
         s->id, s->in_data_max);

    return i;
}


uint16_t enc_max_data_frame(struct q_conn * const c,
                            struct w_iov * const v,
                            const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_MAX_DATA);

    const uint8_t type = FRAM_TYPE_MAX_DATA;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), "0x%02x");
    i = enc(v->buf, v->len, i, &c->local_max_data, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "MAX_DATA" NRM " max=%" PRIu64, c->local_max_data);

    return i;
}


uint16_t enc_stream_blocked_frame(struct q_stream * const s,
                                  const struct w_iov * const v,
                                  const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_STRM_BLCK);

    const uint8_t type = FRAM_TYPE_STRM_BLCK;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), "0x%02x");
    i = enc(v->buf, v->len, i, &s->id, 0, FMT_SID);

    warn(INF, FRAM_OUT "STREAM_BLOCKED" NRM " id=" FMT_SID, s->id);

    return i;
}


uint16_t enc_blocked_frame(const struct w_iov * const v, const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_BLCK);

    const uint8_t type = FRAM_TYPE_BLCK;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), "0x%02x");

    warn(INF, FRAM_OUT "BLOCKED" NRM);

    return i;
}
