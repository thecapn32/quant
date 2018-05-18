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
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>

// #define FUZZING
#ifdef FUZZING
#include <stdlib.h>
#endif

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


static uint16_t __attribute__((nonnull))
dec_stream_frame(struct q_conn * const c,
                 struct w_iov * const v,
                 const uint16_t pos)
{
    bool track_bytes = false;
    meta(v).stream_header_pos = pos;
    const char * kind = 0;
    uint8_t type = 0;
    uint16_t i = dec(&type, v->buf, v->len, pos, sizeof(type), "0x%02x");

    uint64_t sid = 0;
    i = dec(&sid, v->buf, v->len, i, 0, FMT_SID);
    if (unlikely(sid && is_set(F_LONG_HDR, meta(v).hdr.flags) &&
                 meta(v).hdr.type != F_LH_0RTT)) {
        err_close(c, ERR_FRAME_ERR(type), "sid %u in 0x%02x-type pkt", sid,
                  meta(v).hdr.type);
        return 0;
    }

    if (is_set(F_STREAM_OFF, type))
        i = dec(&meta(v).stream_off, v->buf, v->len, i, 0, "%" PRIu64);
    else
        meta(v).stream_off = 0;

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
                 "ignoring frame for closed strm " FMT_SID " on %s conn %s",
                 sid, conn_type(c), cid2str(&c->scid));
            goto done;
        }

        if (unlikely(is_set(STRM_FL_INI_SRV, sid) != c->is_clnt)) {
            err_close(c, ERR_FRAME_ERR(type), "got sid %" PRIu64 " but am %s",
                      sid, conn_type(c));
            return 0;
        }

        if (is_set(STRM_FL_DIR_UNI, sid)) {
            err_close(c, ERR_INTERNAL_ERR,
                      "TODO: unidirectional streams not supported yet");
            return 0;
        }
        s = new_stream(c, sid, false);
    }
    meta(v).stream = s;

    // best case: new in-order data
    if (meta(v).stream_off == s->in_off) {
        kind = "seq";
        track_bytes = true;
        s->in_off += l;
        sq_insert_tail(&s->in, v, next);
        meta(v).stream = s;

        // check if a hole has been filled that lets us dequeue ooo data
        struct pkt_meta *p, *nxt;
        for (p = splay_min(pm_off_splay, &s->in_ooo);
             p && p->stream_off == s->in_off; p = nxt) {
            nxt = splay_next(pm_off_splay, &s->in_ooo, p);
            s->in_off += p->stream_data_end;
            meta(v).stream = s;
            sq_insert_tail(&s->in, w_iov(c->w, pm_idx(p)), next);
            splay_remove(pm_off_splay, &s->in_ooo, p);
        }

        // check if we have delivered a FIN, and act on it if we did
        struct w_iov * const last = sq_last(&s->in, w_iov, next);
        if (last) {
            const uint8_t last_type = last->buf[meta(last).stream_header_pos];
            if (is_set(F_STREAM_FIN, last_type)) {
                strm_to_state(s, s->state <= STRM_STAT_HCRM ? STRM_STAT_HCRM
                                                            : STRM_STAT_CLSD);
                if (s->id != 0)
                    maybe_api_return(q_readall_str, s);
            }
        }

        if (s->id != 0)
            maybe_api_return(q_read, s->c);
        goto done;
    }

    // data is a complete duplicate
    if (meta(v).stream_off + l <= s->in_off) {
        kind = RED "dup" NRM;
        goto done;
    }

    // data is out of order
    kind = YEL "ooo" NRM;
    splay_insert(pm_off_splay, &s->in_ooo, &meta(v));
    track_bytes = true;
    meta(v).stream = s;

done:
    warn(INF,
         FRAM_IN "STREAM" NRM " 0x%02x=%s%s%s%s%s id=" FMT_SID "/%" PRIu64
                 " cdata=%" PRIu64 "/%" PRIu64 " off=%" PRIu64 "/%" PRIu64
                 " len=%" PRIu64 " [%s]",
         type, is_set(F_STREAM_FIN, type) ? "FIN" : "",
         is_set(F_STREAM_FIN, type) &&
                 (is_set(F_STREAM_LEN, type) || is_set(F_STREAM_OFF, type))
             ? "|"
             : "",
         is_set(F_STREAM_LEN, type) ? "LEN" : "",
         is_set(F_STREAM_LEN, type) && is_set(F_STREAM_OFF, type) ? "|" : "",
         is_set(F_STREAM_OFF, type) ? "OFF" : "", sid, max_strm_id(s),
         s->c->in_data, s->c->tp_local.max_data, meta(v).stream_off,
         s->in_data_max, l, kind);

    if (track_bytes)
        track_bytes_in(s, l);

    if (s->id && meta(v).stream_off + l - 1 > s->in_data_max)
        err_close(c, ERR_FLOW_CONTROL_ERR,
                  "stream %" PRIu64 " off %" PRIu64 " > in_data_max %" PRIu64,
                  s->id, meta(v).stream_off + l - 1, s->in_data_max);

    return meta(v).stream_data_end;
}


uint64_t shorten_ack_nr(const uint64_t ack, const uint64_t diff)
{
    ensure(diff, "no diff between ACK %" PRIu64 " and diff %" PRIu64, ack,
           diff);

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
    void (*on_each_ack)(struct q_conn * const, const uint64_t, const uint8_t),
    void (*after_ack)(struct q_conn * const))
{
    uint8_t type = 0;
    uint16_t i = dec(&type, v->buf, v->len, pos, sizeof(type), "0x%02x");

    uint64_t lg_ack = 0;
    i = dec(&lg_ack, v->buf, v->len, i, 0, FMT_PNR_OUT);

    uint64_t ack_delay_raw = 0;
    i = dec(&ack_delay_raw, v->buf, v->len, i, 0, "%" PRIu64);

    // handshake pkts always use an ACK delay exponent of 3
    const uint8_t ade =
        meta(v).hdr.type <= F_LH_INIT && meta(v).hdr.type >= F_LH_HSHK
            ? 3
            : c->tp_peer.ack_del_exp;
    const uint64_t ack_delay = ack_delay_raw * (1 << ade);

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
                             " block=%" PRIu64 " [" FMT_PNR_OUT "]",
                     lg_ack, ack_delay_raw, ack_delay, num_blocks,
                     ack_block_len, lg_ack);
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
            on_each_ack(c, ack, meta(v).hdr.flags);
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
    if (reas_len)
        i = dec_buf(&reas_phr, v->buf, v->len, i, (uint16_t)reas_len, "%s");

    conn_to_state(c, c->state < CONN_STAT_HSHK_DONE ? CONN_STAT_HSHK_FAIL
                                                    : CONN_STAT_DRNG);

    warn(INF,
         FRAM_IN "%s" NRM " err=%s0x%04x " NRM "rlen=%" PRIu64
                 " reason=%s%.*s" NRM,
         type == FRAM_TYPE_CONN_CLSE ? "CONNECTION_CLOSE" : "APPLICATION_CLOSE",
         err_code ? RED : NRM, err_code, reas_len, err_code ? RED : NRM,
         reas_len, reas_phr);

    return i;
}

static uint16_t __attribute__((nonnull))
dec_max_stream_data_frame(struct q_conn * const c,
                          const struct w_iov * const v,
                          const uint16_t pos)
{
    uint64_t sid = 0;
    uint16_t i = dec(&sid, v->buf, v->len, pos + 1, 0, FMT_SID);
    struct q_stream * s = get_stream(c, sid);
    if (s == 0)
        s = new_stream(c, sid, false);
    ensure(s, "have stream %u", sid);
    i = dec(&s->out_data_max, v->buf, v->len, i, 0, "%" PRIu64);
    s->blocked = false;

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
        c->tp_peer.max_strm_uni = max;
        warn(INF, FRAM_IN "MAX_STREAM_ID" NRM " max=%" PRIu64 " (unidir)",
             c->tp_peer.max_strm_uni);
    } else {
        c->tp_peer.max_strm_bidi = max;
        warn(INF, FRAM_IN "MAX_STREAM_ID" NRM " max=%" PRIu64 " (bidir)",
             c->tp_peer.max_strm_bidi);
    }

    maybe_api_return(q_rsv_stream, c);

    return i;
}


static uint16_t __attribute__((nonnull))
dec_max_data_frame(struct q_conn * const c,
                   const struct w_iov * const v,
                   const uint16_t pos)
{
    const uint16_t i =
        dec(&c->tp_peer.max_data, v->buf, v->len, pos + 1, 0, "%" PRIu64);

    c->blocked = false;

    warn(INF, FRAM_IN "MAX_DATA" NRM " max=%" PRIu64, c->tp_peer.max_data);

    return i;
}


static uint16_t __attribute__((nonnull))
dec_stream_blocked_frame(struct q_conn * const c,
                         const struct w_iov * const v,
                         const uint16_t pos)
{
    uint64_t sid = 0;
    uint16_t i = dec(&sid, v->buf, v->len, pos + 1, 0, FMT_SID);
    struct q_stream * const s = get_stream(c, sid);
    if (unlikely(s == 0)) {
        err_close(c, ERR_FRAME_ERR(FRAM_TYPE_STRM_BLCK), "unknown strm %u",
                  sid);
        return 0;
    }

    uint64_t off = 0;
    i = dec(&off, v->buf, v->len, i, 0, "%" PRIu64);

    warn(INF, FRAM_IN "STREAM_BLOCKED" NRM " id=" FMT_SID " off=%" PRIu64, sid,
         off);

    if (off + 2 * MAX_PKT_LEN <= s->in_data_max)
        // open the stream window and send a frame
        s->in_data_max += 0x1000;
    s->tx_max_stream_data = s->c->needs_tx = true;

    return i;
}


static uint16_t __attribute__((nonnull))
dec_blocked_frame(struct q_conn * const c,
                  const struct w_iov * const v,
                  const uint16_t pos)
{
    uint64_t off = 0;
    uint16_t i = dec(&off, v->buf, v->len, pos + 1, 0, "%" PRIu64);

    warn(INF, FRAM_IN "BLOCKED" NRM " off=%" PRIu64, off);

    if (off + 2 * MAX_PKT_LEN <= c->tp_local.max_data)
        // open the connection window and send a frame
        c->tp_local.max_data += 0x1000;
    c->tx_max_data = c->needs_tx = true;

    return i;
}


static uint16_t __attribute__((nonnull))
dec_stream_id_blocked_frame(struct q_conn * const c,
                            const struct w_iov * const v,
                            const uint16_t pos)
{
    uint64_t sid = 0;
    uint16_t i = dec(&sid, v->buf, v->len, pos + 1, 0, FMT_SID);

    warn(INF, FRAM_IN "STREAM_ID_BLOCKED" NRM " sid=" FMT_SID, sid);

    if (sid + 4 <= c->tp_local.max_strm_bidi)
        // let the peer open more streams
        c->tp_local.max_strm_bidi += 4;
    c->needs_tx = c->tx_max_stream_id = true;

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
    if (unlikely(s == 0)) {
        err_close(c, ERR_FRAME_ERR(FRAM_TYPE_STOP_SEND), "unknown strm %u",
                  sid);
        return 0;
    }

    uint16_t err_code = 0;
    i = dec(&err_code, v->buf, v->len, i, sizeof(err_code), "0x%04x");

    warn(INF, FRAM_IN "STOP_SENDING" NRM " id=" FMT_SID " err=%s0x%04x" NRM,
         sid, err_code ? RED : NRM, err_code);

    return i;
}


static uint16_t __attribute__((nonnull))
dec_path_challenge_frame(struct q_conn * const c,
                         const struct w_iov * const v,
                         const uint16_t pos)
{
    uint16_t i = dec(&c->path_chlg_in, v->buf, v->len, pos + 1,
                     sizeof(c->path_chlg_in), "0x%" PRIx64);
    warn(INF, FRAM_IN "PATH_CHALLENGE" NRM " data=%" PRIx64, c->path_chlg_in);

    c->path_resp_out = c->path_chlg_in;
    c->needs_tx = c->tx_path_resp = true;

    return i;
}


static uint16_t __attribute__((nonnull))
dec_path_response_frame(struct q_conn * const c,
                        const struct w_iov * const v,
                        const uint16_t pos)
{
    uint16_t i = dec(&c->path_resp_in, v->buf, v->len, pos + 1,
                     sizeof(c->path_resp_in), "0x%" PRIx64);
    warn(INF, FRAM_IN "PATH_RESPONSE" NRM " data=%" PRIx64, c->path_resp_in);

    if (c->path_resp_in == c->path_chlg_out) {
        c->tx_path_chlg = false;
        if (c->is_clnt == false && c->state == CONN_STAT_HSHK_DONE) {
            // unblock stream 0 SH flight
            struct q_stream * s = get_stream(c, 0);
            s->out_data_max = 0;
            s->blocked = false;
        }
    }

    return i;
}


static uint16_t __attribute__((nonnull))
dec_new_cid_frame(struct q_conn * const c __attribute__((unused)),
                  const struct w_iov * const v,
                  const uint16_t pos)
{
    uint64_t seq = 0;
    uint16_t i = dec(&seq, v->buf, v->len, pos + 1, 0, "%" PRIu64);

    struct cid dcid = {0};
    i = dec(&dcid.len, v->buf, v->len, i, sizeof(dcid.len), "%u");
    i = dec_buf(dcid.id, v->buf, v->len, i, dcid.len, "%s");

    uint8_t token[16];
    i = dec_buf(token, v->buf, v->len, i, sizeof(token), "%s");

    warn(INF,
         FRAM_IN "NEW_CONNECTION_ID" NRM " seq=%" PRIu64
                 " len=%u dcid=%s token=%s",
         seq, dcid.len, hex2str(dcid.id, dcid.len),
         hex2str(token, sizeof(token)));

    // TODO: actually do something with the new CIDs

    return i;
}


static uint16_t __attribute__((nonnull))
dec_rst_stream_frame(struct q_conn * const c __attribute__((unused)),
                     const struct w_iov * const v,
                     const uint16_t pos)
{
    uint64_t sid = 0;
    uint16_t i = dec(&sid, v->buf, v->len, pos + 1, 0, FMT_SID);

    uint16_t err = 0;
    i = dec(&err, v->buf, v->len, i, sizeof(err), "0x%04x");

    uint64_t off = 0;
    i = dec(&off, v->buf, v->len, i, 0, "%" PRIu64);

    warn(INF,
         FRAM_IN "RST_STREAM" NRM " sid=" FMT_SID " err=%s0x%04x" NRM
                 " off=%" PRIu64,
         sid, err ? RED : NRM, err, off);

    // TODO: actually do something with this

    return i;
}


uint16_t dec_frames(struct q_conn * const c, struct w_iov * v)
{
    uint16_t i = meta(v).hdr.hdr_len;
    uint16_t pad_start = 0;

    while (i < v->len) {
        const uint8_t type = ((const uint8_t * const)(v->buf))[i];
        if (pad_start && (type != FRAM_TYPE_PAD || i == v->len - 1)) {
            warn(INF, FRAM_IN "PADDING" NRM " len=%u", i - pad_start);
            pad_start = 0;
        }

        if (is_set(FRAM_TYPE_STRM, type)) {
            bit_set(meta(v).frames, FRAM_TYPE_STRM);
            if (meta(v).stream_data_start && meta(v).stream) {
                // already had at least one stream frame in this packet
                // with non-duplicate data, so generate (another) copy
                warn(DBG, "addtl stream frame at pos %u, copy", i);
                struct w_iov * const vdup = w_iov_dup(v);
                pm_cpy(&meta(vdup), &meta(v));
                // adjust w_iov start and len to stream frame data
                v->buf = &v->buf[meta(v).stream_data_start];
                v->len = stream_data_len(v);
                // continue parsing in the copied w_iov
                v = vdup;
            }

            // this is the first stream frame in this packet
            i = dec_stream_frame(c, v, i);

        } else {
            switch (type) {
            case FRAM_TYPE_ACK:
                i = dec_ack_frame(c, v, i, &on_ack_rx_1, &on_pkt_acked,
                                  on_ack_rx_2);
                break;

            case FRAM_TYPE_PAD:
                pad_start = pad_start ? pad_start : i;
                i++;
                break;

            case FRAM_TYPE_RST_STRM:
                i = dec_rst_stream_frame(c, v, i);
                break;

            case FRAM_TYPE_CONN_CLSE:
            case FRAM_TYPE_APPL_CLSE:
                i = dec_close_frame(c, v, i);
                break;

            case FRAM_TYPE_PING:
                warn(INF, FRAM_IN "PING" NRM);
                // PIMG frames need to be ACK'ed
                c->needs_tx = true;
                i++;
                break;

            case FRAM_TYPE_MAX_STRM_DATA:
                i = dec_max_stream_data_frame(c, v, i);
                break;

            case FRAM_TYPE_MAX_SID:
                i = dec_max_stream_id_frame(c, v, i);
                break;

            case FRAM_TYPE_MAX_DATA:
                i = dec_max_data_frame(c, v, i);
                break;

            case FRAM_TYPE_STRM_BLCK:
                i = dec_stream_blocked_frame(c, v, i);
                break;

            case FRAM_TYPE_BLCK:
                i = dec_blocked_frame(c, v, i);
                break;

            case FRAM_TYPE_ID_BLCK:
                i = dec_stream_id_blocked_frame(c, v, i);
                break;

            case FRAM_TYPE_STOP_SEND:
                i = dec_stop_sending_frame(c, v, i);
                break;

            case FRAM_TYPE_PATH_CHLG:
                i = dec_path_challenge_frame(c, v, i);
                break;

            case FRAM_TYPE_PATH_RESP:
                i = dec_path_response_frame(c, v, i);
                break;

            case FRAM_TYPE_NEW_CID:
                i = dec_new_cid_frame(c, v, i);
                break;

            default:
#ifdef FUZZING
                warn(DBG, "ignoring unknown frame type 0x%02x at pos %u", type,
                     i);
                i++;
#else
                err_close(c, ERR_FRAME_ERR(type),
                          "unknown frame type 0x%02x at pos %u", type, i);
                i = 0;
#endif
            }
        }

        if (unlikely(i == 0))
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
    if (unlikely(len == 0))
        return pos;
    warn(INF, FRAM_OUT "PADDING" NRM " len=%u", len);
#ifdef FUZZING
    if (arc4random() % 9 == 0) {
        // instead of encoding padding bytes, encode random data
        uint8_t fuzz[16];
        arc4random_buf(fuzz, sizeof(fuzz));
        memset_pattern16(&v->buf[pos], fuzz, len);
    } else
#endif
        memset(&v->buf[pos], FRAM_TYPE_PAD, len);
    bit_set(meta(v).frames, FRAM_TYPE_PAD);
    return pos + len;
}


/// Does a have better or equal packet protection to b?
///
/// @param[in]  a     Packet flags.
/// @param[in]  b     Packet flags.
///
/// @return     True if @p a has better or equal packet protection than @p b.
///
bool better_or_equal_prot(const uint8_t a, const uint8_t b)
{
    bool ret = false;

    // if a is a short-header packet (= 1-RTT), we're OK
    if (!is_set(F_LONG_HDR, a))
        ret = true;

    // a is long-header if we get here; if b is 0-RTT, a must also be 0-RTT
    else if (pkt_type(b) == F_LH_0RTT)
        ret = pkt_type(a) == F_LH_0RTT;

    // a is long-header if we get here; b cannot be short-header
    else if (!is_set(F_LONG_HDR, b))
        ret = false;

    // all other long-header packers are equally protected
    else
        ret = true;

    // warn(INF, "a 0x%02x, b 0x%02x = %u", a, b, ret);
    return ret;
}


uint16_t enc_ack_frame(struct q_conn * const c,
                       struct w_iov * const v,
                       const uint16_t pos)
{
    struct ival *b = 0, *lg_hi = 0, *lg_lo = 0, *cur_hi = 0, *cur_lo = 0;
    uint64_t block_cnt = 0;

    splay_foreach_rev (b, diet, &c->recv) {
        // warn(DBG, "range %" PRIu64 " - %" PRIu64 " 0x%02x", b->hi, b->lo,
        //      diet_class(b));

        const bool prot_ok =
            better_or_equal_prot(meta(v).hdr.flags, diet_class(b));

        if (!prot_ok) {
            // warn(DBG, "prot not OK, skipping (ranges=%u)", block_cnt);
            if (cur_lo && lg_lo == 0) {
                lg_lo = cur_lo;
                // warn(DBG, "found lg_lo %" PRIu64 " - %" PRIu64 " 0x%02x",
                //      lg_lo->hi, lg_lo->lo, diet_class(lg_lo));
            }
            cur_hi = cur_lo = 0;
            continue;
        }

        if (cur_hi == 0) {
            cur_hi = cur_lo = b;
            if (lg_hi == 0) {
                lg_hi = b;
                // warn(DBG, "found lg_hi %" PRIu64 " - %" PRIu64 " 0x%02x",
                //      lg_hi->hi, lg_hi->lo, diet_class(lg_hi));
            } else {
                block_cnt++;
                // warn(DBG, "new range (ranges=%u)", block_cnt);
            }
            continue;
        }

        if (cur_lo->lo > b->hi + 1) {
            block_cnt++;
            // warn(DBG, "new range (ranges=%u)", block_cnt);
            if (lg_lo == 0) {
                lg_lo = cur_lo;
                // warn(DBG, "found lg_lo %" PRIu64 " - %" PRIu64 " 0x%02x",
                //      lg_lo->hi, lg_lo->lo, diet_class(lg_lo));
            }
            cur_hi = cur_lo = b;
            continue;
        }

        // warn(DBG, "joining with current");
        cur_lo = b;
    }

    if (lg_hi == 0) {
        warn(WRN, "nothing to ACK");
        return pos;
    }

    if (lg_lo == 0) {
        lg_lo = splay_min(diet, &c->recv);
        // warn(DBG, "found lg_lo %" PRIu64 " - %" PRIu64 " 0x%02x", lg_lo->hi,
        //      lg_lo->lo, diet_class(lg_lo));
    }

    const uint8_t type = FRAM_TYPE_ACK;
    bit_set(meta(v).frames, FRAM_TYPE_ACK);
    meta(v).ack_header_pos = pos;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");

    i = enc(v->buf, v->len, i, &lg_hi->hi, 0, 0, FMT_PNR_IN);

    // handshake pkts always use an ACK delay exponent of 3
    const uint8_t ade =
        meta(v).hdr.type <= F_LH_INIT && meta(v).hdr.type >= F_LH_HSHK
            ? 3
            : c->tp_local.ack_del_exp;
    const uint64_t ack_delay =
        (uint64_t)((ev_now(loop) - diet_timestamp(lg_hi)) * 1000000) /
        (1 << ade);
    i = enc(v->buf, v->len, i, &ack_delay, 0, 0, "%" PRIu64);

    i = enc(v->buf, v->len, i, &block_cnt, 0, 0, "%" PRIu64);

    // warn(DBG, "lg range %" PRIu64 " - %" PRIu64 " 0x%02x", lg_hi->hi,
    // lg_lo->lo,
    //      diet_class(lg_hi));

    // encode the first ACK block directly
    uint64_t block = lg_hi->hi - lg_lo->lo;
    i = enc(v->buf, v->len, i, &block, 0, 0, "%" PRIu64);

    if (block)
        warn(INF,
             FRAM_OUT "ACK" NRM " lg=" FMT_PNR_IN " delay=%" PRIu64 " (%" PRIu64
                      " usec) cnt=%" PRIu64 " block=%" PRIu64 " [" FMT_PNR_IN
                      ".." FMT_PNR_IN "]",
             lg_hi->hi, ack_delay, ack_delay * (1 << ade), block_cnt, block,
             lg_lo->lo, shorten_ack_nr(lg_hi->hi, block));
    else
        warn(INF,
             FRAM_OUT "ACK" NRM " lg=" FMT_PNR_IN " delay=%" PRIu64 " (%" PRIu64
                      " usec) cnt=%" PRIu64 " block=%" PRIu64 " [" FMT_PNR_IN
                      "]",
             lg_hi->hi, ack_delay, ack_delay * (1 << ade), block_cnt, block,
             lg_hi->hi);

    cur_hi = lg_hi;
    cur_lo = lg_lo;
    b = splay_prev(diet, &c->recv, lg_lo);

    while (b) {

        // warn(DBG, "range %" PRIu64 " - %" PRIu64 " 0x%02x", b->hi, b->lo,
        //      diet_class(b));

        // warn(DBG, "cur %" PRIu64 " - %" PRIu64 " 0x%02x", cur_hi->hi,
        //      cur_lo->lo, diet_class(cur_hi));

        if (better_or_equal_prot(meta(v).hdr.flags, diet_class(b)) == false) {
            // warn(DBG, "prot not OK, skipping range");
            goto next;
        }

        if (cur_lo->lo == b->hi + 1 &&
            better_or_equal_prot(meta(v).hdr.flags, diet_class(b))) {
            // warn(DBG, "can join with prev");
            cur_lo = b;
            goto next;
        }

        uint64_t gap = 0;
        if (cur_lo->lo > b->hi + 1 || splay_prev(diet, &c->recv, b) == 0) {
            // warn(DBG, "have gap");
            gap = cur_lo->lo - b->hi - 2;
            i = enc(v->buf, v->len, i, &gap, 0, 0, "%" PRIu64);
            cur_hi = cur_lo = b;
        }

        block = cur_hi->hi - cur_lo->lo;
        i = enc(v->buf, v->len, i, &block, 0, 0, "%" PRIu64);

        if (block)
            warn(INF,
                 FRAM_OUT "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                          " [" FMT_PNR_IN ".." FMT_PNR_IN "]",
                 gap, block, cur_lo->lo, shorten_ack_nr(cur_hi->hi, block));
        else
            warn(INF,
                 FRAM_OUT "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                          " [" FMT_PNR_IN "]",
                 gap, block, cur_lo->lo);

    next:
        b = splay_prev(diet, &c->recv, b);
    }
    return i;
}


uint16_t enc_stream_frame(struct q_stream * const s,
                          struct w_iov * const v,
                          const uint16_t pos)
{
    ensure(s->id == 0 || !is_set(F_LONG_HDR, meta(v).hdr.flags) ||
               meta(v).hdr.type == F_LH_0RTT,
           "sid %u in 0x%02x-type pkt", s->id, meta(v).hdr.type);

    const uint64_t dlen = v->len - Q_OFFSET;
    ensure(dlen || s->state > STRM_STAT_OPEN,
           "no stream data or need to send FIN");

    uint8_t type = FRAM_TYPE_STRM | (dlen ? F_STREAM_LEN : 0) |
                   (s->out_off ? F_STREAM_OFF : 0);

    // if stream is closed locally and this is the last packet, include a FIN
    if ((s->state == STRM_STAT_HCLO || s->state == STRM_STAT_CLSD) &&
        v == sq_last(&s->out, w_iov, next)) {
        type |= F_STREAM_FIN;
        maybe_api_return(q_close_stream, s);
    }
    bit_set(meta(v).frames, type);

    // now that we know how long the stream frame header is, encode it
    uint16_t i = meta(v).stream_header_pos =
        Q_OFFSET - 1 - varint_size_needed(s->id) -
        (dlen ? varint_size_needed(dlen) : 0) -
        (s->out_off ? varint_size_needed(s->out_off) : 0);
    ensure(i > pos, "Q_OFFSET exhausted (%u > %u)", i, pos);
    i = enc(v->buf, v->len, i, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &s->id, 0, 0, FMT_SID);
    if (s->out_off)
        i = enc(v->buf, v->len, i, &s->out_off, 0, 0, "%" PRIu64);
    if (dlen)
        enc(v->buf, v->len, i, &dlen, 0, 0, "%u");

    warn(INF,
         FRAM_OUT "STREAM" NRM " 0x%02x=%s%s%s%s%s id=" FMT_SID "/%" PRIu64
                  " cdata=%" PRIu64 "/%" PRIu64 " off=%" PRIu64 "/%" PRIu64
                  " len=%" PRIu64,
         type, is_set(F_STREAM_FIN, type) ? "FIN" : "",
         is_set(F_STREAM_FIN, type) &&
                 (is_set(F_STREAM_LEN, type) || is_set(F_STREAM_OFF, type))
             ? "|"
             : "",
         is_set(F_STREAM_LEN, type) ? "LEN" : "",
         is_set(F_STREAM_LEN, type) && is_set(F_STREAM_OFF, type) ? "|" : "",
         is_set(F_STREAM_OFF, type) ? "OFF" : "", s->id, max_strm_id(s),
         s->c->out_data, s->c->tp_peer.max_data, s->out_off, s->out_data_max,
         dlen);

    track_bytes_out(s, dlen);
    meta(v).stream = s; // remember stream this buf belongs to
    meta(v).stream_data_start = Q_OFFSET;
    meta(v).stream_data_end = Q_OFFSET + (uint16_t)dlen;
    meta(v).stream_off = s->out_off;

    s->out_off += dlen; // increase the stream data offset

    return v->len;
}


uint16_t enc_close_frame(struct w_iov * const v,
                         const uint16_t pos,
                         const uint8_t type,
                         const uint16_t err_code,
                         const char * const reas)
{
    bit_set(meta(v).frames, type);

    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &err_code, sizeof(err_code), 0, "0x%04x");

    const uint64_t rlen = reas ? MIN(strlen(reas), v->len - i) : 0;
    i = enc(v->buf, v->len, i, &rlen, 0, 0, "%" PRIu64);

    if (reas) {
        i = enc_buf(v->buf, v->len, i, reas, (uint16_t)rlen, "%s");
        warn(INF,
             FRAM_OUT "%s" NRM " err=%s0x%04x" NRM " rlen=%" PRIu64
                      " reason=%s%.*s" NRM,
             type == FRAM_TYPE_CONN_CLSE ? "CONNECTION_CLOSE"
                                         : "APPLICATION_CLOSE",
             err_code ? RED : NRM, err_code, rlen, err_code ? RED : NRM, rlen,
             reas);
    } else
        warn(INF, FRAM_OUT "%s" NRM " err=%s0x%04x" NRM,
             type == FRAM_TYPE_CONN_CLSE ? "CONNECTION_CLOSE"
                                         : "APPLICATION_CLOSE",
             err_code ? RED : NRM, err_code);

    return i;
}


uint16_t enc_max_stream_data_frame(struct q_stream * const s,
                                   struct w_iov * const v,
                                   const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_MAX_STRM_DATA);

    const uint8_t type = FRAM_TYPE_MAX_STRM_DATA;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &s->id, 0, 0, FMT_SID);
    i = enc(v->buf, v->len, i, &s->in_data_max, 0, 0, "%" PRIu64);

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
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &c->tp_local.max_data, 0, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "MAX_DATA" NRM " max=%" PRIu64, c->tp_local.max_data);

    return i;
}


uint16_t enc_max_stream_id_frame(struct q_conn * const c,
                                 struct w_iov * const v,
                                 const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_MAX_SID);

    const uint8_t type = FRAM_TYPE_MAX_SID;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &c->tp_local.max_strm_bidi, 0, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "MAX_STREAM_ID" NRM " max=%" PRIu64,
         c->tp_local.max_strm_bidi);

    return i;
}


uint16_t enc_stream_blocked_frame(struct q_stream * const s,
                                  const struct w_iov * const v,
                                  const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_STRM_BLCK);

    const uint8_t type = FRAM_TYPE_STRM_BLCK;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &s->id, 0, 0, FMT_SID);
    i = enc(v->buf, v->len, i, &s->out_off, 0, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "STREAM_BLOCKED" NRM " id=" FMT_SID " off=%" PRIu64,
         s->id, s->out_off);

    return i;
}


uint16_t enc_blocked_frame(struct q_conn * const c,
                           const struct w_iov * const v,
                           const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_BLCK);

    const uint8_t type = FRAM_TYPE_BLCK;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &c->tp_peer.max_data, 0, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "BLOCKED" NRM " off=%" PRIu64, c->tp_peer.max_data);

    return i;
}


uint16_t enc_stream_id_blocked_frame(struct q_conn * const c,
                                     const struct w_iov * const v,
                                     const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_ID_BLCK);

    const uint8_t type = FRAM_TYPE_ID_BLCK;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &c->tp_peer.max_strm_bidi, 0, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "STREAM_ID_BLOCKED" NRM " sid=" FMT_SID,
         c->tp_peer.max_strm_bidi);

    return i;
}


uint16_t enc_path_response_frame(struct q_conn * const c,
                                 const struct w_iov * const v,
                                 const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_PATH_RESP);

    const uint8_t type = FRAM_TYPE_PATH_RESP;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &c->path_resp_out, sizeof(c->path_resp_out), 0,
            "0x%" PRIx64);

    warn(INF, FRAM_OUT "PATH_RESPONSE" NRM " data=%" PRIx64, c->path_resp_out);

    return i;
}


uint16_t enc_path_challenge_frame(struct q_conn * const c,
                                  const struct w_iov * const v,
                                  const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_PATH_CHLG);

    const uint8_t type = FRAM_TYPE_PATH_CHLG;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &c->path_chlg_out, sizeof(c->path_chlg_out), 0,
            "0x%" PRIx64);

    warn(INF, FRAM_OUT "PATH_CHALLENGE" NRM " data=%" PRIx64, c->path_chlg_out);

    return i;
}
