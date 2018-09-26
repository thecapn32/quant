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
#include <stdlib.h>
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
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"


#define err_close_return(c, code, ...)                                         \
    do {                                                                       \
        err_close((c), (code), __VA_ARGS__);                                   \
        return UINT16_MAX;                                                     \
    } while (0)


#define dec_chk(do_close, type, dst, buf, buf_len, pos, dst_len, ...)          \
    __extension__({                                                            \
        const uint16_t _i =                                                    \
            dec((dst), (buf), (buf_len), (pos), (dst_len), __VA_ARGS__);       \
        if (unlikely(_i == UINT16_MAX)) {                                      \
            if (do_close)                                                      \
                err_close_return(c, ERR_FRAME_ENC, (type), "dec %s in %s:%u",  \
                                 #dst, __FILE__, __LINE__);                    \
            else                                                               \
                die("dec error %s", #dst);                                     \
        }                                                                      \
        _i;                                                                    \
    })


#define dec_chk_buf(do_close, type, dst, buf, buf_len, pos, dst_len)           \
    __extension__({                                                            \
        const uint16_t _i =                                                    \
            dec_buf((dst), (buf), (buf_len), (pos), (dst_len));                \
        if (unlikely(_i == UINT16_MAX)) {                                      \
            if (do_close)                                                      \
                err_close_return(c, ERR_FRAME_ENC, (type), "dec %s in %s:%u",  \
                                 #dst, __FILE__, __LINE__);                    \
            else                                                               \
                die("dec_buf error %s", #dst);                                 \
        }                                                                      \
        _i;                                                                    \
    })


#ifndef NDEBUG
void log_stream_or_crypto_frame(const bool rtx,
                                const struct w_iov * const v,
                                const bool in,
                                const char * const kind)
{
    const struct q_stream * const s = meta(v).stream;
    const struct q_conn * const c = s->c;
    const uint8_t type = v->buf[meta(v).stream_header_pos];

    if (s->id >= 0)
        warn(INF,
             "%sSTREAM" NRM " 0x%02x=%s%s%s%s%s id=" FMT_SID "/%" PRIu64
             " cdata=%" PRIu64 "/%" PRIu64 " off=%" PRIu64 "/%" PRIu64
             " len=%u %s%s%s%s",
             in ? FRAM_IN : FRAM_OUT, type,
             is_set(F_STREAM_FIN, type) ? "FIN" : "",
             is_set(F_STREAM_FIN, type) &&
                     (is_set(F_STREAM_LEN, type) || is_set(F_STREAM_OFF, type))
                 ? "|"
                 : "",
             is_set(F_STREAM_LEN, type) ? "LEN" : "",
             is_set(F_STREAM_LEN, type) && is_set(F_STREAM_OFF, type) ? "|"
                                                                      : "",
             is_set(F_STREAM_OFF, type) ? "OFF" : "", s->id,
             is_set(STRM_FL_INI_SRV, s->id) == c->is_clnt
                 ? ((c->tp_in.max_bidi_streams - 1) << 2) +
                       (is_set(STRM_FL_INI_SRV, s->id) ? STRM_FL_INI_SRV : 0)
                 : ((c->tp_out.max_bidi_streams - 1) << 2) +
                       (is_set(STRM_FL_INI_SRV, s->id) ? STRM_FL_INI_SRV : 0),
             in ? c->in_data : c->out_data,
             in ? c->tp_in.max_data : c->tp_out.max_data, meta(v).stream_off,
             in ? s->in_data_max : s->out_data_max, stream_data_len(v),
             rtx ? REV BLD GRN "[RTX]" NRM " " : "", in ? "[" : "", kind,
             in ? "]" : "");
    else
        warn(INF, "%sCRYPTO" NRM " 0x%02x off=%" PRIu64 " len=%u %s%s%s%s",
             in ? FRAM_IN : FRAM_OUT, type, meta(v).stream_off,
             stream_data_len(v), rtx ? REV BLD GRN "[RTX]" NRM " " : "",
             in ? "[" : "", kind, in ? "]" : "");
}
#endif


static uint16_t __attribute__((nonnull))
dec_stream_or_crypto_frame(struct q_conn * const c,
                           struct w_iov * const v,
                           const uint16_t pos)
{
    meta(v).stream_header_pos = pos;

    // decode the type byte, to check whether this is a stream or crypto frame
    uint8_t t = 0;
    uint16_t i = dec_chk(true, t, &t, v->buf, v->len, pos, sizeof(t), "0x%02x");

    int64_t sid = 0;
    if (t == FRAM_TYPE_CRPT)
        sid = crpt_strm_id(epoch_for_pkt_type(meta(v).hdr.type));
    else
        i = dec_chk(true, t, &sid, v->buf, v->len, i, 0, FMT_SID);

    if (is_set(F_STREAM_OFF, t) || t == FRAM_TYPE_CRPT)
        i = dec_chk(true, t, &meta(v).stream_off, v->buf, v->len, i, 0,
                    "%" PRIu64);
    else
        meta(v).stream_off = 0;

    uint64_t l = 0;
    if (is_set(F_STREAM_LEN, t) || t == FRAM_TYPE_CRPT) {
        i = dec_chk(true, t, &l, v->buf, v->len, i, 0, "%" PRIu64);
        if (unlikely(l > (uint64_t)v->len - i))
            err_close_return(c, ERR_FRAME_ENC, t, "illegal strm len");
    } else
        // stream data extends to end of packet
        l = v->len - i;

    meta(v).stream_data_start = i;
    meta(v).stream_data_end = (uint16_t)l + i;

    // deliver data into stream
    bool is_dup = false;
    struct q_stream * s = get_stream(c, sid);
#ifndef FUZZING
    const char * kind = "";
    if (t != FRAM_TYPE_CRPT && s == 0) {
        if (diet_find(&c->closed_streams, (uint64_t)sid)) {
            warn(WRN,
                 "ignoring frame for closed strm " FMT_SID " on %s conn %s",
                 sid, conn_type(c), cid2str(sq_first(&c->scid)));
            goto done;
        }

        if (unlikely(is_set(STRM_FL_INI_SRV, sid) != c->is_clnt))
            err_close_return(c, ERR_FRAME_ENC, t,
                             "got sid %" PRIu64 " but am %s", sid,
                             conn_type(c));

        if (is_set(STRM_FL_DIR_UNI, sid))
            err_close_return(c, ERR_INTERNAL, 0,
                             "TODO: unidirectional streams not supported yet");

        s = new_stream(c, sid);
    }
    meta(v).stream = s;

    // best case: new in-order data
    if (meta(v).stream_off == s->in_data) {
        kind = "seq";
        track_bytes_in(s, l);
        sq_insert_tail(&s->in, v, next);

        // check if a hole has been filled that lets us dequeue ooo data
        struct pkt_meta *p, *nxt;
        for (p = splay_min(pm_off_splay, &s->in_ooo);
             p && p->stream_off == s->in_data; p = nxt) {
            nxt = splay_next(pm_off_splay, &s->in_ooo, p);
            track_bytes_in(s, p->stream_data_end - p->stream_data_start);
            sq_insert_tail(&s->in, w_iov(c->w, pm_idx(p)), next);
            splay_remove(pm_off_splay, &s->in_ooo, p);
        }

        // check if we have delivered a FIN, and act on it if we did
        struct w_iov * const last = sq_last(&s->in, w_iov, next);
        if (last) {
            // if last is the current packet, its v->buf is the start of the
            // packet header; if it's dequeued from ooo, its v->buf points to
            // the start of the stream data - deal with this:
            if (last != v)
                last->buf -= meta(v).stream_data_start;
            if (is_fin(last)) {
                strm_to_state(s, s->state <= strm_hcrm ? strm_hcrm : strm_clsd);
                if (t != FRAM_TYPE_CRPT)
                    maybe_api_return(q_readall_str, s->c, s);
            }
            if (last != v)
                last->buf += meta(v).stream_data_start;
        }

        if (t != FRAM_TYPE_CRPT) {
            do_stream_fc(s);
            do_conn_fc(s->c);
            s->c->have_new_data = true;
            maybe_api_return(q_read, s->c, 0);
        }
        goto done;
    }

    // data is a complete duplicate
    if (meta(v).stream_off + l <= s->in_data) {
        kind = RED "dup" NRM;
        is_dup = true;
        goto done;
    }

    // data is out of order
    kind = YEL "ooo" NRM;
    splay_insert(pm_off_splay, &s->in_ooo, &meta(v));

done:
    log_stream_or_crypto_frame(false, v, true, kind);
#endif

    if (s && t != FRAM_TYPE_CRPT && meta(v).stream_off + l > s->in_data_max)
        err_close_return(c, ERR_FLOW_CONTROL, 0,
                         "stream %" PRIu64 " off %" PRIu64
                         " > in_data_max %" PRIu64,
                         s->id, meta(v).stream_off + l - 1, s->in_data_max);

    if (is_dup)
        // this indicates to callers that the w_iov was not placed in a stream
        meta(v).stream = 0;

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


uint16_t dec_ack_frame(struct q_conn * const c,
                       const struct w_iov * const v,
                       const uint16_t pos,
                       void (*before_ack)(struct q_conn * const,
                                          struct pn_space * const pn,
                                          const uint64_t,
                                          const uint64_t),
                       void (*on_each_ack)(struct q_conn * const,
                                           struct pn_space * const pn,
                                           const uint64_t),
                       void (*after_ack)(struct q_conn * const,
                                         struct pn_space * const pn),
                       const bool parse_only)
{
    // we need to decode the type byte, to check for ACK_ECN
    uint8_t t = 0;
    uint16_t i = dec_chk(true, t, &t, v->buf, v->len, pos, sizeof(t), "0x%02x");

    uint64_t lg_ack = 0;
    i = dec_chk(!parse_only, t, &lg_ack, v->buf, v->len, i, 0, FMT_PNR_OUT);

    uint64_t ack_delay_raw = 0;
    i = dec_chk(!parse_only, t, &ack_delay_raw, v->buf, v->len, i, 0,
                "%" PRIu64);

    uint64_t ect0_cnt = 0, ect1_cnt = 0, ce_cnt = 0;
    if (t == FRAM_TYPE_ACK_ECN) {
        // decode ECN
        i = dec_chk(!parse_only, t, &ect0_cnt, v->buf, v->len, i, 0,
                    "%" PRIu64);
        i = dec_chk(!parse_only, t, &ect1_cnt, v->buf, v->len, i, 0,
                    "%" PRIu64);
        i = dec_chk(!parse_only, t, &ce_cnt, v->buf, v->len, i, 0, "%" PRIu64);
    }

    // TODO: figure out a better way to handle huge ACK delays
    if (unlikely(ack_delay_raw > UINT32_MAX))
        err_close_return(c, ERR_FRAME_ENC, t, "ACK delay raw %" PRIu64,
                         ack_delay_raw);

    // handshake pkts always use an ACK delay exponent of 3
    const uint8_t ade =
        meta(v).hdr.type == F_LH_INIT && meta(v).hdr.type == F_LH_HSHK
            ? 3
            : c->tp_in.ack_del_exp;
    const uint64_t ack_delay = ack_delay_raw * (1 << ade);

    struct pn_space * const pn = pn_for_pkt_type(c, meta(v).hdr.type);

    uint64_t num_blocks = 0;
    i = dec_chk(!parse_only, t, &num_blocks, v->buf, v->len, i, 0, "%" PRIu64);

    uint64_t lg_ack_in_block = lg_ack;
    if (before_ack)
        before_ack(c, pn, lg_ack_in_block, ack_delay);

    for (uint64_t n = num_blocks + 1; n > 0; n--) {
        uint64_t gap = 0;
        uint64_t ack_block_len = 0;
        i = dec_chk(!parse_only, t, &ack_block_len, v->buf, v->len, i, 0,
                    "%" PRIu64);

        // TODO: figure out a better way to handle huge ACK blocks
        if (unlikely(ack_block_len > UINT16_MAX))
            err_close_return(c, ERR_FRAME_ENC, t, "ACK block len %" PRIu64,
                             ack_block_len);

#ifndef FUZZING
        if (ack_block_len == 0) {
            if (n == num_blocks + 1) {
                if (t == FRAM_TYPE_ACK_ECN)
                    warn(INF,
                         FRAM_IN
                         "ACK_ECN" NRM " lg=" FMT_PNR_OUT " delay=%" PRIu64
                         " (%" PRIu64 " usec) ect0=%" PRIu64 " ect1=%" PRIu64
                         " ce=%" PRIu64 " cnt=%" PRIu64 " block=%" PRIu64
                         " [" FMT_PNR_OUT "]",
                         lg_ack, ack_delay_raw, ack_delay, ect0_cnt, ect1_cnt,
                         ce_cnt, num_blocks, ack_block_len, lg_ack);
                else
                    warn(INF,
                         FRAM_IN "ACK" NRM " lg=" FMT_PNR_OUT " delay=%" PRIu64
                                 " (%" PRIu64 " usec) cnt=%" PRIu64
                                 " block=%" PRIu64 " [" FMT_PNR_OUT "]",
                         lg_ack, ack_delay_raw, ack_delay, num_blocks,
                         ack_block_len, lg_ack);
            } else
                warn(INF,
                     FRAM_IN "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                             " [" FMT_PNR_OUT "]",
                     gap, ack_block_len, lg_ack_in_block);
        } else {
            if (n == num_blocks + 1) {
                if (t == FRAM_TYPE_ACK_ECN)
                    warn(INF,
                         FRAM_IN "ACK_ECN" NRM " lg=" FMT_PNR_OUT
                                 " delay=%" PRIu64 " (%" PRIu64
                                 " usec) cnt=%" PRIu64 " block=%" PRIu64
                                 " [" FMT_PNR_OUT ".." FMT_PNR_OUT "]",
                         lg_ack, ack_delay_raw, ack_delay, num_blocks,
                         ack_block_len, lg_ack_in_block - ack_block_len,
                         shorten_ack_nr(lg_ack_in_block, ack_block_len));
                else
                    warn(INF,
                         FRAM_IN "ACK" NRM " lg=" FMT_PNR_OUT " delay=%" PRIu64
                                 " (%" PRIu64 " usec) ect0=%" PRIu64
                                 " ect1=%" PRIu64 " ce=%" PRIu64 " cnt=%" PRIu64
                                 " block=%" PRIu64 " [" FMT_PNR_OUT
                                 ".." FMT_PNR_OUT "]",
                         lg_ack, ack_delay_raw, ack_delay, ect0_cnt, ect1_cnt,
                         ce_cnt, num_blocks, ack_block_len,
                         lg_ack_in_block - ack_block_len,
                         shorten_ack_nr(lg_ack_in_block, ack_block_len));
            } else
                warn(INF,
                     FRAM_IN "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                             " [" FMT_PNR_OUT ".." FMT_PNR_OUT "]",
                     gap, ack_block_len, lg_ack_in_block - ack_block_len,
                     shorten_ack_nr(lg_ack_in_block, ack_block_len));
        }
#endif

        uint64_t ack = lg_ack_in_block;
        while (ack_block_len >= lg_ack_in_block - ack) {
            on_each_ack(c, pn, ack);
            if (likely(ack > 0))
                ack--;
            else
                break;
        }

        if (n > 1) {
            i = dec_chk(!parse_only, t, &gap, v->buf, v->len, i, 0, "%" PRIu64);
            // warn(ERR, "%" PRIu64 " %" PRIu64, ack, gap);
            if (unlikely(ack <= gap))
                err_close_return(c, ERR_FRAME_ENC, t, "ACK gap %" PRIu64, gap);
            lg_ack_in_block = ack - gap - 1;
        }
    }

    if (after_ack)
        after_ack(c, pn);
    return i;
}


static uint16_t __attribute__((nonnull))
dec_close_frame(struct q_conn * const c,
                const struct w_iov * const v,
                const uint16_t pos)
{
    // we need to decode the type byte, since this function handles two types
    uint8_t type = 0;
    uint16_t i =
        dec_chk(true, type, &type, v->buf, v->len, pos, sizeof(type), "0x%02x");

    uint16_t err_code = 0;
    i = dec_chk(true, type, &err_code, v->buf, v->len, i, sizeof(err_code),
                "0x%04x");

    uint64_t frame_type = 0;
    if (type == FRAM_TYPE_CONN_CLSE)
        i = dec_chk(true, type, &frame_type, v->buf, v->len, i, 0,
                    "0x%" PRIx64);

    uint64_t reas_len = 0;
    i = dec_chk(true, type, &reas_len, v->buf, v->len, i, 0, "%" PRIu64);
    if (unlikely(i == UINT16_MAX || reas_len + i > v->len))
        err_close_return(c, ERR_FRAME_ENC, type, "illegal reason len %u",
                         reas_len);

    char reas_phr[UINT16_MAX];
    if (reas_len)
        i = dec_chk_buf(true, type, &reas_phr, v->buf, v->len, i,
                        (uint16_t)reas_len);

#ifndef FUZZING
    if (type == FRAM_TYPE_CONN_CLSE)
        warn(INF,
             FRAM_IN "CONNECTION_CLOSE" NRM " err=%s0x%04x " NRM
                     "frame=0x%" PRIx64 " rlen=%" PRIu64 " reason=%s%.*s" NRM,
             err_code ? RED : NRM, err_code, frame_type, reas_len,
             err_code ? RED : NRM, reas_len, reas_phr);
    else
        warn(INF,
             FRAM_IN "APPLICATION_CLOSE" NRM " err=%s0x%04x " NRM
                     " rlen=%" PRIu64 " reason=%s%.*s" NRM,
             err_code ? RED : NRM, err_code, reas_len, err_code ? RED : NRM,
             reas_len, reas_phr);
#endif

    if (c->state != conn_drng) {
        conn_to_state(c, conn_drng);
        c->needs_tx = false;
        enter_closing(c);
    }

    return i;
}


static uint16_t __attribute__((nonnull))
dec_max_stream_data_frame(struct q_conn * const c,
                          const struct w_iov * const v,
                          const uint16_t pos)
{
    int64_t sid = 0;
    uint16_t i = dec_chk(true, FRAM_TYPE_MAX_STRM_DATA, &sid, v->buf, v->len,
                         pos + 1, 0, FMT_SID);

    struct q_stream * s = get_stream(c, sid);
    if (unlikely(s == 0))
        s = new_stream(c, sid);

    uint64_t max = 0;
    i = dec_chk(true, FRAM_TYPE_MAX_STRM_DATA, &max, v->buf, v->len, i, 0,
                "%" PRIu64);

#ifndef FUZZING
    warn(INF, FRAM_IN "MAX_STREAM_DATA" NRM " id=" FMT_SID " max=%" PRIu64, sid,
         max);
#endif

    if (max > s->out_data_max) {
        s->out_data_max = max;
        s->blocked = false;
        c->needs_tx = true;
    }
#ifndef FUZZING
    else
        warn(WRN, "MAX_STREAM_DATA %" PRIu64 " <= current value %" PRIu64, max,
             s->out_data_max);
#endif

    return i;
}


static uint16_t __attribute__((nonnull))
dec_max_stream_id_frame(struct q_conn * const c,
                        const struct w_iov * const v,
                        const uint16_t pos)
{
    int64_t max = 0;
    const uint16_t i = dec_chk(true, FRAM_TYPE_MAX_SID, &max, v->buf, v->len,
                               pos + 1, 0, "%" PRIu64);

    if (is_set(STRM_FL_INI_SRV, max) == c->is_clnt)
        err_close_return(c, ERR_FRAME_ENC, FRAM_TYPE_MAX_SID,
                         "illegal MAX_STREAM_ID for %s: %u", conn_type(c), max);

#ifndef FUZZING
    warn(INF, FRAM_IN "MAX_STREAM_ID" NRM " max=" FMT_SID " (%sdir)", max,
         is_set(STRM_FL_DIR_UNI, max) ? "uni" : "bi");
#endif

    int64_t * const which = is_set(STRM_FL_DIR_UNI, max)
                                ? &c->tp_out.max_uni_streams
                                : &c->tp_out.max_bidi_streams;

    max = (max >> 2) + 1;
    if (max > *which) {
        *which = max;
        maybe_api_return(q_rsv_stream, c, 0);
    }
#ifndef FUZZING
    else
        warn(WRN, "max_bidi_streams %" PRIu64 " <= current value %" PRIu64, max,
             *which);
#endif

    return i;
}


static uint16_t __attribute__((nonnull))
dec_max_data_frame(struct q_conn * const c,
                   const struct w_iov * const v,
                   const uint16_t pos)
{
    uint64_t max = 0;
    const uint16_t i = dec_chk(true, FRAM_TYPE_MAX_DATA, &max, v->buf, v->len,
                               pos + 1, 0, "%" PRIu64);

#ifndef FUZZING
    warn(INF, FRAM_IN "MAX_DATA" NRM " max=%" PRIu64, max);
#endif

    if (max > c->tp_out.max_data) {
        c->tp_out.max_data = max;
        c->blocked = false;
        c->needs_tx = true;
    }
#ifndef FUZZING
    else
        warn(WRN, "MAX_DATA %" PRIu64 " <= current value %" PRIu64, max,
             c->tp_out.max_data);
#endif

    return i;
}


static uint16_t __attribute__((nonnull))
dec_stream_blocked_frame(struct q_conn * const c,
                         const struct w_iov * const v,
                         const uint16_t pos)
{
    int64_t sid = 0;
    uint16_t i = dec_chk(true, FRAM_TYPE_STRM_BLCK, &sid, v->buf, v->len,
                         pos + 1, 0, FMT_SID);

    struct q_stream * const s = get_stream(c, sid);
    if (unlikely(s == 0))
        err_close_return(c, ERR_FRAME_ENC, FRAM_TYPE_STRM_BLCK,
                         "unknown strm %u", sid);

    uint64_t off = 0;
    i = dec_chk(true, FRAM_TYPE_STRM_BLCK, &off, v->buf, v->len, i, 0,
                "%" PRIu64);

#ifndef FUZZING
    warn(INF, FRAM_IN "STREAM_BLOCKED" NRM " id=" FMT_SID " off=%" PRIu64, sid,
         off);
#endif

    do_stream_fc(s);
    return i;
}


static uint16_t __attribute__((nonnull))
dec_blocked_frame(struct q_conn * const c,
                  const struct w_iov * const v,
                  const uint16_t pos)
{
    uint64_t off = 0;
    uint16_t i = dec_chk(true, FRAM_TYPE_BLCK, &off, v->buf, v->len, pos + 1, 0,
                         "%" PRIu64);

#ifndef FUZZING
    warn(INF, FRAM_IN "BLOCKED" NRM " off=%" PRIu64, off);
#endif

    do_conn_fc(c);
    return i;
}


static uint16_t __attribute__((nonnull))
dec_stream_id_blocked_frame(struct q_conn * const c,
                            const struct w_iov * const v,
                            const uint16_t pos)
{
    int64_t sid = 0;
    uint16_t i = dec_chk(true, FRAM_TYPE_SID_BLCK, &sid, v->buf, v->len,
                         pos + 1, 0, FMT_SID);

#ifndef FUZZING
    warn(INF, FRAM_IN "STREAM_ID_BLOCKED" NRM " sid=" FMT_SID, sid);
#endif

    if (is_set(STRM_FL_DIR_UNI, sid))
        err_close_return(c, ERR_INTERNAL, 0, "TODO: unidir strm");

    if (sid >> 2 <= c->tp_in.max_bidi_streams)
        // let the peer open more streams
        c->tp_in.max_bidi_streams += 2;
    c->needs_tx = c->tx_max_stream_id = true;

    return i;
}


static uint16_t __attribute__((nonnull))
dec_stop_sending_frame(struct q_conn * const c,
                       const struct w_iov * const v,
                       const uint16_t pos)
{
    int64_t sid = 0;
    uint16_t i = dec_chk(true, FRAM_TYPE_STOP_SEND, &sid, v->buf, v->len,
                         pos + 1, 0, FMT_SID);

    struct q_stream * const s = get_stream(c, sid);
    if (unlikely(s == 0))
        err_close_return(c, ERR_FRAME_ENC, FRAM_TYPE_STOP_SEND,
                         "unknown strm %u", sid);

    uint16_t err_code = 0;
    i = dec_chk(true, FRAM_TYPE_STOP_SEND, &err_code, v->buf, v->len, i,
                sizeof(err_code), "0x%04x");

#ifndef FUZZING
    warn(INF, FRAM_IN "STOP_SENDING" NRM " id=" FMT_SID " err=%s0x%04x" NRM,
         sid, err_code ? RED : NRM, err_code);
#endif

    return i;
}


static uint16_t __attribute__((nonnull))
dec_path_challenge_frame(struct q_conn * const c,
                         const struct w_iov * const v,
                         const uint16_t pos)
{
    uint16_t i =
        dec_chk(true, FRAM_TYPE_PATH_CHLG, &c->path_chlg_in, v->buf, v->len,
                pos + 1, sizeof(c->path_chlg_in), "0x%" PRIx64);

#ifndef FUZZING
    warn(INF, FRAM_IN "PATH_CHALLENGE" NRM " data=%" PRIx64, c->path_chlg_in);
#endif

    c->path_resp_out = c->path_chlg_in;
    c->needs_tx = c->tx_path_resp = true;

    return i;
}


static uint16_t __attribute__((nonnull))
dec_path_response_frame(struct q_conn * const c,
                        const struct w_iov * const v,
                        const uint16_t pos)
{
    uint16_t i =
        dec_chk(true, FRAM_TYPE_PATH_RESP, &c->path_resp_in, v->buf, v->len,
                pos + 1, sizeof(c->path_resp_in), "0x%" PRIx64);

#ifndef FUZZING
    warn(INF, FRAM_IN "PATH_RESPONSE" NRM " data=%" PRIx64, c->path_resp_in);
#endif

    if (c->path_resp_in == c->path_chlg_out)
        c->tx_path_chlg = false;

    return i;
}


static uint16_t __attribute__((nonnull))
dec_new_cid_frame(struct q_conn * const c,
                  const struct w_iov * const v,
                  const uint16_t pos)
{
    uint64_t seq = 0;
    uint16_t i = dec_chk(true, FRAM_TYPE_NEW_CID, &seq, v->buf, v->len, pos + 1,
                         0, "%" PRIu64);

    struct cid dcid;
    i = dec_chk(true, FRAM_TYPE_NEW_CID, &dcid.len, v->buf, v->len, i,
                sizeof(dcid.len), "%u");

    if (unlikely(dcid.len < 4 || dcid.len > 18))
        err_close_return(c, ERR_FRAME_ENC, FRAM_TYPE_NEW_CID,
                         "illegal cid len %u", dcid.len);

    i = dec_chk_buf(true, FRAM_TYPE_NEW_CID, dcid.id, v->buf, v->len, i,
                    dcid.len);
    i = dec_chk_buf(true, FRAM_TYPE_NEW_CID, dcid.srt, v->buf, v->len, i,
                    sizeof(dcid.srt));

#ifndef FUZZING
    warn(INF,
         FRAM_IN "NEW_CONNECTION_ID" NRM " seq=%" PRIu64
                 " len=%u dcid=%s tok=%s",
         seq, dcid.len, cid2str(&dcid), hex2str(dcid.srt, sizeof(dcid.srt)));
#endif

    if (c->max_cid_seq_in == UINT64_MAX || seq > c->max_cid_seq_in) {
        add_dcid(c, &dcid);
        c->max_cid_seq_in = seq;
    }
#ifndef FUZZING
    else
        warn(WRN, "highest seq seen %" PRIu64 " <= %" PRIu64 ", ignoring",
             c->max_cid_seq_in, seq);
#endif

    return i;
}


static uint16_t __attribute__((nonnull))
dec_rst_stream_frame(struct q_conn * const c,
                     const struct w_iov * const v,
                     const uint16_t pos)
{
    uint64_t sid = 0;
    uint16_t i = dec_chk(true, FRAM_TYPE_RST_STRM, &sid, v->buf, v->len,
                         pos + 1, 0, FMT_SID);

    uint16_t err = 0;
    i = dec_chk(true, FRAM_TYPE_RST_STRM, &err, v->buf, v->len, i, sizeof(err),
                "0x%04x");

    uint64_t off = 0;
    i = dec_chk(true, FRAM_TYPE_RST_STRM, &off, v->buf, v->len, i, 0,
                "%" PRIu64);

#ifndef FUZZING
    warn(INF,
         FRAM_IN "RST_STREAM" NRM " sid=" FMT_SID " err=%s0x%04x" NRM
                 " off=%" PRIu64,
         sid, err ? RED : NRM, err, off);
#endif

    // TODO: actually do something with this

    return i;
}


static uint16_t __attribute__((nonnull))
dec_new_token_frame(struct q_conn * const c,
                    const struct w_iov * const v,
                    const uint16_t pos)
{
    uint64_t tok_len = 0;
    uint16_t i = dec_chk(true, FRAM_TYPE_NEW_TOKN, &tok_len, v->buf, v->len,
                         pos + 1, 0, "%" PRIu64);

    if (unlikely(tok_len > (uint64_t)(v->len - i)))
        err_close_return(c, ERR_FRAME_ENC, FRAM_TYPE_NEW_TOKN,
                         "illegal tok len");

    // TODO: actually do something with the token
    uint8_t tok[4096];
    ensure(tok_len < sizeof(tok), "tok_len %" PRIu64 " > %u", tok_len,
           sizeof(tok));
    i = dec_chk_buf(true, FRAM_TYPE_NEW_TOKN, tok, v->buf, v->len, i,
                    (uint16_t)tok_len);

#ifndef FUZZING
    warn(INF, FRAM_IN "NEW_TOKEN" NRM " len=%" PRIu64 " tok=%s", tok_len,
         hex2str(tok, tok_len));
#endif

    // TODO: actually do something with this

    return i;
}


uint16_t dec_frames(struct q_conn * const c, struct w_iov * v)
{
    uint16_t i = meta(v).hdr.hdr_len;
    uint16_t pad_start = 0;

#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
    // when called from the fuzzer, v->ip is zero
    if (v->ip)
        write_to_corpus(corpus_frm_dir, &v->buf[i], v->len - i);
#endif

    while (i < v->len) {
        uint8_t type = 0;
        dec_chk(true, type, &type, v->buf, v->len, i, sizeof(type), "0x%02x");

        if (pad_start && (type != FRAM_TYPE_PAD || i == v->len - 1)) {
#ifndef FUZZING
            warn(INF, FRAM_IN "PADDING" NRM " len=%u", i - pad_start);
#endif
            pad_start = 0;
        }

        if (type == FRAM_TYPE_CRPT ||
            (type >= FRAM_TYPE_STRM && type <= FRAM_TYPE_STRM_MAX)) {
            // we only encode FRAM_TYPE_STRM in the frames bitstr_t
            bit_set(meta(v).frames,
                    type == FRAM_TYPE_CRPT ? FRAM_TYPE_CRPT : FRAM_TYPE_STRM);
            if (meta(v).stream_data_start && meta(v).stream) {
                // already had at least one stream frame in this packet
                // with non-duplicate data, so generate (another) copy
#ifndef FUZZING
                warn(DBG, "addtl stream or crypto frame at pos %u, copy", i);
#endif
                struct w_iov * const vdup = w_iov_dup(v);
                pm_cpy(&meta(vdup), &meta(v));
                // adjust w_iov start and len to stream frame data
                v->buf = &v->buf[meta(v).stream_data_start];
                v->len = stream_data_len(v);
                // continue parsing in the copied w_iov
                v = vdup;
            }

            // this is the first stream frame in this packet
            i = dec_stream_or_crypto_frame(c, v, i);
        } else {
            switch (type) {
            case FRAM_TYPE_ACK:
            case FRAM_TYPE_ACK_ECN:
                i = dec_ack_frame(c, v, i, &on_ack_rx_1, &on_pkt_acked,
                                  on_ack_rx_2, false);
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
#ifndef FUZZING
                warn(INF, FRAM_IN "PING" NRM);
#endif
                // PING frames need to be ACK'ed
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

            case FRAM_TYPE_SID_BLCK:
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

            case FRAM_TYPE_NEW_TOKN:
                i = dec_new_token_frame(c, v, i);
                break;

            default:
                err_close(c, ERR_FRAME_ENC, type,
                          "unknown frame type 0x%02x at pos %u", type, i);
                i = UINT16_MAX;
            }
        }

        if (unlikely(i == UINT16_MAX))
            // there was an error parsing a frame
            return UINT16_MAX;

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
    memset(&v->buf[pos], FRAM_TYPE_PAD, len);
    bit_set(meta(v).frames, FRAM_TYPE_PAD);
    return pos + len;
}


uint16_t enc_ack_frame(struct q_conn * const c,
                       struct pn_space * const pn,
                       struct w_iov * const v,
                       const uint16_t pos)
{
    const bool enc_ecn = c->rec.ect0_cnt || c->rec.ect1_cnt || c->rec.ce_cnt;
    const uint8_t type = enc_ecn ? FRAM_TYPE_ACK_ECN : FRAM_TYPE_ACK;
    bit_set(meta(v).frames, FRAM_TYPE_ACK);
    meta(v).ack_header_pos = pos;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");

    struct ival * b = diet_max_ival(&pn->recv);
    ensure(b, "nothing to ACK");
    const uint64_t lg_recv = b->hi;
    i = enc(v->buf, v->len, i, &lg_recv, 0, 0, FMT_PNR_IN);

    // handshake pkts always use an ACK delay exponent of 3
    const uint8_t ade =
        meta(v).hdr.type <= F_LH_INIT && meta(v).hdr.type >= F_LH_HSHK
            ? 3
            : c->tp_out.ack_del_exp;
    const uint64_t ack_delay =
        (uint64_t)((ev_now(loop) - diet_timestamp(b)) * 1000000) / (1 << ade);
    i = enc(v->buf, v->len, i, &ack_delay, 0, 0, "%" PRIu64);

    if (enc_ecn) {
        // encode ECN
        i = enc(v->buf, v->len, i, &c->rec.ect0_cnt, 0, 0, "%" PRIu64);
        i = enc(v->buf, v->len, i, &c->rec.ect1_cnt, 0, 0, "%" PRIu64);
        i = enc(v->buf, v->len, i, &c->rec.ce_cnt, 0, 0, "%" PRIu64);
    }

    const uint64_t block_cnt = diet_cnt(&pn->recv) - 1;
    i = enc(v->buf, v->len, i, &block_cnt, 0, 0, "%" PRIu64);

    uint64_t prev_lo = 0;
    splay_foreach_rev (b, diet, &pn->recv) {
        uint64_t gap = 0;
        if (prev_lo) {
            gap = prev_lo - b->hi - 2;
            i = enc(v->buf, v->len, i, &gap, 0, 0, "%" PRIu64);
        }
        const uint64_t ack_block = b->hi - b->lo;

        if (ack_block) {
            if (prev_lo)
                warn(INF,
                     FRAM_OUT "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                              " [" FMT_PNR_IN ".." FMT_PNR_IN "]",
                     gap, ack_block, b->lo, shorten_ack_nr(b->hi, ack_block));
            else {
                if (enc_ecn)
                    warn(INF,
                         FRAM_OUT
                         "ACK_ECN" NRM " lg=" FMT_PNR_IN " delay=%" PRIu64
                         " (%" PRIu64 " usec) ect0=%" PRIu64 " ect1=%" PRIu64
                         " ce=%" PRIu64 " cnt=%" PRIu64 " block=%" PRIu64
                         " [" FMT_PNR_IN ".." FMT_PNR_IN "]",
                         lg_recv, ack_delay, ack_delay * (1 << ade),
                         c->rec.ect0_cnt, c->rec.ect1_cnt, c->rec.ce_cnt,
                         block_cnt, ack_block, b->lo,
                         shorten_ack_nr(b->hi, ack_block));
                else
                    warn(INF,
                         FRAM_OUT "ACK" NRM " lg=" FMT_PNR_IN " delay=%" PRIu64
                                  " (%" PRIu64 " usec) cnt=%" PRIu64
                                  " block=%" PRIu64 " [" FMT_PNR_IN
                                  ".." FMT_PNR_IN "]",
                         lg_recv, ack_delay, ack_delay * (1 << ade), block_cnt,
                         ack_block, b->lo, shorten_ack_nr(b->hi, ack_block));
            }
        } else {
            if (prev_lo)
                warn(INF,
                     FRAM_OUT "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                              " [" FMT_PNR_IN "]",
                     gap, ack_block, b->hi);
            else {
                if (enc_ecn)
                    warn(INF,
                         FRAM_OUT
                         "ACK_ECN" NRM " lg=" FMT_PNR_IN " delay=%" PRIu64
                         " (%" PRIu64 " usec) ect0=%" PRIu64 " ect1=%" PRIu64
                         " ce=%" PRIu64 " cnt=%" PRIu64 " block=%" PRIu64,
                         lg_recv, ack_delay, ack_delay * (1 << ade),
                         c->rec.ect0_cnt, c->rec.ect1_cnt, c->rec.ce_cnt,
                         block_cnt, ack_block);
                else
                    warn(INF,
                         FRAM_OUT "ACK" NRM " lg=" FMT_PNR_IN " delay=%" PRIu64
                                  " (%" PRIu64 " usec) cnt=%" PRIu64
                                  " block=%" PRIu64 " [" FMT_PNR_IN "]",
                         lg_recv, ack_delay, ack_delay * (1 << ade), block_cnt,
                         ack_block, lg_recv);
            }
        }
        i = enc(v->buf, v->len, i, &ack_block, 0, 0, "%" PRIu64);
        prev_lo = b->lo;
    }
    return i;
}


uint16_t enc_stream_or_crypto_frame(struct q_stream * const s,
                                    struct w_iov * const v,
                                    const uint16_t pos,
                                    const bool enc_strm)
{
    const uint64_t dlen = v->len - Q_OFFSET;
    uint8_t type;

    if (enc_strm) {
        ensure(!is_set(F_LONG_HDR, meta(v).hdr.flags) ||
                   meta(v).hdr.type == F_LH_0RTT,
               "sid %u in 0x%02x-type pkt", s->id, meta(v).hdr.type);

        ensure(dlen || s->state > strm_open,
               "no stream data or need to send FIN");

        type = FRAM_TYPE_STRM | (dlen ? F_STREAM_LEN : 0) |
               (s->out_data ? F_STREAM_OFF : 0);

        // if stream is closed locally and this is the last packet, include a
        // FIN
        if ((s->state == strm_hclo || s->state == strm_clsd) &&
            v == sq_last(&s->out, w_iov, next)) {
            type |= F_STREAM_FIN;
            s->tx_fin = false;
        }
    } else
        type = FRAM_TYPE_CRPT;

    bit_set(meta(v).frames, type);

    // now that we know how long the stream frame header is, encode it
    uint16_t i = meta(v).stream_header_pos =
        Q_OFFSET - 1 - (enc_strm ? varint_size_needed((uint64_t)s->id) : 0) -
        (dlen || !enc_strm ? varint_size_needed(dlen) : 0) -
        (s->out_data || !enc_strm ? varint_size_needed(s->out_data) : 0);
    ensure(i > pos, "Q_OFFSET exhausted (%u > %u)", i, pos);
    i = enc(v->buf, v->len, i, &type, sizeof(type), 0, "0x%02x");
    if (enc_strm)
        i = enc(v->buf, v->len, i, &s->id, 0, 0, FMT_SID);
    if (s->out_data || !enc_strm)
        i = enc(v->buf, v->len, i, &s->out_data, 0, 0, "%" PRIu64);
    if (dlen || !enc_strm)
        enc(v->buf, v->len, i, &dlen, 0, 0, "%u");

    meta(v).stream = s; // remember stream this buf belongs to
    meta(v).stream_data_start = Q_OFFSET;
    meta(v).stream_data_end = Q_OFFSET + (uint16_t)dlen;
    meta(v).stream_off = s->out_data;

    log_stream_or_crypto_frame(false, v, false, "");
    track_bytes_out(s, dlen);
    ensure(!enc_strm || s->out_data < s->out_data_max, "exceeded fc window");

    return v->len;
}


uint16_t enc_close_frame(struct w_iov * const v,
                         const uint16_t pos,
                         const uint8_t type,
                         const uint16_t err_code,
                         const uint8_t err_frm,
                         const char * const reas)
{
    bit_set(meta(v).frames, type);

    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &err_code, sizeof(err_code), 0, "0x%04x");
    if (type == FRAM_TYPE_CONN_CLSE)
        i = enc(v->buf, v->len, i, &err_frm, sizeof(err_frm), 0, "0x%02x");

    const uint64_t rlen = reas ? MIN(strlen(reas), v->len - i) : 0;
    i = enc(v->buf, v->len, i, &rlen, 0, 0, "%" PRIu64);
    if (rlen)
        i = enc_buf(v->buf, v->len, i, reas, (uint16_t)rlen);

    if (type == FRAM_TYPE_CONN_CLSE)
        warn(INF,
             FRAM_OUT "CONNECTION_CLOSE" NRM " err=%s0x%04x" NRM
                      " frame=0x%02x rlen=%" PRIu64 " reason=%s%.*s" NRM,
             err_code ? RED : NRM, err_code, err_frm, reas ? rlen : 0,
             err_code ? RED : NRM, reas ? rlen : 0, reas);
    else
        warn(INF,
             FRAM_OUT "APPLICATION_CLOSE" NRM " err=%s0x%04x" NRM
                      " rlen=%" PRIu64 " reason=%s%.*s" NRM,
             err_code ? RED : NRM, err_code, reas ? rlen : 0,
             err_code ? RED : NRM, reas ? rlen : 0, reas);


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
    i = enc(v->buf, v->len, i, &s->new_in_data_max, 0, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "MAX_STREAM_DATA" NRM " id=" FMT_SID " max=%" PRIu64,
         s->id, s->new_in_data_max);

    // update the stream
    s->in_data_max = s->new_in_data_max;

    return i;
}


uint16_t enc_max_data_frame(struct q_conn * const c,
                            struct w_iov * const v,
                            const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_MAX_DATA);

    const uint8_t type = FRAM_TYPE_MAX_DATA;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    i = enc(v->buf, v->len, i, &c->tp_in.new_max_data, 0, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "MAX_DATA" NRM " max=%" PRIu64, c->tp_in.new_max_data);

    // update connection
    c->tp_in.max_data = c->tp_in.new_max_data;

    return i;
}


uint16_t enc_max_stream_id_frame(struct q_conn * const c,
                                 struct w_iov * const v,
                                 const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_MAX_SID);

    const uint8_t type = FRAM_TYPE_MAX_SID;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");

    const int64_t mbs = ((c->tp_in.new_max_bidi_streams - 1) << 2) +
                        (c->is_clnt ? STRM_FL_INI_SRV : 0);
    i = enc(v->buf, v->len, i, &mbs, 0, 0, "%" PRId64);

    warn(INF, FRAM_OUT "MAX_STREAM_ID" NRM " max=" FMT_SID, mbs);

    c->tp_in.max_bidi_streams = c->tp_in.new_max_bidi_streams;

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
    i = enc(v->buf, v->len, i, &s->out_data, 0, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "STREAM_BLOCKED" NRM " id=" FMT_SID " off=%" PRIu64,
         s->id, s->out_data);

    return i;
}


uint16_t enc_blocked_frame(struct q_conn * const c,
                           const struct w_iov * const v,
                           const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_BLCK);

    const uint8_t type = FRAM_TYPE_BLCK;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");
    const uint64_t off = c->tp_out.max_data + v->len - Q_OFFSET;
    i = enc(v->buf, v->len, i, &off, 0, 0, "%" PRIu64);

    warn(INF, FRAM_OUT "BLOCKED" NRM " off=%" PRIu64, off);

    return i;
}


uint16_t enc_stream_id_blocked_frame(struct q_conn * const c,
                                     const struct w_iov * const v,
                                     const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_SID_BLCK);

    const uint8_t type = FRAM_TYPE_SID_BLCK;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");

    // TODO handle unidir
    const int64_t mbs = ((c->tp_out.max_bidi_streams - 1) << 2) +
                        (!c->is_clnt ? STRM_FL_INI_SRV : 0);
    i = enc(v->buf, v->len, i, &mbs, 0, 0, "%" PRId64);

    warn(INF, FRAM_OUT "STREAM_ID_BLOCKED" NRM " sid=" FMT_SID, mbs);

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


uint16_t enc_new_cid_frame(struct q_conn * const c,
                           const struct w_iov * const v,
                           const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_NEW_CID);

    const uint8_t type = FRAM_TYPE_NEW_CID;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");

    c->max_cid_seq_out =
        c->max_cid_seq_out == UINT64_MAX ? 0 : c->max_cid_seq_out + 1;
    i = enc(v->buf, v->len, i, &c->max_cid_seq_out, 0, 0, "%" PRIu64);

    struct cid ncid = {.len = c->is_clnt ? CLNT_SCID_LEN : SERV_SCID_LEN};
    arc4random_buf(ncid.id, ncid.len);
    arc4random_buf(ncid.srt, sizeof(ncid.srt));
    add_scid(c, &ncid);

    i = enc(v->buf, v->len, i, &ncid.len, sizeof(ncid.len), 0, "%u");
    i = enc_buf(v->buf, v->len, i, ncid.id, ncid.len);
    i = enc_buf(v->buf, v->len, i, &ncid.srt, sizeof(ncid.srt));

    warn(INF,
         FRAM_OUT "NEW_CONNECTION_ID" NRM " seq=%" PRIx64
                  " len=%u cid=%s tok=%s",
         c->max_cid_seq_out, ncid.len, cid2str(&ncid),
         hex2str(ncid.srt, sizeof(ncid.srt)));

    c->tx_ncid = false;

    return i;
}


uint16_t enc_new_token_frame(struct q_conn * const c,
                             const struct w_iov * const v,
                             const uint16_t pos)
{
    bit_set(meta(v).frames, FRAM_TYPE_NEW_TOKN);

    const uint8_t type = FRAM_TYPE_NEW_TOKN;
    uint16_t i = enc(v->buf, v->len, pos, &type, sizeof(type), 0, "0x%02x");

    const uint64_t tok_len = c->tok_len;
    i = enc(v->buf, v->len, i, &tok_len, 0, 0, "%" PRIu64);
    i = enc_buf(v->buf, v->len, i, c->tok, c->tok_len);

    warn(INF, FRAM_OUT "NEW_TOKEN" NRM " len=%u tok=%s", c->tok_len,
         hex2str(c->tok, c->tok_len));

    return i;
}
