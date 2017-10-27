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

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>

#ifdef __linux__
#include <byteswap.h>
#endif

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
#include "tls.h"


#define FRAM_TYPE_PAD 0x00
#define FRAM_TYPE_CNCL 0x02
#define FRAM_TYPE_MAX_DATA 0x04
#define FRAM_TYPE_MAX_STRM_DATA 0x05
#define FRAM_TYPE_PING 0x07
#define FRAM_TYPE_STRM_BLCK 0x09
#define FRAM_TYPE_STRM 0xC0
#define FRAM_TYPE_ACK 0xA0


// Convert stream ID length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_sid_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x18) >> 3;
    ensure(l <= 3, "cannot decode stream ID length %u", l);
    const uint8_t dec[] = {1, 2, 3, 4};
    return dec[l];
}


// Convert stream offset length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_off_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x06) >> 1;
    ensure(l <= 3, "cannot decode stream offset length %u", l);
    const uint8_t dec[] = {0, 2, 4, 8};
    return dec[l];
}


#define F_STREAM_FIN 0x20
#define F_STREAM_DATA_LEN 0x01


static uint16_t __attribute__((nonnull))
dec_stream_frame(struct q_conn * const c,
                 struct w_iov * const v,
                 const uint16_t pos,
                 uint16_t * const len)
{
    uint16_t i = pos;

    uint8_t type = 0;
    dec(type, v->buf, v->len, i, 0, "0x%02x");

    uint32_t sid = 0;
    const uint8_t sid_len = dec_sid_len(type);
    dec(sid, v->buf, v->len, i, sid_len, "%u");

    const uint8_t off_len = dec_off_len(type);
    uint64_t off = 0;
    if (off_len)
        dec(off, v->buf, v->len, i, off_len, "%" PRIu64);
    // TODO: pay attention to offset when delivering data to app

    if (is_set(F_STREAM_DATA_LEN, type))
        dec(*len, v->buf, v->len, i, 0, "%u");
    else
        // stream data extends to end of packet
        *len = v->len - i;

    ensure(*len || is_set(F_STREAM_FIN, type), "len %u > 0 or FIN", *len);

    // deliver data into stream
    struct q_stream * s = get_stream(c, sid);
    if (s == 0) {
        if (diet_find(&c->closed_streams, sid)) {
            warn(WRN, "ignoring frame for closed str %u on %s conn %" PRIx64,
                 sid, conn_type(c), c->id);
            return i;
        }
        s = new_stream(c, sid);
    }

    // best case: new in-order data
    if (off == s->in_off) {
        warn(NTE,
             "%u byte%s new data (off %" PRIu64 "-%" PRIu64
             ") on %s conn %" PRIx64 " str %u",
             *len, plural(*len), off, off + *len, conn_type(c), c->id, sid);
        s->in_off += *len;
        sq_insert_tail(&s->in, v, next);

        // check if a hole has been filled that lets us dequeue ooo data
        struct pkt_meta *p, *nxt;
        for (p = splay_min(pm_off_splay, &s->in_ooo);
             p && p->in_off == s->in_off; p = nxt) {
            nxt = splay_next(pm_off_splay, &s->in_ooo, p);
            const uint16_t sdl = p->stream_data_end;

            warn(NTE,
                 "deliver %u ooo byte%s (off %" PRIu64 "-%" PRIu64
                 ") on %s conn %" PRIx64 " str %u",
                 sdl, plural(sdl), p->in_off, p->in_off + sdl, conn_type(c),
                 c->id, sid);

            sq_insert_tail(&s->in, w_iov(w_engine(c->sock), w_iov_idx(p)),
                           next);
            splay_remove(pm_off_splay, &s->in_ooo, p);
            s->in_off += sdl;
        }


        if (is_set(F_STREAM_FIN, type)) {
#ifndef NDEBUG
            const uint8_t old_state = s->state;
#endif
            s->state =
                s->state <= STRM_STAT_OPEN ? STRM_STAT_HCRM : STRM_STAT_CLSD;
            warn(NTE,
                 "received FIN on %s conn %" PRIx64 " str %u, state %u -> %u",
                 conn_type(c), c->id, s->id, old_state, s->state);
            if (s->id != 0 && splay_empty(&s->in_ooo))
                maybe_api_return(q_readall_str, s);
        }

        if (s->id != 0)
            maybe_api_return(q_read, s->c);
        else {
            // adjust w_iov start and len to stream frame data for TLS handshake
            uint8_t * const b = v->buf;
            const uint16_t l = v->len;
            v->buf = &v->buf[i];
            v->len = *len;
            if (tls_handshake(s) == 0)
                maybe_api_return(q_connect, c);
            // undo adjust
            v->buf = b;
            v->len = l;
        }
        c->needs_tx = true;
        return i;
    }

    // data is a complete duplicate
    if (off + *len <= s->in_off) {
        warn(NTE,
             "%u byte%s dup data (off %" PRIu64 "-%" PRIu64
             ") on %s conn %" PRIx64 " str %u",
             *len, plural(*len), off, off + *len, conn_type(c), c->id, sid);
        q_free_iov(c, v);
        c->needs_tx = true;
        return i;
    }

    // data is out of order
    warn(NTE,
         "reordered data: %u byte%s data (off %" PRIu64 "-%" PRIu64
         "), expected %" PRIu64 " on %s conn %" PRIx64 " str %u",
         *len, plural(*len), off, off + *len, s->in_off, conn_type(c), c->id,
         sid);
    meta(v).in_off = off;
    meta(v).stream_data_end = *len;
    splay_insert(pm_off_splay, &s->in_ooo, &meta(v));
    return i;
}


// Convert largest ACK length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_lg_ack_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x0C) >> 2;
    ensure(l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 4, 8};
    return dec[l];
}


// Convert length of ACK block length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_len_ack_block_len(const uint8_t flags)
{
    const uint8_t l = flags & 0x03;
    ensure(l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 4, 8};
    return dec[l];
}


#define F_ACK_N 0x10

uint16_t dec_ack_frame(
    struct q_conn * const c,
    const struct w_iov * const v,
    const uint16_t pos,
    void (*before_ack)(struct q_conn * const, const uint64_t, const uint16_t),
    void (*on_each_ack)(struct q_conn * const, const uint64_t),
    void (*after_ack)(struct q_conn * const))
{
    uint16_t i = pos;
    uint8_t type = 0;
    dec(type, v->buf, v->len, i, 0, "0x%02x");

    uint16_t num_blocks = 0;
    if (is_set(F_ACK_N, type))
        dec(num_blocks, v->buf, v->len, i, sizeof(uint8_t), "%u");
    num_blocks++;

    uint8_t num_ts = 0;
    dec(num_ts, v->buf, v->len, i, 0, "%u");

    const uint8_t lg_ack_len = dec_lg_ack_len(type);
    uint64_t lg_ack = 0;
    dec(lg_ack, v->buf, v->len, i, lg_ack_len, "%" PRIu64);

    uint16_t ack_delay = 0;
    dec(ack_delay, v->buf, v->len, i, 0, "%u");

    const uint8_t len_ack_block_len = dec_len_ack_block_len(type);

    uint64_t lg_ack_in_block = lg_ack;
    if (before_ack)
        before_ack(c, lg_ack_in_block, ack_delay);
    do {
        // warn(CRT, "num_blocks %u", num_blocks);
        uint64_t ack_block_len = 0;
        dec(ack_block_len, v->buf, v->len, i, len_ack_block_len, "%" PRIu64);
        if (lg_ack_in_block == lg_ack)
            // this is the first ACK block
            ack_block_len++;

        uint64_t ack = lg_ack_in_block;
        while (ack > lg_ack_in_block - ack_block_len) {
            // const bool is_lg_ack = (ack == lg_ack);
            // const bool is_sm_ack =
            //     (num_blocks == 1 && ack == lg_ack_in_block - ack_block_len +
            //     1);
            // warn(CRT, "ack %" PRIu64 " is_lg_ack %u is_sm_ack %u", ack,
            //      is_lg_ack, is_sm_ack);
            on_each_ack(c, ack); //, ack_delay, is_lg_ack, is_sm_ack);
            ack--;
        }

        if (num_blocks > 1) {
            uint8_t gap = 0;
            dec(gap, v->buf, v->len, i, 0, "%u");
            lg_ack_in_block = ack - gap;
        }
        num_blocks--;
    } while (num_blocks);

    for (uint8_t b = 0; b < num_ts; b++) {
        warn(DBG, "decoding timestamp block #%u", b);
        uint8_t delta_lg_obs = 0;
        dec(delta_lg_obs, v->buf, v->len, i, 0, "%u");
        uint32_t ts = 0;
        dec(ts, v->buf, v->len, i, b == 0 ? 4 : 2, "%u");
    }

    if (after_ack)
        after_ack(c);
    return i;
}


static uint16_t __attribute__((nonnull))
dec_conn_close_frame(struct q_conn * const c,
                     const struct w_iov * const v,
                     const uint16_t pos)
{
    uint16_t i = pos + 1;

    uint32_t err_code = 0;
    dec(err_code, v->buf, v->len, i, 0, "0x%08x");

    uint16_t reas_len = 0;
    dec(reas_len, v->buf, v->len, i, 0, "%u");
    ensure(reas_len <= v->len - i, "reason_len invalid");

    if (reas_len) {
        char reas_phr[UINT16_MAX];
        memcpy(reas_phr, &v->buf[i], reas_len);
        i += reas_len;
        warn(NTE, "%u-byte conn close reason: %.*s", reas_len, reas_len,
             reas_phr);
    }

    // maybe_api_return(q_read, c);

    c->needs_tx = true;
    return i;
}


static uint16_t __attribute__((nonnull))
dec_max_stream_data_frame(struct q_conn * const c,
                          const struct w_iov * const v,
                          const uint16_t pos)
{
    uint16_t i = pos + 1;

    uint32_t sid = 0;
    dec(sid, v->buf, v->len, i, 0, "%u");
    struct q_stream * const s = get_stream(c, sid);
    ensure(s, "have stream %u", sid);
    dec(s->max_stream_data, v->buf, v->len, i, 0, "%" PRIu64);

    return i;
}


static uint16_t __attribute__((nonnull))
dec_max_data_frame(struct q_conn * const c,
                   const struct w_iov * const v,
                   const uint16_t pos)
{
    uint16_t i = pos + 1;
    dec(c->max_data, v->buf, v->len, i, 0, "%" PRIu64);
    return i;
}


static uint16_t __attribute__((nonnull))
dec_stream_blocked(struct q_conn * const c,
                   const struct w_iov * const v,
                   const uint16_t pos)
{
    uint16_t i = pos + 1;

    uint32_t sid = 0;
    dec(sid, v->buf, v->len, i, 0, "%u");
    struct q_stream * const s = get_stream(c, sid);
    ensure(s, "have stream %u", sid);

    // TODO: handle this

    return i;
}


void dec_frames(struct q_conn * const c, struct w_iov * v)
{
    uint16_t i = pkt_hdr_len(v->buf, v->len);
    uint16_t pad_start = 0;
    uint16_t dpos = 0;
    uint16_t dlen = 0;

    while (i < v->len) {
        const uint8_t type = ((const uint8_t * const)(v->buf))[i];
        if (pad_start && (type != FRAM_TYPE_PAD || i == v->len - 1)) {
            warn(DBG, "skipped padding in [%u..%u]", pad_start, i);
            pad_start = 0;
        }

        if (is_set(FRAM_TYPE_STRM, type)) {
            if (dpos) {
                // already had at least one stream frame in this packet,
                // generate (another) copy
                warn(INF, "more than one stream frame in pkt, copy");
                struct w_iov * const vdup =
                    w_alloc_iov(w_engine(c->sock), MAX_PKT_LEN, Q_OFFSET);
                memcpy(vdup->buf, v->buf, v->len);
                meta(vdup) = meta(v);
                vdup->len = v->len;
                // adjust w_iov start and len to stream frame data
                v->buf = &v->buf[dpos];
                v->len = dlen;
                // continue parsing in the copied w_iov
                v = vdup;
            }

            // this is the first stream frame in this packet
            dpos = dec_stream_frame(c, v, i, &dlen);
            i = dpos + dlen;

        } else if (is_set(FRAM_TYPE_ACK, type)) {
            i = dec_ack_frame(c, v, i, &on_ack_rx_1, &on_pkt_acked,
                              on_ack_rx_2);

        } else
            switch (type) {
            case FRAM_TYPE_PAD:
                pad_start = pad_start ? pad_start : i;
                i++;
                break;

            case FRAM_TYPE_CNCL:
                i = dec_conn_close_frame(c, v, i);
                break;

            case FRAM_TYPE_PING:
                warn(INF, "ping frame in [%u]", i);
                i++;
                c->needs_tx = true;
                break;

            case FRAM_TYPE_MAX_STRM_DATA:
                i = dec_max_stream_data_frame(c, v, i);
                break;

            case FRAM_TYPE_MAX_DATA:
                i = dec_max_data_frame(c, v, i);
                break;

            case FRAM_TYPE_STRM_BLCK:
                i = dec_stream_blocked(c, v, i);
                break;

            default:
                die("unknown frame type 0x%02x", type);
            }
    }

    if (dpos) {
        // adjust w_iov start and len to stream frame data
        v->buf = &v->buf[dpos];
        v->len = dlen;
    }
}


uint16_t enc_padding_frame(struct w_iov * const v,
                           const uint16_t pos,
                           const uint16_t len)
{
    warn(DBG, "encoding padding frame into [%u..%u]", pos, pos + len - 1);
    memset(&v->buf[pos], FRAM_TYPE_PAD, len);
    meta(v).is_rtxable = true;
    return len;
}


static const uint8_t enc_lg_ack_len[] = {0xFF,      0x00, 0x01 << 2, 0xFF,
                                         0x02 << 2, 0xFF, 0xFF,      0xFF,
                                         0x03 << 2}; // 0xFF = invalid


static uint8_t __attribute__((const)) needed_lg_ack_len(const uint64_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    if (n < UINT32_MAX)
        return 4;
    return 8;
}


static const uint8_t enc_ack_block_len[] = {
    0xFF, 0x00, 0x01, 0xFF, 0x02, 0xFF, 0xFF, 0xFF, 0x03}; // 0xFF = invalid


static uint8_t __attribute__((nonnull))
needed_ack_block_len(struct q_conn * const c)
{
    const uint64_t max_block = diet_max(&c->recv) - diet_max(&c->recv);
    if (max_block < UINT8_MAX)
        return 1;
    if (max_block < UINT16_MAX)
        return 2;
    if (max_block < UINT32_MAX)
        return 4;
    return 8;
}


uint16_t enc_ack_frame(struct q_conn * const c,
                       struct w_iov * const v,
                       const uint16_t pos)
{
    uint8_t type = FRAM_TYPE_ACK;

    uint8_t num_blocks = (uint8_t)MIN(c->recv.cnt, UINT8_MAX);
    if (num_blocks > 1) {
        num_blocks--;
        type |= F_ACK_N;
    }

    const uint64_t lg_recv = diet_max(&c->recv);
    const uint8_t lg_ack_len = needed_lg_ack_len(lg_recv);
    type |= enc_lg_ack_len[lg_ack_len];
    const uint8_t ack_block_len = needed_ack_block_len(c);
    type |= enc_ack_block_len[ack_block_len];

    uint16_t i = pos;
    enc(v->buf, v->len, i, &type, 0, "0x%02x");

    if (is_set(F_ACK_N, type))
        enc(v->buf, v->len, i, &num_blocks, 0, "%u");

    // TODO: send timestamps in protected packets
    const uint8_t num_ts = 0;
    enc(v->buf, v->len, i, &num_ts, 0, "%u");

    enc(v->buf, v->len, i, &lg_recv, lg_ack_len, "%" PRIu64);

    const uint16_t ack_delay = 0;
    enc(v->buf, v->len, i, &ack_delay, 0, "%u");

    struct ival * b;
    uint64_t prev_lo = 0;
    splay_foreach_rev (b, diet, &c->recv) {
        if (prev_lo) {
            const uint64_t gap = prev_lo - b->hi - 1;
            ensure(gap <= UINT8_MAX, "TODO: gap %" PRIu64 " too large", gap);
            enc(v->buf, v->len, i, &gap, sizeof(uint8_t), "%" PRIu64);
        }
        const uint64_t ack_block = b->hi - b->lo + (prev_lo ? 1 : 0);
        warn(NTE, "ACKing %" PRIu64 "-%" PRIu64, b->lo, b->hi);
        enc(v->buf, v->len, i, &ack_block, ack_block_len, "%" PRIu64);
        prev_lo = b->lo;
    }
    return i - pos;
}


static const uint8_t enc_sid_len[] = {0xFF, 0x00, 0x01, 002,
                                      0x03}; // 0xFF = invalid

static uint8_t __attribute__((const)) needed_sid_len(const uint32_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    if (n < 0x00FFFFFF) // UINT24_MAX :-)
        return 3;
    return 4;
}


static const uint8_t enc_off_len[] = {0x00,      0xFF, 0x01 << 1, 0xFF,
                                      0x02 << 1, 0xFF, 0xFF,      0xFF,
                                      0x03 << 1}; // 0xFF = invalid

static uint8_t __attribute__((const)) needed_off_len(const uint64_t n)
{
    if (n == 0)
        return 0;
    if (n < UINT16_MAX)
        return 2;
    if (n < UINT32_MAX)
        return 4;
    return 8;
}


uint16_t enc_stream_frame(struct q_stream * const s, struct w_iov * const v)
{
    const uint16_t dlen = v->len - Q_OFFSET; // TODO: support FIN bit
    ensure(dlen || s->state > STRM_STAT_OPEN,
           "no stream data or need to send FIN");

    warn(INF, "%u byte%s at off %" PRIu64 "-%" PRIu64 " on str %u", dlen,
         plural(dlen), s->out_off, dlen ? s->out_off + dlen - 1 : s->out_off,
         s->id);

    const uint8_t sid_len = needed_sid_len(s->id);
    uint8_t type =
        FRAM_TYPE_STRM | (dlen ? F_STREAM_DATA_LEN : 0) | enc_sid_len[sid_len];

    // if stream is closed locally and this is the last packet, include a FIN
    if ((s->state == STRM_STAT_HCLO || s->state == STRM_STAT_CLSD) &&
        v == sq_last(&s->out, w_iov, next)) {
        warn(NTE, "sending %s FIN on %s conn %" PRIx64 " str %u, state %u",
             dlen ? "" : "pure", conn_type(s->c), s->c->id, s->id, s->state);
        type |= F_STREAM_FIN;
        s->fin_sent = 1;
        maybe_api_return(q_close_stream, s);
    }

    // prepend a stream frame header
    const uint8_t off_len = needed_off_len(s->out_off);
    type |= enc_off_len[off_len];

    // now that we know how long the stream frame header is, encode it
    uint16_t i = meta(v).stream_header_pos =
        Q_OFFSET - 1 - (dlen ? 2 : 0) - off_len - sid_len;
    enc(v->buf, v->len, i, &type, 0, "0x%02x");
    enc(v->buf, v->len, i, &s->id, sid_len, "%u");
    if (off_len)
        enc(v->buf, v->len, i, &s->out_off, off_len, "%" PRIu64);
    if (dlen)
        enc(v->buf, v->len, i, &dlen, 0, "%u");

    s->out_off += dlen; // increase the stream data offset
    meta(v).str = s;    // remember stream this buf belongs to
    meta(v).is_rtxable = true;

    return v->len;
}


uint16_t enc_conn_close_frame(struct w_iov * const v,
                              const uint16_t pos,
                              const uint32_t err_code,
                              const char * const reas,
                              const uint16_t reas_len)
{
    uint16_t i = pos;

    const uint8_t type = FRAM_TYPE_CNCL;
    enc(v->buf, v->len, i, &type, 0, "0x%02x");

    enc(v->buf, v->len, i, &err_code, 0, "0x%08x");

    const uint16_t rlen = MIN(reas_len, v->len - i);
    enc(v->buf, v->len, i, &rlen, 0, "%u");

    memcpy(&v->buf[i], reas, rlen);
    warn(DBG, "enc %u-byte reason phrase into [%u..%u]", rlen, i, i + rlen - 1);

    meta(v).is_rtxable = true;

    return i + rlen - pos;
}
