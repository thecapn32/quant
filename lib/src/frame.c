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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#include <ev.h>
#pragma clang diagnostic pop

#include <inttypes.h>
#include <math.h>
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
#include "stream.h"


#define FRAM_TYPE_PAD 0x00
#define FRAM_TYPE_CNCL 0x02
#define FRAM_TYPE_PING 0x07
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
        // warn(DBG, "%.*s", *len, &v->buf[i]);
        s->in_off += *len;
        sq_insert_tail(&s->i, v, next);
        s->state = STRM_STATE_OPEN;

        if (is_set(F_STREAM_FIN, type)) {
#ifndef NDEBUG
            const uint8_t old_state = s->state;
#endif
            if (s->state <= STRM_STATE_OPEN)
                s->state = STRM_STATE_HCRM;
            else if (s->state >= STRM_STATE_HCLO)
                maybe_api_return(q_close_stream, s);
            else
                s->state = STRM_STATE_HCRM; // XXX untested

            warn(NTE,
                 "received FIN on %s conn %" PRIx64 " str %u, state %u -> %u",
                 conn_type(c), c->id, s->id, old_state, s->state);

            // XXX what if the FIN also has data?
            // w_free_iov(w_engine(c->sock), v);

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
        return i;
    }

    // data is a complete duplicate
    if (off + *len <= s->in_off) {
        warn(NTE,
             "%u byte%s dup data (off %" PRIu64 "-%" PRIu64
             ") on %s conn %" PRIx64 " str %u",
             *len, plural(*len), off, off + *len, conn_type(c), c->id, sid);
        // warn(DBG, "%.*s", *len, &v->buf[i]);
        // w_free_iov(w_engine(c->sock), v);
        return i;
    }

    die("TODO: handle partially new or reordered data: %u byte%s data (off "
        "%" PRIu64 "-%" PRIu64 "), expected %" PRIu64 " on %s conn %" PRIx64
        " str %u: %.*s",
        *len, plural(*len), off, off + *len, s->in_off, conn_type(c), c->id,
        sid, *len, &v->buf[i]);
}


// Convert largest ACK length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_lg_ack_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x0C) >> 2;
    ensure(l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 4, 8};
    return dec[l];
}


// Convert ACK block length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_ack_block_len(const uint8_t flags)
{
    const uint8_t l = flags & 0x03;
    ensure(l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 4, 8};
    return dec[l];
}


// TODO: should use a better data structure here
static struct w_iov * __attribute__((nonnull))
find_sent_pkt(struct q_conn * const c, const uint64_t nr)
{
    // warn(DBG, "find_sent_pkt %" PRIu64, nr);
    // check if packed is in the unACKed queue
    struct w_iov * v;
    sq_foreach (v, &c->sent_pkts, next) {
        // warn(DBG, "sent_pkts %" PRIu64, meta(v).nr);
        if (meta(v).nr == nr)
            return v;
    }

    // check if packet was sent and already ACKed
    if (diet_find(&c->acked_pkts, nr)) {
        // warn(DBG, "pkt %" PRIu64 " already ACKed", nr);
        return 0;
    }

    die("we never sent packet %" PRIu64, nr);
}


#define F_ACK_N 0x10

static uint16_t __attribute__((nonnull))
dec_ack_frame(struct q_conn * const c,
              const struct w_iov * const v,
              const uint16_t pos)
{
    uint16_t i = pos;
    uint8_t type = 0;
    dec(type, v->buf, v->len, i, 0, "0x%02x");

    uint8_t num_blocks = 1;
    if (is_set(F_ACK_N, type)) {
        dec(num_blocks, v->buf, v->len, i, 0, "%u");
        num_blocks++;
    }

    uint8_t num_ts = 0;
    dec(num_ts, v->buf, v->len, i, 0, "%u");

    const uint8_t lg_ack_len = dec_lg_ack_len(type);
    uint64_t lg_ack = 0;
    dec(lg_ack, v->buf, v->len, i, lg_ack_len, "%" PRIu64);

    uint16_t ack_delay = 0;
    dec(ack_delay, v->buf, v->len, i, 0, "%u");

    // first clause from OnAckReceived pseudo code:
    struct w_iov * p = find_sent_pkt(c, lg_ack);
    // if the largest ACKed is newly ACKed, update the RTT
    if (p && meta(p).ack_cnt == 0) {
        c->latest_rtt = ev_now(loop) - meta(p).time;
        if (c->latest_rtt > ack_delay)
            c->latest_rtt -= ack_delay;

        // see UpdateRtt pseudo code:
        if (fpclassify(c->srtt) == FP_ZERO) {
            c->srtt = c->latest_rtt;
            c->rttvar = c->latest_rtt / 2;
        } else {
            c->rttvar = .75 * c->rttvar + .25 * (c->srtt - c->latest_rtt);
            c->srtt = .875 * c->srtt + .125 * c->latest_rtt;
        }
        warn(DBG, "%s conn %" PRIx64 " srtt = %f, rttvar = %f", conn_type(c),
             c->id, c->srtt, c->rttvar);
    }

    // second clause from OnAckReceived pseudo code:
    // the sender may skip packets for detecting optimistic ACKs
    // TODO: if (packets ACKed that the sender skipped): abortConnection()

    const uint8_t ack_block_len = dec_ack_block_len(type);
#ifndef NDEBUG
    uint64_t n = meta(v).nr;
#endif
    uint64_t ack = lg_ack;
    for (uint8_t b = 0; b < num_blocks; b++) {
        uint64_t l = 0;
        dec(l, v->buf, v->len, i, ack_block_len, "%" PRIu64);

        // third clause from OnAckReceived pseudo code:

        // find all newly ACKed packets
        while (ack >= lg_ack - l) {
            warn(INF, "pkt %" PRIu64 " had ACK for %" PRIu64, n, ack);
            p = find_sent_pkt(c, ack);
            if (p && ++meta(p).ack_cnt == 1) {
                // this is a newly ACKed packet
                warn(NTE, "pkt %" PRIu64 " had first ACK for %" PRIu64, n, ack);
                c->lg_acked = MAX(c->lg_acked, ack);

                // see OnPacketAcked pseudo code (for LD):

                // If a packet sent prior to RTO was ACKed, then the RTO
                // was spurious.  Otherwise, inform congestion control.
                if (c->rto_cnt && ack > c->lg_sent_before_rto)
                    // see OnRetransmissionTimeoutVerified pseudo code
                    c->cwnd = kMinimumWindow;
                c->handshake_cnt = c->tlp_cnt = c->rto_cnt = 0;

                // this packet is no no longer unACKed
                diet_insert(&c->acked_pkts, ack);

                // see OnPacketAcked pseudo code (for CC):
                if (ack >= c->rec_end) {
                    if (c->cwnd < c->ssthresh)
                        c->cwnd += p->len;
                    else
                        c->cwnd += p->len / c->cwnd;
                    warn(INF, "cwnd now %" PRIu64, c->cwnd);
                }

                sq_remove(&c->sent_pkts, p, w_iov, next);
                if (meta(p).buf_len > Q_OFFSET) {
                    // move the iov from sent_pkts back to user return stailq
                    struct q_stream * const s = meta(p).str;
                    sq_insert_tail(&s->r, p, next);

                    // adjust in_flight
                    c->in_flight -= meta(p).buf_len;
                    warn(INF, "in_flight -%u = %" PRIu64, meta(p).buf_len,
                         c->in_flight);

                    // FIXME this is the wrong condition
                    warn(CRT, "c->lg_acked %" PRIu64 ">= s->out_nr %" PRIu64,
                         c->lg_acked, s->out_nr);
                    if (c->state == CONN_STAT_ESTB &&
                        s->state == STRM_STATE_OPEN && c->lg_acked >= s->out_nr)
                        maybe_api_return(q_write, s);

                } else
                    // this iov did not have user data
                    w_free_iov(w_engine(c->sock), p);
            }
            ack--;
        }

        // skip ACK gap (no gap after last ACK block)
        if (b < num_blocks - 1) {
            uint8_t gap = 0;
            dec(gap, v->buf, v->len, i, 0, "%u");
            ack -= gap;
        }
    }

    detect_lost_pkts(c);
    set_ld_alarm(c);

    for (uint8_t b = 0; b < num_ts; b++) {
        warn(DBG, "decoding timestamp block #%u", b);
        uint8_t delta_lg_obs = 0;
        dec(delta_lg_obs, v->buf, v->len, i, 0, "%u");
        uint32_t ts = 0;
        dec(ts, v->buf, v->len, i, b == 0 ? 4 : 2, "%u");
    }
    warn(DBG, "done dec ACKs");
    return i;
}


static uint16_t __attribute__((nonnull))
dec_conn_close_frame(struct q_conn * const c,
                     const struct w_iov * const v,
                     const uint16_t pos)
{
    uint16_t i = pos;
    uint8_t type = 0;
    dec(type, v->buf, v->len, i, 0, "0x%02x");

    uint32_t err_code = 0;
    dec(err_code, v->buf, v->len, i, 0, "0x%08x");

    uint16_t reas_len = 0;
    dec(reas_len, v->buf, v->len, i, 0, "%u");
    ensure(reas_len <= v->len - i, "reason_len invalid");

    if (reas_len) {
        char reas_phr[UINT16_MAX];
        memcpy(reas_phr, &v->buf[i], reas_len);
        i += reas_len;
        warn(NTE, "conn close reason: %.*s", reas_len, reas_phr);
    }

    c->state = CONN_STAT_IDLE;
    maybe_api_return(q_read, c);

    return i;
}


bool dec_frames(struct q_conn * const c, struct w_iov * v)
{
    uint16_t i = pkt_hdr_len(v->buf, v->len);
    uint16_t pad_start = 0;
    uint16_t dpos = 0;
    uint16_t dlen = 0;
    bool tx_needed = false;

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
            tx_needed = true;

        } else if (is_set(FRAM_TYPE_ACK, type)) {
            i = dec_ack_frame(c, v, i);

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
                tx_needed = true;
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

    return tx_needed;
}


uint16_t
enc_padding_frame(uint8_t * const buf, const uint16_t pos, const uint16_t len)
{
    warn(DBG, "encoding padding frame into [%u..%u]", pos, pos + len - 1);
    memset(&buf[pos], FRAM_TYPE_PAD, len);
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
                       uint8_t * const buf,
                       const uint16_t len,
                       const uint16_t pos)
{
    uint8_t type = FRAM_TYPE_ACK;

    const uint8_t num_blocks = (uint8_t)MIN(c->recv.cnt, UINT8_MAX);
    if (num_blocks > 1)
        type |= F_ACK_N;

    const uint64_t lg_recv = diet_max(&c->recv);
    const uint8_t lg_ack_len = needed_lg_ack_len(lg_recv);
    type |= enc_lg_ack_len[lg_ack_len];
    const uint8_t ack_block_len = needed_ack_block_len(c);
    type |= enc_ack_block_len[ack_block_len];

    uint16_t i = pos;
    enc(buf, len, i, &type, 0, "0x%02x");

    if (num_blocks > 1)
        enc(buf, len, i, &num_blocks, 0, "%u");

    // TODO: send timestamps in protected packets
    const uint8_t num_ts = 0;
    enc(buf, len, i, &num_ts, 0, "%u");

    enc(buf, len, i, &lg_recv, lg_ack_len, "%" PRIu64);

    const uint16_t ack_delay = 0;
    enc(buf, len, i, &ack_delay, 0, "%u");

    struct ival * b;
    uint64_t prev_lo = 0;
    splay_foreach_rev (b, diet, &c->recv) {
        if (prev_lo) {
            const uint64_t gap = prev_lo - b->hi;
            ensure(gap <= UINT8_MAX, "TODO: gap %" PRIu64 " too large", gap);
            enc(buf, len, i, &gap, sizeof(uint8_t), "%" PRIu64);
        }
        prev_lo = b->lo;
        const uint64_t ack_block = b->hi - b->lo;
        warn(NTE, "ACKing %" PRIu64 "-%" PRIu64, b->lo, b->hi);
        enc(buf, len, i, &ack_block, ack_block_len, "%" PRIu64);
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


uint16_t enc_stream_frame(struct q_stream * const s,
                          struct w_iov * const v,
                          const uint64_t off)
{
    const uint16_t dlen = v->len - Q_OFFSET; // TODO: support FIN bit
    ensure(dlen || s->state > STRM_STATE_OPEN,
           "no stream data or need to send FIN");

    warn(INF, "%u byte%s at off %" PRIu64 "-%" PRIu64 " on str %u", dlen,
         plural(dlen), off, off + dlen, s->id);
    // warn(DBG, "%.*s", dlen, &v->buf[Q_OFFSET]);

    uint64_t o = off;
    const uint8_t sid_len = needed_sid_len(s->id);
    uint8_t type =
        FRAM_TYPE_STRM | (dlen ? F_STREAM_DATA_LEN : 0) | enc_sid_len[sid_len];

    // if this stream was closed locally or remotely, and this is the last
    // packet or we have no more packets, include a FIN
    if (s->state == STRM_STATE_CLSD ||
        (s->state == STRM_STATE_HCLO &&
         (sq_next(sq_first(&s->o), next) == 0 || sq_empty(&s->o)))) {
        warn(NTE, "sending FIN on %s conn %" PRIx64 " str %u, state %u",
             conn_type(s->c), s->c->id, s->id, s->state);
        type |= F_STREAM_FIN;
        if (s->state == STRM_STATE_CLSD)
            s->state = STRM_STATE_IDLE;
    }
    // prepend a stream frame header
    const uint8_t off_len = needed_off_len(o);
    type |= enc_off_len[off_len];

    // now that we know how long the stream frame header is, encode it
    uint16_t i = meta(v).head_start =
        Q_OFFSET - 1 - (dlen ? 2 : 0) - off_len - sid_len;
    enc(v->buf, v->len, i, &type, 0, "0x%02x");
    enc(v->buf, v->len, i, &s->id, sid_len, "%u");
    if (off_len)
        enc(v->buf, v->len, i, &o, off_len, "%" PRIu64);
    if (dlen)
        enc(v->buf, v->len, i, &dlen, 0, "%u");

    // TODO: support multiple frames per packet? (needs memcpy!)
    return v->len;
}


uint16_t enc_conn_close_frame(struct q_conn * const c __attribute__((unused)),
                              uint8_t * const buf,
                              const uint16_t len,
                              const uint16_t pos,
                              const uint32_t err_code,
                              const char * const reas,
                              const uint16_t reas_len)
{
    uint16_t i = pos;

    const uint8_t type = FRAM_TYPE_CNCL;
    enc(buf, len, i, &type, 0, "0x%02x");

    enc(buf, len, i, &err_code, 0, "0x%08x");

    const uint16_t rlen = MIN(reas_len, len - i);
    enc(buf, len, i, &rlen, 0, "%u");

    memcpy(&buf[i], reas, rlen);

    return i + rlen - pos;
}
