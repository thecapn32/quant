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
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef __linux__
#include <byteswap.h>
#endif

#include <warpcore/warpcore.h>

#include "conn.h"
#include "fnv_1a.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"


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
dec_stream_frame(struct w_iov * const v,
                 const uint16_t pos,
                 uint32_t * const sid,
                 uint16_t * const data_start,
                 uint16_t * const data_len)
{
    *data_start = pos;
    uint8_t type = 0;
    dec(type, v->buf, v->len, *data_start, 0, "0x%02x");

    *sid = 0;
    const uint8_t sid_len = dec_sid_len(type);
    dec(*sid, v->buf, v->len, *data_start, sid_len, "%u");

    const uint8_t off_len = dec_off_len(type);
    uint64_t off = 0;
    if (off_len)
        dec(off, v->buf, v->len, *data_start, off_len, "%" PRIu64);
    // TODO: pay attention to offset when delivering data to app

    *data_len = 0;
    if (type & F_STREAM_DATA_LEN)
        dec(*data_len, v->buf, v->len, *data_start, 0, "%u");
    ensure(type & F_STREAM_FIN || *data_len, "FIN or data_len");

    return *data_start + *data_len;
}


// Convert largest ACK length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_lg_ack_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x0C) >> 2;
    ensure(l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 4, 6};
    return dec[l];
}


// Convert ACK block length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_ack_block_len(const uint8_t flags)
{
    const uint8_t l = flags & 0x03;
    ensure(l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 4, 6};
    return dec[l];
}


// TODO: should use a better data structure here
static struct w_iov * __attribute__((nonnull))
find_sent_pkt(const struct w_iov_stailq * const q, const uint64_t nr)
{
    struct w_iov * v;
    STAILQ_FOREACH (v, q, next)
        if (pkt_nr(v->buf, v->len) == nr)
            return v;
    die("sent packet %" PRIu64 " not found", nr);
    return 0;
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

    uint8_t num_blocks = 0;
    if (type & F_ACK_N) {
        dec(num_blocks, v->buf, v->len, i, 0, "%u");
        num_blocks++;
    } else {
        num_blocks = 1;
        warn(debug, "F_ACK_N unset; one ACK block present");
    }

    uint8_t ts_blocks = 0;
    dec(ts_blocks, v->buf, v->len, i, 0, "%u");

    const uint8_t lg_ack_len = dec_lg_ack_len(type);
    uint64_t lg_ack = 0;
    dec(lg_ack, v->buf, v->len, i, lg_ack_len, "%" PRIu64);

    uint16_t ack_delay = 0;
    dec(ack_delay, v->buf, v->len, i, 0, "%u");

    // first clause from OnAckReceived pseudo code:
    struct w_iov * p = find_sent_pkt(&c->sent_pkts, lg_ack);
    // if the largest ACKed is newly ACKed, update the RTT
    if (p && q_pkt_meta[p->idx].ack_cnt == 0) {
        c->latest_rtt = ev_now(loop) - q_pkt_meta[p->idx].time;
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
        warn(info, "conn %" PRIx64 " srtt = %f, rttvar = %f", c->id, c->srtt,
             c->rttvar);
    }

    // second clause from OnAckReceived pseudo code:
    // the sender may skip packets for detecting optimistic ACKs
    // TODO: if (packets ACKed that the sender skipped): abortConnection()

    const uint8_t ack_block_len = dec_ack_block_len(type);
    warn(debug, "%u-byte ACK block len", ack_block_len);

    uint64_t ack = lg_ack;
    for (uint8_t b = 0; b < num_blocks; b++) {
        warn(debug, "decoding ACK block #%u", b);
        uint64_t l = 0;
        dec(l, v->buf, v->len, i, ack_block_len, "%" PRIu64);

        // third clause from OnAckReceived pseudo code:

        // find all newly ACKed packets
        while (ack > lg_ack - l) {
            warn(notice, "got ACK for %" PRIu64, ack);
            p = find_sent_pkt(&c->sent_pkts, ack);
            if (p) {
                if (q_pkt_meta[p->idx].ack_cnt == 0) {
                    // this is a newly ACKed packet

                    // see OnPacketAcked pseudo code (for LD):

                    // If a packet sent prior to RTO was ACKed, then the RTO
                    // was spurious.  Otherwise, inform congestion control.
                    if (c->rto_cnt && ack > c->lg_sent_before_rto)
                        // see OnRetransmissionTimeoutVerified pseudo code
                        c->cwnd = kMinimumWindow;
                    c->handshake_cnt = c->tlp_cnt = c->rto_cnt = 0;
                    // TODO: pseudo code is wrong here - figure out when to
                    // remove sent packets from data structure
                    // STAILQ_REMOVE(&c->sent_pkts, p, w_iov, next);

                    // see OnPacketAcked pseudo code (for CC):
                    if (ack >= c->rec_end) {
                        if (c->cwnd < c->ssthresh)
                            c->cwnd += p->len;
                        else
                            c->cwnd += p->len / c->cwnd;
                        warn(debug, "cwnd now %" PRIu64, c->cwnd);
                    }
                }

                // remember that we've seen an ACK for this packet
                q_pkt_meta[p->idx].ack_cnt++;
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

    for (uint8_t b = 0; b < ts_blocks; b++) {
        warn(debug, "decoding timestamp block #%u", b);
        uint8_t delta_lg_obs = 0;
        dec(delta_lg_obs, v->buf, v->len, i, 0, "%u");
        uint32_t ts = 0;
        dec(ts, v->buf, v->len, i, 0, "%u");
    }

    return i;
}


bool dec_frames(struct q_conn * const c, struct w_iov * const v)
{
    uint16_t i = pkt_hdr_len(v->buf, v->len) + HASH_LEN;
    uint16_t pad_start = 0;
    uint16_t data_start = 0;
    uint16_t data_len = 0;
    uint32_t sid = 0;

    while (i < v->len) {
        const uint8_t type = ((const uint8_t * const)(v->buf))[i];
        if (pad_start && (type != T_PADDING || i == v->len - 1)) {
            warn(debug, "skipped padding in [%u..%u]", pad_start, i);
            pad_start = 0;

        } else if (type != T_PADDING)
            warn(debug, "frame type 0x%02x, start pos %u", type, i);

        if (bitmask_match(type, T_STREAM)) {
            // TODO: support multiple stream frames per packet (needs memcpy)
            ensure(data_len == 0,
                   "can only handle one stream frame per packet");
            i += dec_stream_frame(v, i, &sid, &data_start, &data_len);

        } else if (bitmask_match(type, T_ACK)) {
            i += dec_ack_frame(c, v, i);

        } else
            switch (type) {
            case T_PADDING:
                pad_start = pad_start ? pad_start : i;
                i++;
                break;

            // case T_RST_STREAM:
            //     die("rst_stream frame");
            //     break;
            // case T_CONNECTION_CLOSE:
            //     i += dec_conn_close_frame(c, &v->buf[i], v->len - i);
            //     break;
            // case T_GOAWAY:
            //     die("goaway frame");
            //     break;
            // case T_WINDOW_UPDATE:
            //     die("window_update frame");
            //     break;
            // case T_BLOCKED:
            //     die("blocked frame");
            //     break;
            // case T_PING:
            //     die("ping frame");
            //     break;
            default:
                die("unknown frame type 0x%02x", type);
            }
    }

    if (data_len == 0) {
        // if there was no stream frame present, we did not enqueue this w_iov
        // into a stream, so free it here
        warn(debug, "freeing w_iov w/o stream data");
        struct w_iov_stailq q = STAILQ_HEAD_INITIALIZER(q);
        STAILQ_INSERT_HEAD(&q, v, next);
        w_free(w_engine(c->sock), &q);

    } else {
        // adjust w_iov start and len to stream frame data
        v->buf = &v->buf[data_start];
        v->len = data_len;

        // deliver data into stream
        struct q_stream * s = get_stream(c, sid);
        if (s == 0)
            s = new_stream(c, sid);
        warn(info, "%u byte%s on str %u: %.*s", data_len, plural(data_len), sid,
             v->len, v->buf);
        s->in_off += data_len;
        STAILQ_INSERT_TAIL(&s->i, v, next);
        if (s->id != 0) {
            pthread_mutex_lock(&lock);
            pthread_cond_signal(&read_cv);
            pthread_mutex_unlock(&lock);
        }
    }

    return data_len;
}


uint16_t
enc_padding_frame(void * const buf, const uint16_t pos, const uint16_t len)
{
    warn(debug, "encoding padding frame into [%u..%u]", pos, pos + len - 1);
    memset(&((uint8_t *)buf)[pos], T_PADDING, len);
    return len;
}


static const uint8_t enc_lg_ack_len[] = {0xFF, 0x00, 0x01, 0xFF,
                                         0x02, 0xFF, 0x03}; // 0xFF = invalid


static uint8_t __attribute__((const)) needed_lg_ack_len(const uint64_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    if (n < UINT32_MAX)
        return 4;
    return 6;
}


static const uint8_t enc_ack_block_len[] = {0xFF, 0x00, 0x01, 0xFF,
                                            0x02, 0xFF, 0x03}; // 0xFF = invalid


static uint8_t __attribute__((nonnull))
needed_ack_block_len(const struct q_conn * const c)
{
    const uint64_t max_block = c->lg_recv - c->lg_recv_acked;
    if (max_block < UINT8_MAX)
        return 1;
    if (max_block < UINT16_MAX)
        return 2;
    if (max_block < UINT32_MAX)
        return 3;
    return 6;
}


uint16_t enc_ack_frame(struct q_conn * const c,
                       void * const buf,
                       const uint16_t len,
                       const uint16_t pos)
{
    uint8_t type = T_ACK;
    // type |= 0x00; // TODO: support Num Blocks > 0
    const uint8_t lg_ack_len = needed_lg_ack_len(c->lg_recv);
    type |= enc_lg_ack_len[lg_ack_len];
    const uint8_t ack_block_len = needed_ack_block_len(c);
    type |= enc_ack_block_len[ack_block_len];

    uint16_t i = pos;
    enc(buf, len, i, &type, 0, "0x%02x");

    const uint8_t num_ts = 0;
    enc(buf, len, i, &num_ts, 0, "%u");

    enc(buf, len, i, &c->lg_recv, lg_ack_len, "%" PRIu64);
    warn(notice, "ACKing %" PRIu64, c->lg_recv);

    const uint16_t ack_delay = 0;
    enc(buf, len, i, &ack_delay, 0, "%u");

    // TODO: support Num Blocks > 0
    const uint64_t ack_block = c->lg_recv - c->lg_recv_acked;
    enc(buf, len, i, &ack_block, ack_block_len, "%" PRIu64);
    c->lg_recv = c->lg_recv_acked;

    return i - pos;
}


static const uint8_t enc_sid_len[] = {0x00, 0x01, 002, 0x03}; // 0xFF = invalid

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


static const uint8_t enc_off_len[] = {0x00,      0xFF, 0x01 << 2, 0xFF,
                                      0x02 << 2, 0xFF, 0xFF,      0xFF,
                                      0x03 << 2}; // 0xFF = invalid

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
                          void * const buf,
                          const uint16_t pos __attribute__((unused)),
                          const uint16_t len)
{
    const uint16_t data_len = len - Q_OFFSET; // TODO: support FIN bit
    if (data_len == 0)
        // there might not be stream data, e.g., for pure ACKs
        return len;

    // there is stream data, so prepend a stream frame header
    const uint8_t off_len = needed_off_len(s->out_off);
    const uint8_t sid_len = needed_sid_len(s->id);
    const uint8_t type = T_STREAM | F_STREAM_DATA_LEN | enc_off_len[off_len] |
                         enc_sid_len[sid_len];
    uint16_t i = Q_OFFSET - 3 - off_len - sid_len; // space for header

    // now that we know how long the stream frame header is, encode it
    enc(buf, len, i, &type, 0, "0x%02x");
    enc(buf, len, i, &s->id, sid_len, "%u");
    if (off_len)
        enc(buf, len, i, &s->out_off, off_len, "%" PRIu64);
    enc(buf, len, i, &data_len, 0, "%u");

    // TODO: support multiple frames per packet? (needs memcpy!)

    return len;
}
