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

#include <ev.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

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
#include "tommy.h"


// Convert stream ID length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_sid_len(const uint8_t flags)
{
    const uint8_t l = flags & 0x03;
    ensure(l >= 0 && l <= 2, "cannot decode stream ID length %u", l);
    const uint8_t dec[] = {1, 2, 4};
    return dec[l];
}


// Convert stream offset length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_off_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x0C) >> 2;
    ensure(l >= 0 && l <= 3, "cannot decode stream offset length %u", l);
    const uint8_t dec[] = {0, 2, 4, 8};
    return dec[l];
}


#define F_STREAM_FIN 0x20
#define F_STREAM_DATA_LEN 0x10


static uint16_t __attribute__((nonnull))
dec_stream_frame(struct q_conn * const c,
                 struct w_iov * const v,
                 const uint16_t pos)
{
    uint16_t i = pos;
    uint8_t type = 0;
    dec(type, v->buf, v->len, i, 0, "0x%02x");

    uint16_t data_len = 0;
    if (type & F_STREAM_DATA_LEN)
        dec(data_len, v->buf, v->len, i, 0, "%u");
    ensure(type & F_STREAM_FIN || data_len, "FIN or data_len");

    const uint8_t sid_len = dec_sid_len(type);
    uint32_t sid = 0;
    dec(sid, v->buf, v->len, i, sid_len, "%u");
    struct q_stream * s = get_stream(c, sid);
    if (s == 0)
        s = new_stream(c, sid);
    s->in_off += data_len;

    const uint8_t off_len = dec_off_len(type);
    uint64_t off = 0;
    if (off_len)
        dec(off, v->buf, v->len, i, off_len, "%" PRIu64);

    // deliver data on stream; set v-buf to start of stream data
    // TODO: pay attention to offset and gaps
    v->buf = &((uint8_t *)v->buf)[i];
    warn(info, "%u byte%s on str %u: %.*s", data_len, plural(data_len), sid,
         data_len, v->buf);
    STAILQ_INSERT_TAIL(&s->i, v, next);

    pthread_mutex_lock(&lock);
    pthread_cond_signal(&read_cv);
    pthread_mutex_unlock(&lock);

    return i;
}


// Convert largest ACK length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_lg_ack_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x0C) >> 2;
    ensure(l >= 0 && l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 3, 6};
    return dec[l];
}


// Convert ACK block length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_ack_block_len(const uint8_t flags)
{
    const uint8_t l = flags & 0x03;
    ensure(l >= 0 && l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 4, 6};
    return dec[l];
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
    // if the largest acked is newly acked, update the RTT
    node * n = list_head(&c->sent_pkts);
    while (n) {
        const struct pkt_info * const pi = n->data;
        if (lg_ack == pi->nr) {
            ev_tstamp rtt_sample = ev_now(loop) - pi->tx_t;
            if (rtt_sample > ack_delay)
                rtt_sample -= ack_delay;
            if (c->handshake_cnt == 0) { // XXX: pseudo code checks srtt == 0
                c->srtt = rtt_sample;
                c->rttvar = rtt_sample / 2;
            } else {
                c->rttvar = .75 * c->rttvar + .25 * (c->srtt - rtt_sample);
                c->srtt = .875 * c->srtt + .125 * rtt_sample;
            }
            warn(info, "conn %" PRIx64 " srtt = %f, rttvar = %f", c->id,
                 c->srtt, c->rttvar);
            break;
        }
        n = n->next;
    }

    // second clause from OnAckReceived pseudo code:
    // the sender may skip packets for detecting optimistic ACKs
    // TODO: if (packets acked that the sender skipped): abortConnection()

    const uint8_t ack_block_len = dec_ack_block_len(type);
    warn(debug, "%u-byte ACK block len", ack_block_len);

    uint64_t ack = lg_ack;
    for (uint8_t b = 0; b < num_blocks; b++) {
        warn(debug, "decoding ACK block #%u", b);
        uint64_t l = 0;
        dec(l, v->buf, v->len, i, ack_block_len, "%" PRIu64);

        // third clause from OnAckReceived pseudo code:
        // find all newly acked packets
        while (ack >= lg_ack - l) {
            warn(debug, "got ACK for %" PRIu64, ack);
            // see OnPacketAcked pseudo code
            // If a packet sent prior to RTO was acked, then the RTO
            // was spurious.  Otherwise, inform congestion control.
            if (c->rto_cnt > 0 && ack > c->lg_sent_before_rto)
                c->cwnd = kMinimumWindow;
            c->handshake_cnt = 0; // XXX: why?
            c->tlp_cnt = 0;
            c->rto_cnt = 0;
            n = list_head(&c->sent_pkts);
            while (n) {
                const struct pkt_info * const pi = n->data;
                if (ack == pi->nr) {
                    list_remove(&c->sent_pkts, n);
                    break;
                }
            }
            ack--;
        }

        // XXX: assume that the gap is not present for the very last ACK block
        if (b < num_blocks - 1) {
            uint8_t gap = 0;
            dec(gap, v->buf, v->len, i, 0, "%u");
            ack -= gap;
        }
    }

    for (uint8_t b = 0; b < ts_blocks; b++) {
        warn(debug, "decoding timestamp block #%u", b);
        uint8_t delta_lg_obs = 0;
        dec(delta_lg_obs, v->buf, v->len, i, 0, "%u");
        uint32_t ts = 0;
        dec(ts, v->buf, v->len, i, 0, "%u");
    }

    return i;
}


uint16_t dec_frames(struct q_conn * const c, struct w_iov * const v)
{
    uint16_t i = pkt_hdr_len(v->buf, v->len) + HASH_LEN;
    uint16_t pad_start = 0;
    bool got_stream_frame = false;

    while (i < v->len) {
        const uint8_t type = ((const uint8_t * const)(v->buf))[i];
        if (pad_start && (type != T_PADDING || i == v->len - 1)) {
            warn(debug, "skipped padding in [%u..%u]", pad_start, i);
            pad_start = 0;
        } else if (type != T_PADDING)
            warn(debug, "frame type 0x%02x, start pos %u", type, i);

        if (bitmask_match(type, T_STREAM)) {
            // TODO: support multiple stream frames per packet (needs memcpy)
            ensure(got_stream_frame == false,
                   "can only handle one stream frame per packet");
            i += dec_stream_frame(c, v, i);
            got_stream_frame = true;
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

    if (got_stream_frame == false) {
        // if there was no stream frame present, we did not enqueue this w_iov
        // into a stream, so free it here
        warn(debug, "freeing w_iov w/o stream data");
        struct w_iov_stailq q = STAILQ_HEAD_INITIALIZER(q);
        STAILQ_INSERT_HEAD(&q, v, next);
        w_free(w_engine(c->sock), &q);
    }

    return i;
}


uint16_t
enc_padding_frame(void * const buf, const uint16_t pos, const uint16_t len)
{
    warn(debug, "encoding padding frame into [%u..%u]", pos, pos + len - 1);
    memset(&((uint8_t *)buf)[pos], T_PADDING, len);
    return len;
}


static const uint8_t enc_lg_ack_len[] = {0xFF, 0x00, 0x01, 0xFF,
                                         0x03}; // 0xFF = invalid

static uint8_t __attribute__((const)) needed_lg_ack_len(const uint64_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    return 4;
}

uint16_t enc_ack_frame(struct q_conn * const c,
                       void * const buf,
                       const uint16_t len,
                       const uint16_t pos)
{
    uint8_t type = T_ACK;
    // type |= 0x00; // TODO: support Num Blocks > 0
    const uint8_t lg_ack_len = needed_lg_ack_len(c->in);
    type |= enc_lg_ack_len[lg_ack_len];
    // type |= 0x00; // TODO: support longer than 8-bit ACK Block lengths

    uint16_t i = pos;
    enc(buf, len, i, &type, 0, "0x%02x");

    const uint8_t num_ts = 0;
    enc(buf, len, i, &num_ts, 0, "%u");

    enc(buf, len, i, &c->in, lg_ack_len, "%" PRIu64);
    warn(info, "ACKing %" PRIu64, c->in);

    const uint16_t ack_delay = 0;
    enc(buf, len, i, &ack_delay, 0, "%u");

    enc(buf, len, i, &ack_delay, 0, "%u");

    // TODO: send actual information
    const uint8_t ack_block = 0;
    enc(buf, len, i, &ack_block, 0, "%u");

    return i - pos;
}


static const uint8_t enc_sid_len[] = {0xFF, 0x00, 0x01, 0xFF,
                                      0x02}; // 0xFF = invalid

static uint8_t __attribute__((const)) needed_sid_len(const uint32_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    return 4;
}


static const uint8_t enc_off_len[] = {0x00,      0x01 << 2, 0xFF, 0xFF,
                                      0x02 << 2, 0xFF,      0xFF, 0xFF,
                                      0x03 << 2}; // 0xFF = invalid

static uint8_t __attribute__((const)) needed_off_len(const uint64_t n)
{
    if (n == 0)
        return 0;
    if (n < UINT16_MAX)
        return 1;
    if (n < UINT32_MAX)
        return 4;
    return 8;
}


uint16_t enc_stream_frame(struct q_stream * const s,
                          void * const buf,
                          const uint16_t pos __attribute__((unused)),
                          const uint16_t len,
                          const uint16_t max_len __attribute__((unused)))
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
    enc(buf, len, i, &data_len, 0, "%u");
    enc(buf, len, i, &s->id, sid_len, "%u");
    if (off_len)
        enc(buf, len, i, &s->out_off, off_len, "%" PRIu64);

    // TODO: support multiple frames per packet? (needs memcpy!)

    return len;
}
