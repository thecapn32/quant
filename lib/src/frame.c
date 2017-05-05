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
                 const void * const buf,
                 const uint16_t pos,
                 const uint16_t len)
{
    uint16_t i = pos;
    uint8_t type = 0;
    i += dec(type, buf, len, i, 0, "0x%02x");
    warn(debug, "fin = %u", type & F_STREAM_FIN);

    const uint8_t sid_len = dec_sid_len(type);
    uint32_t sid = 0;
    i += dec(sid, buf, len, i, sid_len, "%u");
    struct q_stream * s = get_stream(c, sid);
    if (s == 0)
        s = new_stream(c, sid);

    const uint8_t off_len = dec_off_len(type);
    uint64_t off = 0;
    if (off_len)
        i += dec(off, buf, len, i, off_len, "%" PRIu64);

    uint16_t data_len = 0;
    if (type & F_STREAM_DATA_LEN)
        i += dec(data_len, buf, len, i, 0, "%u");
    else
        data_len = len - i;

    warn(info, "got data: %s", &buf[i]);
    // TODO: check how app can get at data
    s->in_off += data_len;

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
dec_ack_frame(struct q_conn * const c __attribute__((unused)),
              const void * const buf,
              const uint16_t pos,
              const uint16_t len)
{
    uint16_t i = pos;
    uint8_t type = 0;
    i += dec(type, buf, len, i, 0, "0x%02x");

    uint8_t num_blocks = 0;
    if (type & F_ACK_N) {
        i += dec(num_blocks, buf, len, i, 0, "%u");
        num_blocks++;
    } else {
        num_blocks = 1;
        warn(debug, "F_ACK_N unset; one ACK block present");
    }

    uint8_t ts_blocks = 0;
    i += dec(ts_blocks, buf, len, i, 0, "%u");

    const uint8_t lg_ack_len = dec_lg_ack_len(type);
    uint64_t lg_ack = 0;
    i += dec(lg_ack, buf, len, i, lg_ack_len, "%" PRIu64);

    uint16_t lg_ack_delta_t = 0;
    i += dec(lg_ack_delta_t, buf, len, i, 0, "%u");

    const uint8_t ack_block_len = dec_ack_block_len(type);
    warn(debug, "%u-byte ACK block length", ack_block_len);

    for (uint8_t b = 0; b < num_blocks; b++) {
        warn(debug, "decoding ACK block #%u", b);
        uint64_t l = 0;
        i += dec(l, buf, len, i, ack_block_len, "%" PRIu64);
        // XXX: assume that the gap is not present for the very last ACK block
        if (b < num_blocks - 1) {
            uint8_t gap = 0;
            i += dec(gap, buf, len, i, 0, "%u");
        }
    }

    for (uint8_t b = 0; b < ts_blocks; b++) {
        warn(debug, "decoding timestamp block #%u", b);
        uint8_t delta_lg_obs = 0;
        i += dec(delta_lg_obs, buf, len, i, 0, "%u");
        uint32_t ts = 0;
        i += dec(ts, buf, len, i, 0, "%u");
    }

    return i;
}


uint16_t dec_frames(struct q_conn * const c __attribute__((unused)),
                    const void * const buf,
                    const uint16_t len)
{
    uint16_t i = pkt_hdr_len(buf, len) + HASH_LEN;
    uint16_t pad_start = 0;
    bool got_stream_frame = false;

    while (i < len) {
        const uint8_t type = ((const uint8_t * const)(buf))[i];
        if (pad_start && (type != T_PADDING || i == len - 1)) {
            warn(debug, "skipped padding in [%u..%u]", pad_start, i);
            pad_start = 0;
        } else if (type != T_PADDING)
            warn(debug, "frame type 0x%02x, start pos %u", type, i);

        if (bitmask_match(type, T_STREAM)) {
            // TODO: support multiple stream frames per packet (needs memcpy)
            ensure(got_stream_frame == false,
                   "can only handle one stream frame per packet");
            i += dec_stream_frame(c, buf, i, len);
            got_stream_frame = true;
        } else if (bitmask_match(type, T_ACK)) {
            i += dec_ack_frame(c, buf, i, len);
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
            //     i += dec_conn_close_frame(c, &buf[i], len - i);
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
    return i;
}


uint16_t
enc_padding_frame(void * const buf, const uint16_t pos, const uint16_t len)
{
    warn(debug, "encoding padding frame into [%u..%u]", pos, pos + len - 1);
    memset(&buf[pos], T_PADDING, len);
    return len;
}


const uint8_t enc_lg_ack_len[] = {0xFF, 0x00, 0x01, 0xFF, 0x03}; // 0xFF invalid

static uint8_t __attribute__((const)) needed_lg_ack_len(const uint32_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    return 4;
}

uint16_t enc_ack_frame(const struct q_conn * const c,
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
    i += enc(buf, len, i, &type, 0, "0x%02x");

    const uint8_t num_ts = 0;
    i += enc(buf, len, i, &num_ts, 0, "%u");

    i += enc(buf, len, i, &c->in, lg_ack_len, "%" PRIu64);

    const uint16_t ack_delay = 0;
    i += enc(buf, len, i, &ack_delay, 0, "%u");

    i += enc(buf, len, i, &ack_delay, 0, "%u");

    // TODO: send actual information
    const uint8_t ack_block = 0;
    i += enc(buf, len, i, &ack_block, 0, "%u");

    return i - pos;
}


const uint8_t enc_sid_len[] = {0xFF, 0x00, 0x01, 0xFF, 0x02}; // 0xFF invalid

static uint8_t __attribute__((const)) needed_sid_len(const uint32_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    return 4;
}


const uint8_t enc_off_len[] = {
    0x00, 0x01 << 2, 0xFF, 0xFF,     0x02 << 2,
    0xFF, 0xFF,      0xFF, 0x03 << 2}; // 0xFF invalid

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
                          const uint16_t max_len)
{
    // TODO: support multiple frames per packet? (needs memcpy!)

    const uint8_t off_len = needed_off_len(s->out_off);
    const uint8_t sid_len = needed_sid_len(s->id);
    uint16_t i = Q_OFFSET - 1 - off_len - sid_len; // space for header

    uint8_t type = T_STREAM | enc_off_len[off_len] | enc_sid_len[sid_len];
    if (len < max_len)
        // this stream frame will not extend to the end of the packet, add FIN
        type |= F_STREAM_FIN;

    // now that we know how long the stream frame header is, encode it
    i += enc(buf, len, i, &type, 0, "0x%02x");
    i += enc(buf, len, i, &s->id, sid_len, "%u");
    if (off_len)
        enc(buf, len, i, &s->out_off, off_len, "%" PRIu64);

    return len;
}
