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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <byteswap.h>
#endif

#include <warpcore.h>

#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic_internal.h"
#include "stream.h"

struct q_conn;


// Convert stream ID length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_sid_len(const uint8_t flags)
{
    const uint8_t l = flags & 0x03;
    ensure(/*l >= 0 && */ l <= 3, "cannot decode stream ID length %u", l);
    const uint8_t dec[] = {1, 2, 3, 4};
    return dec[l];
}


// Convert stream ID length encoded in bytes to flags
static uint8_t __attribute__((const)) enc_sid_len(const uint8_t n)
{
    ensure(n >= 1 && n <= 4, "cannot decode stream ID length %u", n);
    const uint8_t enc[] = {0xFF, 0, 1, 2, 3}; // 0xFF invalid
    return enc[n];
}


// Calculate the minimum number of bytes needed to encode the stream ID
static uint8_t __attribute__((const)) calc_sid_len(const uint64_t n)
{
    for (uint8_t shift = 1; shift < 4; shift++)
        if (n >> shift == 0)
            return shift;
    return 4;
}


// Convert stream offset length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_off_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x1C) >> 2;
    ensure(/* l >= 0 && */ l <= 7, "cannot decode stream offset length %u", l);
    const uint8_t dec[] = {0, 2, 3, 4, 5, 6, 7, 8};
    return dec[l];
}


// Convert stream offset length encoded in bytes to flags
static uint8_t __attribute__((const)) enc_off_len(const uint8_t n)
{
    ensure(n != 1 && n <= 8, "cannot stream encode offset length %u", n);
    const uint8_t enc[] = {0, 0xFF, 1, 2, 3, 4, 5, 6, 7}; // 0xFF invalid
    return (uint8_t)(enc[n] << 2);
}


// Calculate the minimum number of bytes needed to encode the stream ID
static uint8_t __attribute__((const)) calc_off_len(const uint64_t n)
{
    if (n == 0)
        return 0;
    for (uint8_t shift = 2; shift < 8; shift++)
        if (n >> shift == 0)
            return shift;
    return 8;
}


// Convert largest ACK length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_lg_ack_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x0C) >> 2;
    ensure(/* l >= 0 && */ l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 3, 4};
    return dec[l];
}


// Convert ACK block length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_ack_block_len(const uint8_t flags)
{
    const uint8_t l = flags & 0x03;
    ensure(/*l >= 0 && */ l <= 3, "cannot decode largest ACK length %u", l);
    const uint8_t dec[] = {1, 2, 4, 6};
    return dec[l];
}


static uint16_t __attribute__((nonnull))
dec_stream_frame(struct q_conn * const c,
                 const uint8_t * const buf,
                 const uint16_t len)
{
    uint16_t i = 0;
    uint8_t type = 0;
    dec(type, buf, len, i, 0, "0x%02x");
    warn(debug, "fin = %u", type & F_STREAM_FIN);

    const uint8_t sid_len = dec_sid_len(type);
    uint32_t sid = 0;
    dec(sid, buf, len, i, sid_len, "%u");
    struct q_stream * s = get_stream(c, sid);
    if (s == 0)
        s = new_stream(c, sid);

    const uint8_t off_len = dec_off_len(type);
    uint64_t off = 0;
    if (off_len)
        dec(off, buf, len, i, off_len, "%" PRIu64);

    uint16_t data_len = 0;
    if (type & F_STREAM_DATA_LEN)
        dec(data_len, buf, len, i, 0, "%u");
    else
        data_len = len - i;

    // append data
    warn(info, "got data: %s", &buf[i]);
    s->in = realloc(s->in, s->in_len + data_len);
    ensure(s->in, "realloc");
    dec(s->in[s->in_len], buf, len, i, data_len, "%u");
    s->in_len += data_len;
    s->in_off += data_len;

    pthread_mutex_lock(&lock);
    pthread_cond_signal(&read_cv);
    pthread_mutex_unlock(&lock);

    return i;
}


static uint16_t __attribute__((nonnull))
dec_ack_frame(struct q_conn * const c __attribute__((unused)),
              const uint8_t * const buf,
              const uint16_t len)
{
    uint16_t i = 0;
    uint8_t type = 0;
    dec(type, buf, len, i, 0, "0x%02x");

    ensure((type & F_ACK_UNUSED) == 0, "unused ACK frame bit set");

    const uint8_t lg_ack_len = dec_lg_ack_len(type);
    uint64_t lg_ack = 0;
    dec(lg_ack, buf, len, i, lg_ack_len, "%" PRIu64);

    uint16_t lg_ack_delta_t = 0;
    dec(lg_ack_delta_t, buf, len, i, 0, "%u");

    const uint8_t ack_block_len = dec_ack_block_len(type);
    warn(debug, "%u-byte ACK block length", ack_block_len);

    uint8_t ack_blocks = 0;
    if (type & F_ACK_N) {
        dec(ack_blocks, buf, len, i, 0, "%u");
        ack_blocks++; // NOTE: draft-hamilton says +1
    } else {
        ack_blocks = 1;
        warn(debug, "F_ACK_N unset; one ACK block present");
    }

    for (uint8_t b = 0; b < ack_blocks; b++) {
        warn(debug, "decoding ACK block #%u", b);
        uint64_t l = 0;
        dec(l, buf, len, i, ack_block_len, "%" PRIu64);
        // XXX: assume that the gap is not present for the very last ACK block
        if (b < ack_blocks - 1) {
            uint8_t gap = 0;
            dec(gap, buf, len, i, 0, "%u");
        }
    }

    uint8_t ts_blocks = 0;
    dec(ts_blocks, buf, len, i, 0, "%u");
    for (uint8_t b = 0; b < ts_blocks; b++) {
        warn(debug, "decoding timestamp block #%u", b);
        uint8_t delta_lg_obs = 0;
        dec(delta_lg_obs, buf, len, i, 0, "%u");
        uint32_t ts = 0;
        dec(ts, buf, len, i, 0, "%u");
    }

    return i;
}


static uint16_t __attribute__((nonnull))
dec_stop_waiting_frame(struct q_conn * const c __attribute__((unused)),
                       const struct q_cmn_hdr * const p,
                       const uint8_t * const buf,
                       const uint16_t len)
{
    uint16_t i = 0;
    uint8_t type = 0;
    dec(type, buf, len, i, 0, "0x%02x");

    uint64_t lst_unacked = 0;
    const uint8_t nr_len = dec_pkt_nr_len(p->flags);
    dec(lst_unacked, buf, len, i, nr_len, "%" PRIu64);
    return i;
}


static uint16_t __attribute__((nonnull))
dec_conn_close_frame(struct q_conn * const c __attribute__((unused)),
                     const uint8_t * const buf,
                     uint16_t len)
{
    uint16_t i = 0;
    uint8_t type = 0;
    dec(type, buf, len, i, 0, "0x%02x");

    uint32_t err = 0;
    dec(err, buf, len, i, 0, "%u");

    uint16_t reason_len = 0;
    dec(reason_len, buf, len, i, 0, "%u");

    if (reason_len) {
        // uint8_t * reason = calloc(1, reason_len);
        // dec(*reason, buf, len, i, reason_len, "%u"); // XXX: ugly
        warn(err, "%s", buf);
    }

    return i;
}


uint16_t dec_frames(struct q_conn * const c,
                    const struct q_cmn_hdr * const p,
                    const uint8_t * const buf,
                    const uint16_t len)
{
    uint16_t i = 0;

    while (i < len) {
        const uint8_t flags = buf[i];
        warn(debug, "frame type 0x%02x, start pos %u", flags, i);

        if (flags & F_STREAM) {
            i += dec_stream_frame(c, &buf[i], len - i);
            continue;
        }
        if (flags & F_ACK) {
            i += dec_ack_frame(c, &buf[i], len - i);
            continue;
        }

        switch (flags) {
        case T_PADDING:
            warn(debug, "%u-byte padding frame", len - i);
            const uint8_t zero[MAX_PKT_LEN] = {0};
            ensure(memcmp(&buf[i], zero, len - i) == 0,
                   "%u-byte padding not zero", len - i);
            i = len;
            break;

        case T_RST_STREAM:
            die("rst_stream frame");
            break;
        case T_CONNECTION_CLOSE:
            i += dec_conn_close_frame(c, &buf[i], len - i);
            break;
        case T_GOAWAY:
            die("goaway frame");
            break;
        case T_WINDOW_UPDATE:
            die("window_update frame");
            break;
        case T_BLOCKED:
            die("blocked frame");
            break;
        case T_STOP_WAITING:
            i += dec_stop_waiting_frame(c, p, &buf[i], len - i);
            break;
        case T_PING:
            die("ping frame");
            break;
        default:
            die("unknown frame type 0x%02x", buf[0]);
        }
    }
    return i;
}


uint16_t __attribute__((nonnull))
enc_ack_frame(uint8_t * const buf, const uint16_t len)
{
    uint16_t i = 0;
    const uint8_t type = F_ACK;
    enc(buf, len, i, &type, 0, "%u");
    return i;
}


uint16_t __attribute__((nonnull))
enc_conn_close_frame(uint8_t * const buf, const uint16_t len)
{
    uint16_t i = 0;
    const uint8_t type = T_CONNECTION_CLOSE;
    enc(buf, len, i, &type, 0, "%u");
    const uint32_t err = QUIC_INVALID_VERSION;
    enc(buf, len, i, &err, 0, "%u");
    // const char reason[] = "Because I don't like you.";
    // const uint16_t reason_len = sizeof(reason);
    // enc(buf, len, i, &reason, reason_len, "%s");
    return i;
}


uint16_t enc_stream_frame(struct q_stream * const s,
                          uint8_t * const buf,
                          const uint16_t pos __attribute__((unused)),
                          const uint16_t len,
                          const uint16_t max_len)
{
    uint16_t i = Q_OFFSET - sizeof(uint8_t); // space for type fields
    uint8_t type = F_STREAM;

    const uint8_t sid_len = calc_sid_len(s->id);
    i -= sid_len;
    type |= enc_sid_len(sid_len);

    const uint8_t off_len = calc_off_len(s->out_off);
    if (off_len) {
        i -= off_len;
        type |= enc_off_len(off_len);
    }

    if (len < max_len) {
        // this stream frame will not extend to the end of the packet, add data
        // length field XXX and FIN
        i -= sizeof(uint16_t);
        type |= F_STREAM_DATA_LEN | F_STREAM_FIN;
    }

    // now that we know how long the stream frame header is, encode it
    enc(buf, len, i, &type, 0, "%u");
    enc(buf, len, i, &s->id, sid_len, "%u");
    if (off_len)
        enc(buf, len, i, &s->out_off, off_len, "%" PRIu64);
    if (len < max_len) {
        const uint16_t data_len = len - Q_OFFSET;
        enc(buf, len, i, &data_len, 0, "%u");
    }

    return len;
}


uint16_t __attribute__((nonnull))
enc_padding_frame(uint8_t * const buf, const uint16_t len)
{
    buf[0] = T_PADDING;
    memset(&buf[1], 0, len - 1);
    warn(debug, "inserting %u byte%s of zero padding", len - 1,
         plural(len - 1));
    return len;
}
