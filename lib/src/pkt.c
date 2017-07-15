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
#include <stdint.h>

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


/// Packet number lengths for different short-header packet types
static const uint8_t pkt_nr_len[] = {0, 1, 2, 4};


uint16_t pkt_hdr_len(const uint8_t * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint16_t pos = 0;
    if (flags & F_LONG_HDR)
        pos = 17;
    else
        pos = 1 + (flags & F_SH_CID ? 8 : 0) + pkt_nr_len[pkt_type(buf)];
    ensure(pos <= len, "payload position %u after end of packet %u", pos, len);
    return pos;
}


uint64_t pkt_cid(const uint8_t * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint64_t cid = 0;
    if (flags & F_LONG_HDR || flags & F_SH_CID) {
        uint16_t i = 1;
        dec(cid, buf, len, i, 0, "%" PRIx64);
    } else
        die("no connection ID in header");
    return cid;
}


uint64_t pkt_nr(const uint8_t * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint64_t nr = 0;
    uint16_t i = 9;
    dec(nr, buf, len, i, flags & F_LONG_HDR ? 4 : pkt_nr_len[pkt_type(buf)],
        "%" PRIu64);
    return nr;
}


uint32_t pkt_vers(const uint8_t * const buf, const uint16_t len)
{
    ensure(pkt_flags(buf) & F_LONG_HDR, "short header");
    uint32_t vers = 0;
    uint16_t i = 13;
    dec(vers, buf, len, i, 0, "0x%08x");
    return vers;
}


static const uint8_t enc_pkt_nr_len[] = {0, 0x01, 0x02, 0, 0x03};

static uint8_t __attribute__((const)) needed_pkt_nr_len(const uint64_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    return 4;
}


uint16_t enc_pkt(struct q_conn * const c,
                 struct q_stream * const s,
                 struct w_iov * const v)
{
    // prepend the header by adjusting the buffer offset
    v->buf -= Q_OFFSET;
    v->len += Q_OFFSET;

    uint16_t i = 0;
    uint8_t flags = 0;
    meta(v).nr = ++c->lg_sent; // TODO: increase by random offset

    warn(debug, "%s conn state %u", conn_type(c), c->state);
    switch (c->state) {
    case CONN_STAT_VERS_SENT:
        flags |= F_LONG_HDR | F_LH_CLNT_INIT;
        break;
    case CONN_STAT_VERS_REJ:
        flags |= F_LONG_HDR | F_LH_TYPE_VNEG;
        break;
    case CONN_STAT_VERS_OK:
        flags |= F_LONG_HDR | (is_clnt(c) ? F_LH_CLNT_CTXT : F_LH_SERV_CTXT);
        break;
    case CONN_STAT_ESTB:
        // TODO: support short headers w/o cid
        flags |= F_SH_CID | enc_pkt_nr_len[needed_pkt_nr_len(c->lg_sent)];
        break;
    default:
        die("unknown conn state %u", c->state);
        break;
    }
    enc(v->buf, v->len, i, &flags, 0, "0x%02x");

    if (is_set(F_LONG_HDR, flags) || is_set(F_SH_CID, flags))
        enc(v->buf, v->len, i, &c->id, 0, "%" PRIx64);

    if (is_set(F_LONG_HDR, flags)) {
        const uint32_t nr = (const uint32_t)c->lg_sent;
        enc(v->buf, v->len, i, &nr, 0, "%u");
        enc(v->buf, v->len, i, &c->vers, 0, "0x%08x");
        if (c->state == CONN_STAT_VERS_REJ) {
            warn(info, "sending version negotiation server response");
            for (uint8_t j = 0; j < ok_vers_len; j++)
                enc(v->buf, v->len, i, &ok_vers[j], 0, "0x%08x");
            return i;
        }
    } else
        enc(v->buf, v->len, i, &c->lg_sent, needed_pkt_nr_len(c->lg_sent),
            "%" PRIu64);

    if (!SPLAY_EMPTY(&c->recv))
        i += enc_ack_frame(c, v->buf, v->len, i);

    // if we've been passed a stream pointer, we need to prepend a stream frame
    // header to the data (otherwise, it's an RTX)
    if (s) {
        // pad out the rest of Q_OFFSET
        enc_padding_frame(v->buf, i, Q_OFFSET - i);

        // encode any stream data present
        if (v->len > Q_OFFSET || s->state >= STRM_STATE_HCLO) {
            i = enc_stream_frame(s, v, s->out_off);

            // increase the stream data offset
            s->out_nr = c->lg_sent;
            s->out_off += i - Q_OFFSET;
        }

        if (c->state == CONN_STAT_VERS_SENT)
            v->len = i += enc_padding_frame(v->buf, i, MIN_INI_LEN - i);

        // store final packet length and number
        meta(v).buf_len = i;

    } else {
        // this is a RTX, pad out until beginning of stream header
        enc_padding_frame(v->buf, i, meta(v).head_start - i);
        // skip over existing stream header and data
        v->len = i = meta(v).buf_len;
        warn(debug, "RTX %u", i);
    }

    const uint64_t hash = fnv_1a(v->buf, i);
    warn(debug, "inserting %lu-byte hash over range [0..%u] into [%u..%lu]",
         HASH_LEN, i - 1, i, i + HASH_LEN - 1);
    v->len += HASH_LEN;
    enc(v->buf, v->len, i, &hash, 0, "%" PRIx64);

    return i;
}
