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
#include <string.h>

#ifdef __linux__
#include <byteswap.h>
#endif

#include <picotls.h>
// #include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "fnv_1a.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"


/// Packet number lengths for different short-header packet types
static const uint8_t pkt_nr_len[] = {0xFF, 1, 2, 4};


uint16_t pkt_hdr_len(const uint8_t * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint16_t pos = 0;
    if (is_set(F_LONG_HDR, flags))
        pos = 17;
    else {
        const uint8_t type = pkt_type(flags);
        if (type < 1 || type > 3) {
            warn(ERR, "illegal pkt type %u", type);
            return UINT16_MAX;
        }
        pos = 1 + (is_set(F_SH_CID, flags) ? 8 : 0) + pkt_nr_len[type];
    }
    ensure(pos <= len, "payload position %u after end of packet %u", pos, len);
    return pos;
}


uint64_t pkt_cid(const uint8_t * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint64_t cid = 0;
    if (is_set(F_LONG_HDR, flags) || is_set(F_SH_CID, flags)) {
        uint16_t i = 1;
        dec(cid, buf, len, i, 0, "%" PRIx64);
    } else
        die("no connection ID in header");
    return cid;
}


uint64_t
pkt_nr(const uint8_t * const buf, const uint16_t len, struct q_conn * const c)
{
    const uint8_t flags = pkt_flags(buf);
    uint64_t nr = c ? diet_max(&c->recv) + 1 : 0;
    uint16_t i = is_set(F_LONG_HDR, flags) || is_set(F_SH_CID, flags) ? 9 : 1;
    dec(nr, buf, len, i,
        is_set(F_LONG_HDR, flags) ? 4 : pkt_nr_len[pkt_type(flags)],
        "%" PRIu64);
    return nr;
}


uint32_t pkt_vers(const uint8_t * const buf, const uint16_t len)
{
    ensure(is_set(F_LONG_HDR, pkt_flags(buf)), "short header");
    uint32_t vers = 0;
    uint16_t i = 13;
    dec(vers, buf, len, i, 0, "0x%08x");
    return vers;
}

static const uint8_t enc_pkt_nr_len[] = {0xFF, 1, 2, 0xFF, 3};

static uint8_t __attribute__((const)) needed_pkt_nr_len(const uint64_t n)
{
    if (n < UINT8_MAX)
        return 1;
    if (n < UINT16_MAX)
        return 2;
    return 4;
}


#define CONN_CLOS_ERR_NO_ERROR 0x80000000
// #define CONN_CLOS_ERR_INTERNAL_ERROR 0x80000001
// #define CONN_CLOS_ERR_CANCELLED 0x80000002
// #define CONN_CLOS_ERR_FLOW_CONTROL_ERROR 0x80000003
// #define CONN_CLOS_ERR_STREAM_ID_ERROR 0x80000004
// #define CONN_CLOS_ERR_STREAM_STATE_ERROR 0x80000005
// #define CONN_CLOS_ERR_FINAL_OFFSET_ERROR 0x80000006
// #define CONN_CLOS_ERR_FRAME_FORMAT_ERROR 0x80000007
// #define CONN_CLOS_ERR_VERSION_NEGOTIATION_ERROR 0x80000009
// #define CONN_CLOS_ERR_PROTOCOL_VIOLATION 0x8000000A

void enc_pkt(struct q_stream * const s,
             const bool rtx,
             struct w_iov * const v,
             struct w_iov_sq * const q)
{
    struct q_conn * const c = s->c;

    // prepend the header by adjusting the buffer offset
    v->buf -= Q_OFFSET;
    v->len += Q_OFFSET;

    uint16_t i = 0;
    uint8_t flags = 0;

    if (rtx)
        warn(DBG, "enc RTX %" PRIu64 " as %" PRIu64, meta(v).nr,
             c->state == CONN_STAT_VERS_REJ ? diet_max(&c->recv)
                                            : c->lg_sent + 1);

    meta(v).nr =
        c->state == CONN_STAT_VERS_REJ ? diet_max(&c->recv) : ++c->lg_sent;
    // TODO: increase by random offset

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
    case CONN_STAT_CLSD:
        if (!is_set(CONN_FLAG_OMIT_CID, c->flags))
            flags |= F_SH_CID;
        flags |= enc_pkt_nr_len[needed_pkt_nr_len(meta(v).nr)];
        break;
    default:
        die("unknown conn state %u", c->state);
    }

    if (rtx && flags != pkt_flags(v->buf)) {
        warn(INF,
             "RTX of 0x%02x-type pkt %" PRIu64
             " prevented; new type would be 0x%02x",
             pkt_flags(v->buf), meta(v).nr, flags);
        return;
    }

    enc(v->buf, v->len, i, &flags, 0, "0x%02x");

    if (is_set(F_LONG_HDR, flags) || is_set(F_SH_CID, flags))
        enc(v->buf, v->len, i, &c->id, 0, "%" PRIx64);

    if (is_set(F_LONG_HDR, flags)) {
        enc(v->buf, v->len, i, &meta(v).nr, sizeof(uint32_t), "%u");
        enc(v->buf, v->len, i, &c->vers, 0, "0x%08x");
        if (c->state == CONN_STAT_VERS_REJ) {
            warn(INF, "sending version negotiation server response");
            for (uint8_t j = 0; j < ok_vers_len; j++)
                if (!is_force_neg_vers(ok_vers[j]))
                    enc(v->buf, v->len, i, &ok_vers[j], 0, "0x%08x");
            v->len = i;
            // don't remember the failed client initial
            diet_remove(&c->recv, meta(v).nr);
        }
    } else
        enc(v->buf, v->len, i, &meta(v).nr, needed_pkt_nr_len(meta(v).nr),
            "%" PRIu64);

    const uint16_t hdr_len = i;

    if (c->state != CONN_STAT_VERS_REJ && !splay_empty(&c->recv)) {
        meta(v).ack_header_pos = i;
        i += enc_ack_frame(c, v->buf, v->len, i);
    } else
        meta(v).ack_header_pos = 0;

    if (c->state == CONN_STAT_CLSD) {
        const char reas[] = "As if that blind rage had washed me clean, rid me "
                            "of hope; for the first time, in that night alive "
                            "with signs and stars, I opened myself to the "
                            "benign indifference of the world. Finding it so "
                            "much like myself—so like a brother, really—I felt "
                            "that I had been happy and that I was happy again. "
                            "For everything to be consummated, for me to feel "
                            "less alone, I had only to wish that there be a "
                            "large crowd of spectators the day of my execution "
                            "and that they greet me with cries of hate.";
        v->len = i + 7 + sizeof(reas);
        i += enc_conn_close_frame(v, i, CONN_CLOS_ERR_NO_ERROR, reas,
                                  sizeof(reas));
        // maybe_api_return(q_close, c);

    } else {

        if (rtx) {
            ensure(is_rtxable(&meta(v)), "is rtxable");

            // this is a RTX, pad out until beginning of stream header
            enc_padding_frame(v->buf, i, meta(v).stream_header_pos - i);
            i = meta(v).stream_data_end;

        } else {
            // this is a fresh data or pure FIN packet
            if (v->len > Q_OFFSET || s->state == STRM_STAT_HCLO ||
                s->state == STRM_STAT_CLSD) {
                // add a stream frame header, after padding out rest of Q_OFFSET
                enc_padding_frame(v->buf, i, Q_OFFSET - i);
                meta(v).stream_data_end = i = enc_stream_frame(s, v);
            }
        }

        if (c->state == CONN_STAT_VERS_SENT)
            i += enc_padding_frame(v->buf, i, MIN_INI_LEN - i);
        v->len = i;
    }
    // #ifndef NDEBUG
    //     if (_dlevel == debug)
    //         hexdump(v->buf, v->len);
    // #endif

    // alloc a new buffer to encrypt/sign into for TX
    struct w_iov * const x = w_alloc_iov(w_engine(c->sock), MAX_PKT_LEN, 0);
    x->ip = v->ip;
    x->port = v->port;
    x->flags = v->flags;

    if (c->state < CONN_STAT_ESTB) {
        memcpy(x->buf, v->buf, v->len); // copy data
        x->len = v->len;
        // version negotiation server responses do not carry a hash
        if (c->state != CONN_STAT_VERS_REJ) {
            const uint64_t hash = fnv_1a(x->buf, x->len);
            warn(DBG,
                 "adding %lu-byte hash %" PRIx64 " over [0..%u] into [%u..%lu]",
                 sizeof(hash), hash, x->len - 1, x->len,
                 x->len + sizeof(hash) - 1);
            uint64_t hash_pos = x->len;
            x->len += sizeof(hash);
            enc(x->buf, x->len, hash_pos, &hash, 0, "%" PRIx64);
        }
    } else {
        memcpy(x->buf, v->buf, hdr_len); // copy pkt header
        x->len = hdr_len + (uint16_t)ptls_aead_encrypt(
                               c->out_kp0, &x->buf[hdr_len], &v->buf[hdr_len],
                               v->len - hdr_len, meta(v).nr, v->buf, hdr_len);
        warn(DBG, "adding %d-byte AEAD over [0..%u] into [%u..%u]",
             x->len - v->len, i - 1, i, x->len - 1);
    }

    sq_insert_tail(q, x, next);

    meta(v).tx_cnt++;

    if (v->len > Q_OFFSET) {
        // FIXME packet is retransmittable (check incorrect)
        if (!rtx) {
            c->in_flight += x->len;
            warn(INF, "in_flight +%u = %" PRIu64, x->len, c->in_flight);
        }
        set_ld_alarm(c);
    }

    warn(NTE,
         "enc pkt %" PRIu64
         " (len %u+%u, idx %u+%u, type 0x%02x = " bitstring_fmt
         ") on %s conn %" PRIx64,
         meta(v).nr, v->len, x->len - v->len, v->idx, x->idx, pkt_flags(v->buf),
         to_bitstring(pkt_flags(v->buf)), conn_type(c), c->id);

    if (c->state == CONN_STAT_VERS_SENT)
        // adjust v->len to end of stream data (excl. padding)
        v->len = meta(v).stream_data_end;

    v->buf += Q_OFFSET;
    v->len -= Q_OFFSET;
}
