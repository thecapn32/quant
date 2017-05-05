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

#include <warpcore/warpcore.h>

#include "conn.h"
#include "fnv_1a.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "tommy.h"


/// Packet number lengths for different short-header packet types
const uint8_t pkt_nr_len[] = {0, 1, 2, 4};


uint16_t pkt_hdr_len(const void * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint16_t pos = 0;
    if (flags & F_LONG_HDR)
        pos = 17;
    else
        pos = 1 + (flags & F_SH_CID ? 8 : 0) + pkt_nr_len[pkt_type(buf)];
    ensure(pos <= len, "payload position %u after end pf packet %u", pos, len);
    return pos;
}


uint64_t pkt_cid(const void * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint64_t cid = 0;
    if (flags & F_LONG_HDR || flags & F_SH_CID)
        dec(cid, buf, len, 1, 0, "%" PRIu64);
    else
        die("no connection ID in header");
    return cid;
}


uint64_t pkt_nr(const void * const buf, const uint16_t len)
{
    const uint8_t flags = pkt_flags(buf);
    uint64_t nr = 0;
    dec(nr, buf, len, 9, flags & F_LONG_HDR ? 4 : pkt_nr_len[pkt_type(buf)],
        "%" PRIu64);
    return nr;
}


uint32_t pkt_vers(const void * const buf, const uint16_t len)
{
    ensure(pkt_flags(buf) & F_LONG_HDR, "short header");
    uint32_t vers = 0;
    dec(vers, buf, len, 13, 0, "0x%08x");
    return vers;
}


const uint8_t enc_pkt_nr_len[] = {0, 0x01, 0x02, 0, 0x03};

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
                 uint8_t * const buf,
                 const uint16_t len,
                 const uint16_t max_len)
{
    uint16_t i = 0;
    uint8_t flags = 0;
    if (c->state < CONN_ESTB)
        flags |= F_LONG_HDR | F_LH_TYPE_VERS_NEG;
    else {
        flags |= enc_pkt_nr_len[needed_pkt_nr_len(c->out)];
        flags |= F_SH_CID; // TODO: support short headers w/o cid
    }
    i += enc(buf, len, i, &flags, 0, "0x%02x");

    if (flags & F_LONG_HDR || flags & F_SH_CID)
        i += enc(buf, len, i, &c->id, 0, "%" PRIu64);

    if (flags & F_LONG_HDR) {
        const uint32_t nr = c->state == CONN_VERS_RECV ? c->in : c->out;
        i += enc(buf, len, i, &nr, 0, "%u");
        i += enc(buf, len, i, &c->vers, 0, "0x%08x");
        if (c->state == CONN_VERS_RECV) {
            warn(info, "sending version negotiation server response");
            for (uint8_t j = 0; j < ok_vers_len; j++)
                i += enc(buf, len, i, &ok_vers[j], 0, "0x%08x");
            return i;
        }
    } else
        i += enc(buf, len, i, &c->out, needed_pkt_nr_len(c->out), "%" PRIu64);

    const uint16_t hash_pos = i;
    i += HASH_LEN;
    ensure(i < Q_OFFSET, "Q_OFFSET is too small");
    warn(debug, "skipping [%u..%u] to leave room for hash", hash_pos, i - 1);

    if (c->in)
        i += enc_ack_frame(c, buf, len, i);

    if (c->state >= CONN_ESTB && s) {
        // stream frames must be last, because they can extend to end of packet.
        i += enc_padding_frame(buf, i, Q_OFFSET - i);
        i = enc_stream_frame(s, buf, i, len, max_len);
    }

    const uint128_t hash = fnv_1a(buf, i, hash_pos, HASH_LEN);
    warn(debug, "inserting %u-byte hash over range [0..%u] into [%u..%u]",
         HASH_LEN, i - 1, hash_pos, hash_pos + HASH_LEN - 1);
    memcpy(&buf[hash_pos], &hash, HASH_LEN);

    return i;
}
