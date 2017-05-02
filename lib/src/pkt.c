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
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"
#include "tommy.h"


static const q_tag prst = {.as_str = "PRST"}, rnon = {.as_str = "RNON"},
                   rseq = {.as_str = "RSEQ"}, cadr = {.as_str = "CADR"};


uint8_t dec_flags(const void * const buf, const uint16_t len)
{
    ensure(len, "len zero");
    return *(const uint8_t * const)buf;
}


uint64_t dec_cid(const void * const buf, const uint16_t len)
{
    const uint8_t flags = dec_flags(buf, len);
    uint64_t cid = 0;
    if (flags & F_LONG_HDR || flags & F_SH_CID)
        dec(cid, buf, len, 1, 0, "%" PRIu64);
    return cid;
}


uint64_t dec_nr(const void * const buf, const uint16_t len)
{
    uint64_t nr = 0;
    dec(nr, buf, len, 9, sizeof(uint32_t), "%" PRIu64);
    return nr;
}


q_tag dec_vers(const void * const buf, const uint16_t len)
{
    const uint8_t flags = dec_flags(buf, len);
    ensure(flags & F_LONG_HDR, "short header");
    q_tag vers = {0};
    dec(vers.as_int, buf, len, 13, 0, "0x%08x");
    return vers;
}


uint16_t __attribute__((nonnull)) enc_pkt(struct q_conn * const c,
                                          uint8_t * const buf,
                                          const uint16_t len,
                                          const uint16_t max_len)
{
    uint16_t i = 0;

    uint8_t flags = 0;
    if (c->state < CONN_ESTB)
        flags |= F_LONG_HDR | F_LH_TYPE_VERS_NEG;
    enc(buf, len, i, &flags, 0, "0x%02x");

    if (flags & F_LONG_HDR || flags & F_SH_CID)
        enc(buf, len, i, &c->id, 0, "%" PRIu64);

    if (flags & F_LONG_HDR) {
        const uint32_t nr = (uint32_t)c->out;
        enc(buf, len, i, &nr, 0, "%u");
        if (vers[c->vers].as_int)
            enc(buf, len, i, &vers[c->vers].as_int, 0, "0x%08x");
        else {
            warn(info, "sending version negotiation server response");
            enc(buf, len, i, &vers[0].as_int, vers_len, "0x%08x");
            return i;
        }
    }

    const uint16_t hash_pos = i;
    i += HASH_LEN;
    ensure(i < Q_OFFSET, "Q_OFFSET is too small");
    warn(debug, "skipping %u..%u to leave room for hash", hash_pos, i);

    // fill remainder of offset with padding
    //
    // TODO find a way to not zero where the stream frame header will go (just
    // before Q_OFFSET)
    warn(debug, "zeroing %u..%u", hash_pos + HASH_LEN, Q_OFFSET);
    memset(&buf[hash_pos + HASH_LEN], 0, Q_OFFSET - i);

    // stream frames must be last, because they can extend to end of packet.
    i = enc_stream_frames(c, buf, i, len, max_len);

    const uint128_t hash = fnv_1a(buf, i, hash_pos, HASH_LEN);
    warn(debug, "inserting %u-byte hash over range 0..%u (w/o %u..%u)",
         HASH_LEN, i, hash_pos, hash_pos + HASH_LEN);
    memcpy(&buf[hash_pos], &hash, HASH_LEN);

    return i;
}
