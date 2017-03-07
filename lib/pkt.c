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

#include <warpcore.h>

#include "conn.h"
#include "fnv_1a.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic_internal.h"
#include "stream.h"
#include "tommy.h"


static const q_tag prst = {.as_str = "PRST"}, rnon = {.as_str = "RNON"},
                   rseq = {.as_str = "RSEQ"}, cadr = {.as_str = "CADR"};


extern uint8_t __attribute__((const)) dec_pkt_nr_len(uint8_t flags);
extern uint8_t __attribute__((const)) enc_pkt_nr_len(uint8_t n);
extern uint8_t __attribute__((const)) calc_req_pkt_nr_len(uint64_t n);


uint16_t dec_cmn_hdr(struct q_cmn_hdr * const ph,
                     const uint8_t * const buf,
                     const uint16_t len,
                     struct q_conn ** const c)
{
    ph->flags = buf[0];
    warn(debug, "ph->flags = 0x%02x", ph->flags);
    uint16_t i = 1;

    if (ph->flags & F_CID)
        dec(ph->cid, buf, len, i, 0, "%" PRIu64);
    *c = get_conn(ph->cid);

    if (ph->flags & F_VERS)
        dec(ph->vers.as_int, buf, len, i, 0, "0x%08x");

    if (ph->flags & F_PUB_RST) {
        warn(err, "public reset");
        uint32_t tag = 0;
        dec(tag, buf, len, i, 0, "0x%04x");
        ensure(tag == prst.as_int, "PRST tag mismatch 0x%04x != 0x%04x", tag,
               prst.as_int);

        uint8_t n = 0;
        dec(n, buf, len, i, 0, "%u");
        ensure(n == 3, "got %u tags in PRST", n);
        i += n; // XXX: undocumented in draft-hamilton

        dec(tag, buf, len, i, 0, "0x%04x");
        ensure(tag == rnon.as_int, "RNON tag mismatch 0x%04x != 0x%04x", tag,
               rnon.as_int);
        uint64_t val = 0;
        dec(val, buf, len, i, 0, "0x%" PRIx64);

        dec(tag, buf, len, i, 0, "0x%04x");
        ensure(tag == rseq.as_int, "RSEQ tag mismatch 0x%04x != 0x%04x", tag,
               rseq.as_int);
        dec(val, buf, len, i, 0, "0x%" PRIx64);

        dec(tag, buf, len, i, 0, "0x%04x");
        ensure(tag == cadr.as_int, "CADR tag mismatch 0x%04x != 0x%04x", tag,
               cadr.as_int);
        // dec(val, buf, len, i, 0, "0x%" PRIx64);

        return i;
    }

    if (ph->flags & F_VERS && i == len)
        // this is a version negotiation packet from the server
        return i;

    const uint8_t nr_len = dec_pkt_nr_len(ph->flags);
    dec(ph->nr, buf, len, i, nr_len, "%" PRIu64);

    if (ph->flags & (F_MULTIPATH | F_UNUSED))
        die("unsupported flag set");

    if (i <= len) {
        // if there are bytes left, there must be a hash to verify
        warn(debug,
             "verifying %u-byte hash over range 0..%u (w/o %u..%u) at pos %u",
             HASH_LEN, len, i, i + HASH_LEN, i);
        const uint128_t hash = fnv_1a(buf, len, i, HASH_LEN);
        if (memcmp(&buf[i], &hash, HASH_LEN) != 0)
            die("hash mismatch");
        else
            warn(debug, "hash OK");
        i += HASH_LEN;
        ensure(i <= len, "pub hdr only %u bytes; truncated?", len);
    }

    return i;
}


uint16_t __attribute__((nonnull)) enc_pkt(struct q_conn * const c,
                                          uint8_t * const buf,
                                          const uint16_t len,
                                          const uint16_t max_len)
{
    uint16_t i = 0;

    // XXX: omit cid to force a PRST
    const uint8_t flags = F_CID;
    enc(buf, len, i, &flags, 0, "0x%02x");

    enc(buf, len, i, &c->id, 0, "%" PRIu64);

    if (c->state < CONN_ESTB || c->state == CONN_FINW) {
        buf[0] |= F_VERS;
        if (vers[c->vers].as_int)
            enc(buf, len, i, &vers[c->vers].as_int, 0, "0x%08x");
        else {
            warn(info, "sending version negotiation server response");
            enc(buf, len, i, &vers[0].as_int, vers_len, "0x%08x");
            return i;
        }
    } else
        warn(info, "not including negotiated version %.4s",
             vers[c->vers].as_str);

    const uint8_t req_pkt_nr_len = calc_req_pkt_nr_len(c->out);
    buf[0] |= enc_pkt_nr_len(req_pkt_nr_len);
    enc(buf, len, i, &c->out, req_pkt_nr_len, "%" PRIu64);

    const uint16_t hash_pos = i;
    i += HASH_LEN;

    if (c->state == CONN_FINW)
        i += enc_conn_close_frame(&buf[i], len - i);

    ensure(i < Q_OFFSET, "Q_OFFSET is too small");
    // TODO: fill remainder of offset with padding?

    // Stream frames must be last, because they can extend to end of packet.
    i = enc_stream_frames(c, buf, i, len, max_len);

    const uint128_t hash = fnv_1a(buf, i, hash_pos, HASH_LEN);
    warn(debug,
         "inserting %u-byte hash over range 0..%u (w/o %u..%u) at pos %u",
         HASH_LEN, i, hash_pos, hash_pos + HASH_LEN, hash_pos);
    memcpy(&buf[hash_pos], &hash, HASH_LEN);

    warn(debug, "ph->flags = 0x%02x", buf[0]);

    return i;
}
