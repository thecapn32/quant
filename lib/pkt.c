#include <inttypes.h>
#include <stdbool.h>
#include <sys/param.h>

#include "fnv_1a.h"
#include "frame.h"
#include "pkt.h"
#include "quic.h"
#include "util.h"

static const q_tag prst = {.as_str = "PRST"}, rnon = {.as_str = "RNON"},
                   rseq = {.as_str = "RSEQ"}, cadr = {.as_str = "CADR"};


// Convert packet number length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_pkt_nr_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x30) >> 4;
    assert(/* l >= 0 && */ l <= 3, "cannot decode packet number length %d", l);
    const uint8_t dec[] = {1, 2, 3, 6};
    return dec[l];
}


// Convert packet number length in bytes into flags
static uint8_t __attribute__((const)) enc_pkt_nr_len(const uint8_t n)
{
    assert(n == 1 || n == 2 || n == 4 || n == 6,
           "cannot encode packet number length %d", n);
    static const uint8_t enc[] = {0xFF, 0, 1, 0xFF, 3, 0xFF, 4}; // 0xFF invalid
    return enc[n];
}


uint16_t __attribute__((nonnull))
dec_pub_hdr(struct q_pkt * restrict const p,
            const uint8_t * restrict const buf,
            const uint16_t len)
{
    p->flags = buf[0];
    warn(debug, "p->flags = 0x%02x", p->flags);
    uint16_t i = 1;

    if (p->flags & F_CID)
        decode(p->cid, buf, len, i, 0, "%" PRIu64); // XXX: no ntohll()?

    if (p->flags & F_VERS)
        decode(p->vers.as_int, buf, len, i, 0, "0x%08x");

    if (p->flags & F_PUB_RST) {
        warn(err, "public reset");
        uint32_t tag;
        decode(tag, buf, len, i, 0, "0x%04x");
        assert(tag == prst.as_int, "PRST tag mismatch 0x%04x != 0x%04x", tag,
               prst.as_int);

        uint8_t n;
        decode(n, buf, len, i, 0, "%d");
        assert(n == 3, "got %d tags in PRST", n);
        i += n; // XXX: undocumented in draft-hamilton

        decode(tag, buf, len, i, 0, "0x%04x");
        assert(tag == rnon.as_int, "RNON tag mismatch 0x%04x != 0x%04x", tag,
               rnon.as_int);
        uint64_t val;
        decode(val, buf, len, i, 0, "0x%" PRIx64);

        decode(tag, buf, len, i, 0, "0x%04x");
        assert(tag == rseq.as_int, "RSEQ tag mismatch 0x%04x != 0x%04x", tag,
               rseq.as_int);
        decode(val, buf, len, i, 0, "0x%" PRIx64);

        decode(tag, buf, len, i, 0, "0x%04x");
        assert(tag == cadr.as_int, "CADR tag mismatch 0x%04x != 0x%04x", tag,
               cadr.as_int);
        // decode(val, buf, len, i, 0, "0x%" PRIx64);

        return i;
    }

    if (p->flags & F_NONCE) {
        p->nonce_len = (uint8_t)MIN(len - i, MAX_NONCE_LEN);
        decode(p->nonce, buf, len, i, p->nonce_len, "%s");
        assert(i <= len, "pub hdr only %d bytes; truncated?", len);
    }

    if (p->flags & F_VERS && i == len)
        // this is a version negotiation packet from the server
        return i;

    p->nr_len = dec_pkt_nr_len(p->flags);
    decode(p->nr, buf, len, i, p->nr_len, "%" PRIu64); // XXX: no ntohll()?

    if (p->flags & (F_MULTIPATH | F_UNUSED))
        die("unsupported flag set");

    if (i <= len) {
        // if there are bytes left in the packet, there must be a hash to
        // verify
        const uint128_t hash = fnv_1a(buf, len, i, HASH_LEN);
        if (memcmp(&buf[i], &hash, HASH_LEN))
            die("hash mismatch");
        else
            warn(debug, "hash OK");
        i += HASH_LEN;
        assert(i <= len, "pub hdr only %d bytes; truncated?", len);
    }

    if (i <= len)
        // if there are still bytes left, we have frames
        i += dec_frames(p, &buf[i], len - i);

    return i;
}


uint16_t __attribute__((nonnull))
enc_init_pkt(const struct q_conn * restrict const c,
             uint8_t * restrict const buf,
             const uint16_t len)
{
    buf[0] = F_CID;
    uint16_t i = 1;
    encode(buf, len, i, c->id, 0, "%" PRIu64); // XXX: no htonll()?

    // XXX: omit version to force a PRST
    if (c->state == CLOSED || vers[c->vers].as_int == 0) {
        buf[0] |= F_VERS;
        encode(buf, len, i, vers[c->vers].as_int, 0, "0x%08x");
    } else
        warn(info, "skipping version");

    if (vers[c->vers].as_int == 0) {
        warn(info, "sending version negotiation server response");
        encode(buf, len, i, vers[0].as_int, vers_len, "0x%08x"); // XXX
        return i;
    }

    buf[0] |= enc_pkt_nr_len(sizeof(uint8_t));
    encode(buf, len, i, c->out, 0, "%" PRIu64);

    const uint16_t hash_pos = i;
    i += HASH_LEN;
    assert(i <= len, "buf len %d, consumed %d", len, i);
    // i += enc_stream_frame(&buf[i], len - i);
    // assert(=i < len, "buf len %d, consumed %d", len, i);
    i += enc_padding_frame(&buf[i], len - i);
    assert(i <= len, "buf len %d, consumed %d", len, i);

    const uint128_t hash = fnv_1a(buf, i, hash_pos, HASH_LEN);
    warn(debug, "inserting %d-byte hash at pos %d", HASH_LEN, hash_pos);
    memcpy(&buf[hash_pos], &hash, HASH_LEN);

    return i;
}
