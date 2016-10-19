#include <inttypes.h>
#include <stdbool.h>
#include <sys/param.h>

#include "fnv_1a.h"
#include "frame.h"
#include "pkt.h"
#include "quic.h"
#include "util.h"


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

    if (p->flags & F_NONCE) {
        p->nonce_len = (uint8_t)MIN(len - i, MAX_NONCE_LEN);
        decode(p->nonce, buf, len, i, p->nonce_len, "%s");
        assert(i <= len, "pub hdr only %d bytes; truncated?", len);
    }

    if (p->flags & F_PUB_RST)
        warn(err, "public reset");

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
        hexdump(&buf[i], HASH_LEN);
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
    memcpy(&buf[i], &c->id, sizeof(c->id)); // XXX: no htonll()?
    warn(debug, "cid %" PRIu64, c->id);
    i += sizeof(c->id);
    assert(i <= len, "buf len %d, consumed %d", len, i);

    if (vers[c->vers].as_int || c->state == VERS_RECV) {
        buf[0] |= F_VERS;
        const uint8_t v = vers[c->vers].as_int ? c->vers : 0;
        memcpy(&buf[i], &vers[v].as_int, sizeof(vers[v]));
        warn(debug, "vers 0x%08x %.4s", vers[v].as_int, vers[v].as_str);
        i += sizeof(vers[v]);
        assert(i <= len, "buf len %d, consumed %d", len, i);
        if (c->state == VERS_RECV) {
            // TODO: omit version included in the version field above from the
            // nonce
            warn(debug, "nonce len %zu %.*s", vers_len, (int)vers_len,
                 (const char *)&vers[0].as_int);
            memcpy(&buf[i], &vers[0].as_int, vers_len);
            i += vers_len;
            assert(i <= len, "buf len %d, consumed %d", len, i);
            // version negotiation response ends here (no hash)
            return i;
        }
    }

    buf[0] |= enc_pkt_nr_len(sizeof(uint8_t));
    buf[i] = (uint8_t)c->out;
    warn(debug, "%zu-byte nr %d", sizeof(uint8_t), (uint8_t)c->out);
    i += sizeof(uint8_t);
    assert(i <= len, "buf len %d, consumed %d", len, i);

    const uint16_t hash_pos = i;
    i += HASH_LEN;
    assert(i <= len, "buf len %d, consumed %d", len, i);
    // i += enc_stream_frame(&buf[i], len - i);
    // assert(=i < len, "buf len %d, consumed %d", len, i);
    i += enc_padding_frame(&buf[i], len - i);
    assert(i <= len, "buf len %d, consumed %d", len, i);

    const uint128_t hash = fnv_1a(buf, i, hash_pos, HASH_LEN);
    warn(debug, "inserting %d-byte hash at pos %d", HASH_LEN, hash_pos);
    hexdump(&hash, HASH_LEN);
    memcpy(&buf[hash_pos], &hash, HASH_LEN);

    return i;
}
