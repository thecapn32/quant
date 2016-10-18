#include <inttypes.h>
#include <sys/param.h>

#include "fnv_1a.h"
#include "frame.h"
#include "pkt.h"
#include "util.h"


// Convert pkt nr length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_nr_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x30) >> 4;
    return l ? 2 * l : 1;
}


// Convert pkt nr length in bytes into flags
static uint8_t __attribute__((const)) enc_nr_len(const uint8_t n)
{
    return (uint8_t)((n >> 1) << 4);
}


uint16_t __attribute__((nonnull))
dec_pub_hdr(struct q_pkt * restrict const p,
            const uint8_t * restrict const buf,
            const uint16_t len)
{
    uint16_t i = 0;

    p->flags = buf[i++];
    warn(debug, "flags 0x%02x", p->flags);
    assert(i <= len, "pub hdr only %d bytes; truncated?", len);

    if (p->flags & F_CID) {
        memcpy(&p->cid, &buf[i], sizeof(p->cid)); // XXX: no ntohll()?
        i += sizeof(p->cid);
        warn(debug, "cid %" PRIu64, p->cid);
        assert(i <= len, "pub hdr only %d bytes; truncated?", len);
    }

    if (p->flags & F_VERS) {
        memcpy(&p->vers.as_int, &buf[i],
               sizeof(p->vers)); // no need for ntohl()
        i += sizeof(p->vers);
        warn(debug, "vers 0x%08x %.4s", p->vers.as_int, p->vers.as_str);
        assert(i <= len, "pub hdr only %d bytes; truncated?", len);
    }

    if (p->flags & F_NONCE) {
        p->nonce_len = (uint8_t)MIN(len - i, MAX_NONCE_LEN);
        warn(debug, "nonce len %d %.*s", p->nonce_len, p->nonce_len,
             (const char *)&buf[i]);
        memcpy(p->nonce, &buf[i], p->nonce_len);
        i += p->nonce_len;
        assert(i <= len, "pub hdr only %d bytes; truncated?", len);
    }

    if (p->flags & F_PUB_RST)
        warn(err, "public reset");

    const uint8_t nr_len = dec_nr_len(p->flags);
    warn(debug, "nr_len %d", nr_len);

    memcpy(&p->nr, &buf[i], nr_len); // XXX: no ntohll()?
    warn(debug, "nr %" PRIu64, p->nr);
    i += nr_len;

    if (p->flags & (F_MULTIPATH | F_UNUSED))
        warn(warn, "unsupported flag encountered");

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
    memcpy(&buf[i], &c->id, sizeof(c->id)); // XXX: no htonll()?
    warn(debug, "cid %" PRIu64, c->id);
    i += sizeof(c->id);
    assert(i < len, "buf too short");

    if (vers[c->vers].as_int || c->state == VERS_RECV) {
        buf[0] |= F_VERS;
        const uint8_t v = vers[c->vers].as_int ? c->vers : 0;
        memcpy(&buf[i], &vers[v].as_int, sizeof(vers[v]));
        warn(debug, "vers 0x%08x %.4s", vers[v].as_int, vers[v].as_str);
        i += sizeof(vers[v]);
        assert(i < len, "buf too short");
    }

    buf[0] |= enc_nr_len(sizeof(uint8_t));
    buf[i] = (uint8_t)c->out;
    warn(debug, "%zu-byte nr %d", sizeof(uint8_t), (uint8_t)c->out);
    i += sizeof(uint8_t);
    assert(i < len, "buf too short");

    if (vers[c->vers].as_int == 0 && c->state == VERS_RECV &&
        sizeof(vers) / sizeof(vers[0]) > 0) {
        const uint8_t l = sizeof(vers) - sizeof(vers[0].as_int);
        warn(debug, "nonce len %d %.*s", l, l, (const char *)&vers[1].as_int);
        memcpy(&buf[i], &vers[1].as_int, l);
        i += l;
        assert(i < len, "buf too short");
        // version negotiation response ends here (no hash)
        return i;
    }

    const uint128_t hash = fnv_1a(buf, i + HASH_LEN, i, HASH_LEN);
    warn(debug, "inserting %d-byte hash at pos %d", HASH_LEN, i);
    memcpy(&buf[i], &hash, HASH_LEN);
    i += HASH_LEN;
    assert(i < len, "buf too short");

    return i;
}
