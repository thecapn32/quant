#include <inttypes.h>
#include <sys/param.h>

#include "fnv_1a.h"
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


// Convert stream ID length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_sid_len(const uint8_t flags)
{
    return ((flags & 0x06) >> 1) + 1;
}


// Convert stream offset length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_stream_off_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x1C) >> 2;
    return l == 0 ? 0 : l + 1;
}


static uint16_t __attribute__((nonnull))
dec_stream_frame(struct q_pkt * const p __attribute__((unused)),
                 const uint8_t * restrict const buf,
                 const uint16_t len __attribute__((unused)))
{
    uint16_t i = 1;

    struct q_stream_frame * f = calloc(1, sizeof(*f));
    assert(f, "could not calloc");
    f->type = buf[0];

    warn(debug, "stream type %02x", f->type);

    warn(debug, "fin %d", f->type & F_STREAM_FIN);

    const uint8_t slen = dec_sid_len(f->type);
    if (slen) {
        memcpy(&f->sid, &buf[i], slen);
        i += slen;
        warn(debug, "%d-byte sid %d", slen, f->sid);
    }

    const uint8_t off_len = dec_stream_off_len(f->type);
    if (off_len) {
        memcpy(&f->off, &buf[i], off_len);
        i += off_len;
        warn(debug, "%d-byte off %" PRIu64, off_len, f->off);
    }

    if (f->type & F_STREAM_DATA_LEN) {
        memcpy(&f->dlen, &buf[i], sizeof(f->dlen));
        i += sizeof(f->dlen);
        warn(debug, "dlen %d", f->dlen);
        // keep a pointer to the frame data around
        f->data = &buf[i];

        // TODO check that FIN is 0
        // XXX skipping content

        i += f->dlen;
    }

    // add this frame to the packet's list of frames
    // SLIST_INSERT_HEAD(&p->fl, (struct q_frame *)f, next);
    return i;
}


static uint16_t __attribute__((nonnull))
dec_ack_frame(const struct q_pkt * const p __attribute__((unused)),
              const uint8_t * restrict const buf __attribute__((unused)),
              const uint16_t len)
{
    die("here at %d", len);
    return len;
}


static uint16_t __attribute__((nonnull))
dec_frames(struct q_pkt * const p,
           const uint8_t * restrict const buf,
           const uint16_t len)
{
    uint16_t i = 0;
    // SLIST_INIT(&p->fl);

    while (i < len) {
        const uint8_t flags = buf[i];
        warn(debug, "frame 0x%02x, %d %d", flags, i, len);
        if (flags & F_STREAM) {
            i += dec_stream_frame(p, &buf[i], len - i);
            continue;
        }
        if (flags & ((!F_STREAM) | F_ACK)) {
            i += dec_ack_frame(p, &buf[i], len - i);
            continue;
        }

        switch (flags) {
        case T_PADDING:
            warn(debug, "%d-byte padding frame", len - i);
            static const uint8_t zero[MAX_PKT_LEN] = {0};
            assert(memcmp(&buf[i], zero, len - i) == 0,
                   "%d-byte padding not zero", len - i);
            i = len;
            break;

        case T_RST_STREAM:
            die("rst_stream frame");
            break;
        case T_CONNECTION_CLOSE:
            die("connection_close frame");
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
            die("stop_waiting frame");
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

    if (i <= len) {
        warn(debug, "frames frames frames");
        // if there are still bytes left, we have frames
        i += dec_frames(p, &buf[i], len - i);
    }

    return i;
}


// static uint16_t enc_stream_frame(const uint32_t id,
//                                     const uint64_t off,
//                                     const uint16_t data_len,
//                                     struct q_pkt * const p)
// {
//     uint16_t i = 0;

//     p->buf[i++] = F_STREAM;
//     if (p->len - i - sizeof(uint32_t) > 0) {
//         *(uint32_t *)((void *)&p[i]) = htonl(id);
//         warn(debug, "4-byte id %d", id);
//         p->buf[0] |= enc_sid_len_flags(4);
//         i += sizeof(uint32_t);
//     } else
//         die("cannot encode id");

//     if (p->len - i - sizeof(uint64_t) > 0) {
//         *(uint64_t *)((void *)&p[i]) = htonl(off);
//         warn(debug, "8-byte off %"PRIu64, off);
//         p->buf[0] |= enc_stream_off_len_flags(8);
//         i += sizeof(uint64_t);
//     } else
//         die("cannot encode off");

//     if (p->len - i - sizeof(uint16_t) > 0) {
//         *(uint16_t *)((void *)&p[i]) = htons(data_len);
//         warn(debug, "2-byte data_len %d", data_len);
//         p->buf[0] |= F_STREAM_DATA_LEN;
//         i += sizeof(uint16_t);
//     } else
//         die("cannot encode data_len");

//     // XXX FIN bit

//     return i;
// }


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
