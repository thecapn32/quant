#include <inttypes.h>
#include <sys/param.h>

#include "fnv_1a.h"
#include "pkt.h"
#include "util.h"


// Convert pkt nr length encoded in flags to bytes
uint8_t dec_nr_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x30) >> 4;
    return l ? 2 * l : 1;
}


// Convert pkt nr length in bytes into flags
uint8_t enc_nr_len(const uint8_t n)
{
    return (uint8_t)((n >> 1) << 4);
}


// Convert stream ID length encoded in flags to bytes
uint8_t dec_sid_len(const uint8_t flags)
{
    return (flags & 0x03) + 1;
}


// Convert stream offset length encoded in flags to bytes
uint8_t dec_stream_off_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x1C) >> 2;
    return l == 0 ? 0 : l + 1;
}


uint16_t dec_pub_hdr(struct q_pkt * const p)
{
    uint16_t i = 0;
    // assert(i <= p->len);

    p->flags = p->buf[i++];
    warn(debug, "flags 0x%02x", p->flags);
    assert(i <= p->len, "pub hdr only %d bytes; truncated?", p->len);

    if (p->flags & F_CID) {
        memcpy(&p->cid, &p->buf[i], sizeof(p->cid)); // XXX: no ntohll()?
        i += sizeof(p->cid);
        warn(debug, "cid %" PRIu64, p->cid);
        assert(i <= p->len, "pub hdr only %d bytes; truncated?", p->len);
    }

    if (p->flags & F_VERS) {
        memcpy(&p->vers, &p->buf[i], sizeof(p->vers)); // no need for ntohl()
        i += sizeof(p->vers);
        warn(debug, "vers 0x%08x %.4s", p->vers, (char *)&p->vers);
        assert(i <= p->len, "pub hdr only %d bytes; truncated?", p->len);
    }

    if (p->flags & F_NONCE) {
        p->nonce_len = (uint8_t)MIN(p->len - i, MAX_NONCE_LEN);
        warn(debug, "nonce len %d %.*s", p->nonce_len, p->nonce_len,
             (char *)&p->buf[i]);

        if (p->flags & F_PUB_RST) {
            warn(err, "public reset");
            // interpret public reset packet
            if (memcmp("PRST", &p->buf[i], 4) == 0) {
                const uint32_t tag_len = *&p->buf[i + 4];
                warn(debug, "PRST with %d tags", tag_len);
                i += 8;

                for (uint32_t t = 0; t < tag_len; t++) {
                    char tag[5];
                    memcpy(tag, &p->buf[i], 4);
                    tag[4] = 0;
                    uint64_t value = *&p->buf[i + 4];
                    i += 8;
                    warn(debug, "%s = %" PRIu64, tag, value);
                }

            } else
                die("cannot parse PRST");
        }

        i += p->nonce_len;
        assert(i <= p->len, "pub hdr only %d bytes; truncated?", p->len);
    }

    const uint8_t nr_len = dec_nr_len(p->flags);
    warn(debug, "nr_len %d", nr_len);

    memcpy(&p->nr, &p->buf[i], nr_len); // XXX: no ntohll()?
    warn(debug, "nr %" PRIu64, p->nr);
    i += nr_len;

    if (p->flags & (F_MULTIPATH | F_UNUSED))
        warn(warn, "unsupported flag encountered");

    // Version negotiation from a server don't have a hash, nor do public reset
    // packets
    // if (!(qc->r_nr == 0 && p->flags & F_VERS) && (p->flags & F_PUB_RST) == 0)
    // {
    //     const uint128_t hash = fnv_1a(p->buf, p->len, i, HASH_LEN);
    //     if (memcmp(&p->buf[i], &hash, HASH_LEN))
    //         die("hash mismatch");
    //     i += HASH_LEN;
    //     assert(i <= p->len, "pub hdr only %d bytes; truncated?", p->len);
    // }

    return i;
}


uint16_t enc_pub_hdr(struct q_pkt * const p)
{
    uint16_t i = 0;

    p->buf[i++] = p->flags;

    if (p->flags & F_CID) {
        memcpy(&p->buf[i], &p->cid, sizeof(p->cid)); // XXX: no htonll()?
        warn(debug, "cid %" PRIu64, p->cid);
        i += sizeof(p->cid);
    }

    if (p->flags & F_VERS) {
        memcpy(&p->buf[i], &p->vers, sizeof(p->vers));
        warn(debug, "vers 0x%08x %.4s", p->vers, (const char *)&p->vers);
        i += sizeof(p->vers);
    }

    const uint8_t nr_len = 1;
    p->buf[i] = (uint8_t)p->nr;
    p->buf[0] |= enc_nr_len(nr_len);
    warn(debug, "%d-byte nr %d", nr_len, (uint8_t)p->nr);
    i += sizeof(uint8_t);

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


static uint16_t dec_stream_frame(struct q_pkt * const p, const uint16_t pos)
{
    uint16_t i = pos;

    struct q_stream_frame * f = calloc(1, sizeof(*f));
    assert(f, "could not calloc");
    f->type = p->buf[i++];

    warn(debug, "stream type %02x", f->type);

    const uint8_t slen = dec_sid_len(f->type);
    if (slen) {
        memcpy(&f->sid, &p->buf[i], slen);
        i += slen;
        warn(debug, "%d-byte sid %d", slen, f->sid);
    }

    const uint8_t off_len = dec_stream_off_len(f->type);
    if (off_len) {
        memcpy(&f->off, &p->buf[i], off_len);
        i += off_len;
        warn(debug, "%d-byte off %" PRIu64, off_len, f->off);
    }

    if (f->type & F_STREAM_DATA_LEN) {
        memcpy(&f->dlen, &p->buf[i], sizeof(f->dlen));
        i += sizeof(f->dlen);
        warn(debug, "dlen %d", f->dlen);
        // keep a pointer to the frame data around
        f->data = &p->buf[i];

        // TODO check that FIN is 0
        // XXX skipping content

        i += f->dlen;
    }

    // add this frame to the packet's list of frames
    SLIST_INSERT_HEAD(&p->fl, (struct q_frame *)f, next);
    return i;
}


static uint16_t dec_ack_frame(const struct q_pkt * const p, const uint16_t pos)
{
    warn(debug, "here at %d", pos);
    return p->len;
}


static uint16_t dec_regular_frame(const struct q_pkt * const p,
                                  const uint16_t             pos)
{
    uint16_t i = pos;

    warn(debug, "here at %d", i);

    switch (p->buf[i]) {
    case T_PADDING:
        warn(debug, "padding frame");
        break;
    case T_RST_STREAM:
        warn(debug, "rst_stream frame");
        break;
    case T_CONNECTION_CLOSE:
        warn(debug, "connection_close frame");
        break;
    case T_GOAWAY:
        warn(debug, "goaway frame");
        break;
    case T_WINDOW_UPDATE:
        warn(debug, "window_update frame");
        break;
    case T_BLOCKED:
        warn(debug, "blocked frame");
        break;

    case T_STOP_WAITING: {
        uint64_t      delta = 0;
        const uint8_t nr_len = dec_nr_len(p->flags);
        memcpy(&delta, &p->buf[i], nr_len);
        warn(debug, "stop_waiting frame, delta %" PRIu64, p->nr - delta);
        i += nr_len;
        break;
    }

    case T_PING:
        warn(debug, "ping frame");
        break;
    default:
        die("unknown frame type 0x%02x", p->buf[0]);
    }

    return i;
}


uint16_t dec_frames(struct q_pkt * const p, const uint16_t pos)
{
    uint16_t i = pos;
    SLIST_INIT(&p->fl);
    while (i < p->len)
        if (p->flags & F_STREAM)
            i += dec_stream_frame(p, i);
        else if (p->buf[0] & ((!F_STREAM) | F_ACK))
            i += dec_ack_frame(p, i);
        else
            i += dec_regular_frame(p, i);

    return i;
}
