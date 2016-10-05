#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/socket.h>

#include "debug.h"
#include "fnv_1a.h"
#include "pkt.h"
#include "quic.h"
#include "version.h"

// #define BIN_PATTERN "%c%c%c%c%c%c%c%c"
// #define BIN(byte)                                                              \
//     (byte & 0x80 ? '1' : '0'), (byte & 0x40 ? '1' : '0'),                      \
//         (byte & 0x20 ? '1' : '0'), (byte & 0x10 ? '1' : '0'),                  \
//         (byte & 0x08 ? '1' : '0'), (byte & 0x04 ? '1' : '0'),                  \
//         (byte & 0x02 ? '1' : '0'), (byte & 0x01 ? '1' : '0')

static int qs = 0;


// Convert pkt nr length encoded in flags to bytes
static __attribute__((const)) uint8_t decode_nr_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x30) >> 4;
    return l ? 2 * l : 1;
}


// Convert pkt nr length in bytes into flags
static __attribute__((const)) uint8_t encode_nr_len(const uint8_t n)
{
    return (uint8_t)((n >> 1) << 4);
}


// Convert stream ID length encoded in flags to bytes
static __attribute__((const)) uint8_t decode_sid_len(const uint8_t flags)
{
    return (flags & 0x03) + 1;
}


// Convert stream offset length encoded in flags to bytes
static __attribute__((const)) uint8_t decode_stream_off_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x1C) >> 2;
    return l == 0 ? 0 : l + 1;
}


static uint16_t decode_public_hdr(struct q_pkt * const p, const bool is_initial)
{
    uint16_t i = 0;

    p->flags = p->buf[i++];
    warn(debug, "flags 0x%02x", p->flags);

    if (i >= p->len)
        die("public header length only %d", p->len);

    if (p->flags & F_CID) {
        p->cid = (*(uint64_t *)(void *)&p->buf[i]); // ntohll
        i += sizeof(p->cid);
        warn(debug, "cid %" PRIu64, p->cid);
        if (i >= p->len)
            die("public header length only %d", p->len);
    }

    if (p->flags & F_VERS) {
        p->vers = ntohl(*(uint32_t *)(void *)&p->buf[i]);
        i += sizeof(p->vers);
        const uint8_t v[5] = vers_to_ascii(p->vers);
        warn(debug, "vers 0x%08x %s", p->vers, v);
        if (i >= p->len)
            die("public header length only %d", p->len);
    }

    if (p->flags & F_NONCE) {
        p->nonce_len = (uint8_t)MIN(p->len - i, MAX_NONCE_LEN);
        warn(debug, "nonce len %d", p->nonce_len);
        hexdump(&p->buf[i], p->nonce_len);

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
            // return i;
        }

        i += p->nonce_len;
        if (i >= p->len)
            die("public header length only %d", p->len);
    }

    const uint8_t nr_len = decode_nr_len(p->flags);
    warn(debug, "nr_len %d", nr_len);

    memcpy(&p->nr, &p->buf[i], nr_len);
    warn(debug, "nr %" PRIu64, p->nr);
    i += nr_len;
    if (i >= p->len)
        die("public header length only %d", p->len);

    if (p->flags & F_MULTIPATH)
        warn(warn, "flag multipath");

    if (p->flags & F_UNUSED)
        warn(err, "flag unused");

    warn(debug, "i %d, len %d", i, p->len);
    // hexdump(p->buf, p->len);
    if (is_initial && (p->flags & F_PUB_RST) == 0) {
        p->hash = fnv_1a(p, i, HASH_LEN);
        if (memcmp(&p->buf[i], &p->hash, HASH_LEN)) {
            die("hash mismatch");
        }
    }

    return i;
}


static uint16_t encode_public_hdr(struct q_pkt * const p)
{
    uint16_t i = 0;

    p->buf[i++] = p->flags;

    if (p->flags & F_CID) {
        *(uint64_t *)((void *)&p->buf[i]) = htonll(p->cid);
        warn(debug, "cid %" PRIu64, p->cid);
        i += sizeof(p->cid);
    }

    if (p->flags & F_VERS) {
        *(uint32_t *)((void *)&p->buf[i]) = htonl(p->vers);
        const uint8_t v[5] = vers_to_ascii(p->vers);
        warn(debug, "vers 0x%08x %s", p->vers, v);
        i += sizeof(p->vers);
    }

    const uint8_t nr_len = 1;
    *(uint8_t *)((void *)&p->buf[i]) = (uint8_t)p->nr;
    p->buf[0] |= encode_nr_len(nr_len);
    warn(debug, "%d-byte nr %d", nr_len, (uint8_t)p->nr);
    i += sizeof(uint8_t);

    return i;
}


// static uint16_t encode_stream_frame(const uint32_t id,
//                                     const uint64_t off,
//                                     const uint16_t data_len,
//                                     struct q_pkt * const p)
// {
//     uint16_t i = 0;

//     p->buf[i++] = F_STREAM;
//     if (p->len - i - sizeof(uint32_t) > 0) {
//         *(uint32_t *)((void *)&p[i]) = htonl(id);
//         warn(debug, "4-byte id %d", id);
//         p->buf[0] |= encode_sid_len_flags(4);
//         i += sizeof(uint32_t);
//     } else
//         die("cannot encode id");

//     if (p->len - i - sizeof(uint64_t) > 0) {
//         *(uint64_t *)((void *)&p[i]) = htonl(off);
//         warn(debug, "8-byte off %"PRIu64, off);
//         p->buf[0] |= encode_stream_off_len_flags(8);
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


static uint16_t decode_stream_frame(struct q_pkt * const p,
                                    const uint16_t             pos)
{
    uint16_t i = pos;

    struct q_stream_frame * f = calloc(1, sizeof(struct q_stream_frame));
    f->type = p->buf[i++];

    warn(debug, "stream type %02x", f->type);

    const uint8_t slen = decode_sid_len(f->type);
    if (slen) {
        memcpy(&f->sid, &p->buf[i], slen);
        i += slen;
        warn(debug, "%d-byte sid %d", slen, f->sid);
    }

    const uint8_t off_len = decode_stream_off_len(f->type);
    if (off_len) {
        memcpy(&f->off, &p->buf[i], off_len);
        i += off_len;
        warn(debug, "%d-byte off %" PRIu64, off_len, f->off);
    }

    if (f->type & F_STREAM_DATA_LEN) {
        f->dlen = *(const uint16_t *)(const void *)&p->buf[i];
        i += sizeof(f->dlen);
        warn(debug, "dlen %d", f->dlen);
        // keep a pointer to the frame data around
        f->data = &p->buf[i];

        // TODO check that FIN is 0
        /// XXX skipping content

        i += f->dlen;
    }

    // add this frame to the packet's list of frames
    SLIST_INSERT_HEAD(&p->fl, (struct q_frame *)f, next);
    return i;
}


static uint16_t decode_ack_frame(const struct q_pkt * const p,
                                 const uint16_t             pos)
{
    warn(debug, "here at %d", pos);
    return p->len;
}


static uint16_t decode_regular_frame(const struct q_pkt * const p,
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
        const uint8_t nr_len = decode_nr_len(p->flags);
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


static uint16_t decode_frames(struct q_pkt * const p, const uint16_t pos)
{
    uint16_t i = pos;
    SLIST_INIT(&p->fl);
    while (i < p->len)
        if (p->flags & F_STREAM)
            i += decode_stream_frame(p, i);
        else if (p->buf[0] & (!F_STREAM | F_ACK))
            i += decode_ack_frame(p, i);
        else
            i += decode_regular_frame(p, i);
    return i;
}


void q_connect(const int s)
{
    if (qs)
        die("can only handle a single connection");
    qs = s;

    struct q_pkt p = {
        .flags = F_VERS | F_CID, .vers = quic_vers, .cid = 0xDECAFBAD, .nr = 1};
    p.len = encode_public_hdr(&p);
    warn(debug, "pub hdr len %d", p.len);

    // leave space for hash
    const uint16_t hash_pos = p.len;
    p.len += HASH_LEN;

    // char data[] = "GET /";
    // p.len += encode_stream_frame(1, 0, (uint16_t)strlen(data), p + len,
    //                                 MAX_PKT_LEN - len);
    // memcpy(p + len, "GET /", strlen(data));
    // len += strlen(data);

    p.hash = fnv_1a(&p, hash_pos, HASH_LEN);
    memcpy(&p.buf[hash_pos], &p.hash, HASH_LEN);
    warn(debug, "inserted %d-byte hash at pos %d", HASH_LEN, hash_pos);

    ssize_t n = send(s, p.buf, p.len, 0);
    if (n < 0)
        die("send");
    warn(debug, "sent %ld bytes", n);

    struct pollfd fds = {.fd = s, .events = POLLIN};
    do {
        n = poll(&fds, 1, 1000);
        if (n < 0)
            die("poll");
    } while (n == 0);

    p.len = (uint16_t)recv(s, p.buf, MAX_PKT_LEN, 0);
    if (p.len < 0)
        die("recv");

    warn(debug, "received %d bytes, decoding", p.len);
    decode_public_hdr(&p, true);
    // decode_frames(p, len, &hdr);

    if (p.flags & F_VERS) {
        const uint8_t v[5] = vers_to_ascii(quic_vers);
        die("server didn't accept our vers 0x%08x %s", quic_vers, v);
    }
}


void q_serve(const int s)
{
    if (qs)
        die("can only handle a single connection");
    qs = s;

    struct pollfd fds = {.fd = s, .events = POLLIN};
    ssize_t       n;
    do {
        n = poll(&fds, 1, 1000);
        if (n < 0)
            die("poll");
    } while (n == 0);

    struct q_pkt p;
    p.len = (uint16_t)recv(s, p.buf, MAX_PKT_LEN, 0);
    if (p.len < 0)
        die("recv");
    warn(debug, "received %d bytes, decoding", p.len);
    uint16_t pos = decode_public_hdr(&p, true);

    char h[HASH_LEN * 2 + 1] = "";
    for (uint8_t i = 0; i < HASH_LEN; i++)
        snprintf(&h[i * 2], 2 * (HASH_LEN - i + 1), "%02x", p.buf[pos + i]);
    warn(debug, "hash %s", h);

    p.hash = fnv_1a(&p, pos, HASH_LEN);
    if (memcmp(&p.buf[pos], &p.hash, HASH_LEN))
        die("hash error");
    else
        warn(debug, "hash verified OK");
    pos += HASH_LEN;

    decode_frames(&p, pos);
}
