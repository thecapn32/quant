#include <inttypes.h>
#include <sys/param.h>

#include "frame.h"
#include "pkt.h"
#include "util.h"


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


uint16_t __attribute__((nonnull)) dec_frames(struct q_pkt * const p,
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
