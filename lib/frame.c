#include <inttypes.h>
#include <sys/param.h>

#include "frame.h"
#include "pkt.h"
#include "util.h"


// Convert stream ID length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_sid_len(const uint8_t flags)
{
    const uint8_t l = flags & 0x03;
    assert(/*l >= 0 && */ l <= 3, "cannot decode stream ID length %d", l);
    static const uint8_t dec[] = {1, 2, 3, 4};
    return dec[l];
}


// Convert stream ID length encoded in bytes to flags
static uint8_t __attribute__((const)) enc_sid_len(const uint8_t n)
{
    assert(n >= 1 && n <= 4, "cannot decode stream ID length %d", n);
    static const uint8_t enc[] = {0xFF, 0, 1, 2, 3}; // 0xFF invalid
    return enc[n];
}


// Convert stream offset length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_off_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x1C) >> 2;
    assert(/* l >= 0 && */ l <= 7, "cannot decode stream offset length %d", l);
    static const uint8_t dec[] = {0, 2, 3, 4, 5, 6, 7, 8};
    return dec[l];
}


// Convert stream offset length encoded in bytes to flags
static uint8_t __attribute__((const)) enc_off_len(const uint8_t n)
{
    assert(n != 1 && n <= 8, "cannot stream encode offset length %d", n);
    static const uint8_t enc[] = {0, 0xFF, 1, 2, 3, 4, 5, 6, 7}; // 0xFF invalid
    return (uint8_t)(enc[n] << 2);
}


// Convert largest ACK length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_lg_ack_len(const uint8_t flags)
{
    const uint8_t l = (flags & 0x0C) >> 2;
    assert(/* l >= 0 && */ l <= 3, "cannot decode largest ACK length %d", l);
    static const uint8_t dec[] = {1, 2, 3, 4};
    return dec[l];
}


// Convert ACK block length encoded in flags to bytes
static uint8_t __attribute__((const)) dec_ack_block_len(const uint8_t flags)
{
    const uint8_t l = flags & 0x03;
    assert(/*l >= 0 && */ l <= 3, "cannot decode largest ACK length %d", l);
    static const uint8_t dec[] = {1, 2, 4, 6};
    return dec[l];
}


static uint16_t __attribute__((nonnull))
dec_stream_frame(struct q_pkt * restrict const p __attribute__((unused)),
                 const uint8_t * restrict const buf,
                 const uint16_t len)
{
    uint16_t i = 1;
    assert(i < len, "buf too short");

    struct q_stream_frame * f = calloc(1, sizeof(*f));
    assert(f, "could not calloc");
    f->type = buf[0];

    warn(debug, "fin = %d", f->type & F_STREAM_FIN);

    const uint8_t sid_len = dec_sid_len(f->type);
    if (sid_len)
        decode(f->sid, buf, len, i, sid_len, "%d");

    const uint8_t off_len = dec_off_len(f->type);
    if (off_len)
        decode(f->off, buf, len, i, off_len, "%" PRIu64);

    if (f->type & F_STREAM_DATA_LEN) {
        decode(f->dlen, buf, len, i, 0, "%d");

        // keep a pointer to the frame data around
        f->data = &buf[i];

        // TODO check that FIN is 0
        // XXX skipping content

        i += f->dlen;
    }

    return i;
}


static uint16_t __attribute__((nonnull))
dec_ack_frame(const struct q_pkt * restrict const p __attribute__((unused)),
              const uint8_t * restrict const buf,
              const uint16_t len)
{
    uint16_t i = 1;
    assert(i < len, "buf too short");

    struct q_ack_frame * f = calloc(1, sizeof(*f));
    assert(f, "could not calloc");
    f->type = buf[0];

    assert((f->type & F_ACK_UNUSED) == 0, "unused ACK frame bit set");

    const uint8_t lg_ack_len = dec_lg_ack_len(f->type);
    decode(f->lg_ack, buf, len, i, lg_ack_len, "%" PRIu64);

    // TODO: support the weird float format they've defined
    decode(f->lg_ack_delta_t, buf, len, i, 0, "%d");

    const uint8_t ack_block_len = dec_ack_block_len(f->type);
    warn(debug, "%d-byte ACK block length", ack_block_len);

    if (f->type & F_ACK_N) {
        decode(f->ack_blocks, buf, len, i, 0, "%d");
        f->ack_blocks++; // NOTE: draft-hamilton says +1
    } else {
        f->ack_blocks = 1;
        warn(debug, "F_ACK_N unset; one ACK block present");
    }

    for (uint8_t b = 0; b < f->ack_blocks; b++) {
        // TODO: create structure for this in q_pkt
        warn(debug, "decoding ACK block #%d", b);
        uint64_t l = 0;
        decode(l, buf, len, i, ack_block_len, "%" PRIu64);
        uint8_t gap;
        decode(gap, buf, len, i, 0, "%d");
    }

    // memcpy(&f->ts_blocks, &buf[i], sizeof(f->ts_blocks));
    // warn(debug, "%d timestamp blocks", f->ts_blocks);
    // i += sizeof(f->ts_blocks);
    // for (uint8_t b = 0; b < f->ts_blocks; b++) {
    //     warn(debug, "decoding timestamp block #%d", b);
    //     uint8_t delta_lg_obs;
    //     memcpy(&delta_lg_obs, &buf[i], sizeof(delta_lg_obs));
    //     warn(debug, "delta_lg_obs %d", delta_lg_obs);
    //     i += sizeof(delta_lg_obs);

    //     uint32_t ts;
    //     memcpy(&ts, &buf[i], sizeof(ts));
    //     warn(debug, "ts %d", ts);
    //     i += sizeof(ts);
    // }


    return i;
}


static uint16_t __attribute__((nonnull))
dec_stop_waiting_frame(const struct q_pkt * restrict const p,
                       const uint8_t * restrict const buf,
                       const uint16_t len)
{
    uint16_t i = 1;
    assert(i < len, "buf too short");

    struct q_stop_waiting_frame * f = calloc(1, sizeof(*f));
    assert(f, "could not calloc");
    f->type = buf[0];

    decode(f->lst_unacked, buf, len, i, p->nr_len, "%" PRIu64);
    return i;
}


static uint16_t __attribute__((nonnull))
dec_conn_close_frame(const struct q_pkt * restrict const p
                     __attribute__((unused)),
                     const uint8_t * restrict const buf,
                     const uint16_t len)
{
    uint16_t i = 1;
    assert(i < len, "buf too short");

    struct q_conn_close_frame * f = calloc(1, sizeof(*f));
    assert(f, "could not calloc");
    f->type = buf[0];

    decode(f->err, buf, len, i, 0, "%d");
    decode(f->reason_len, buf, len, i, 0, "%d");

    if (f->reason_len) {
        f->reason = calloc(1, f->reason_len);
        assert(f->reason, "could not calloc");
        decode(*f->reason, buf, len, i, f->reason_len, "%d"); // XXX: ugly
        warn(err, "%s", f->reason);
    }

    return i;
}


uint16_t __attribute__((nonnull)) dec_frames(struct q_pkt * restrict const p,
                                             const uint8_t * restrict const buf,
                                             const uint16_t len)
{
    uint16_t i = 0;

    while (i < len) {
        const uint8_t flags = buf[i];
        warn(debug, "frame type 0x%02x, start pos %d", flags, i);
        if (flags & F_STREAM) {
            i += dec_stream_frame(p, &buf[i], len - i);
            continue;
        }
        if (flags & F_ACK) {
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
            i += dec_conn_close_frame(p, &buf[i], len - i);
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
            i += dec_stop_waiting_frame(p, &buf[i], len - i);
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
enc_stream_frame(uint8_t * restrict const buf, const uint16_t len)
{
    buf[0] = F_STREAM;
    uint16_t i = 1;
    assert(i < len, "buf too short");

    const uint32_t dummy_id = 1;
    memcpy(&buf[i], &dummy_id, sizeof(dummy_id));
    warn(debug, "%zu-byte id %d", sizeof(dummy_id), dummy_id);
    buf[0] |= enc_sid_len(sizeof(dummy_id));
    i += sizeof(dummy_id);
    assert(i < len, "buf too short");

    const uint16_t dummy_dl = 0;
    memcpy(&buf[i], &dummy_dl, sizeof(dummy_dl));
    warn(debug, "%zu-byte dl %d", sizeof(dummy_dl), dummy_dl);
    buf[0] |= F_STREAM_DATA_LEN;
    i += sizeof(dummy_dl);
    assert(i < len, "buf too short");

    const uint64_t dummy_off = 0;
    memcpy(&buf[i], &dummy_off, sizeof(dummy_off));
    const uint8_t off_len = enc_off_len(sizeof(dummy_off));
    warn(debug, "%zu-byte off %" PRIu64 " encoded as 0x%0x", sizeof(dummy_off),
         dummy_off, off_len);
    buf[0] |= off_len;
    i += sizeof(dummy_off);
    assert(i < len, "buf too short");

    buf[0] |= F_STREAM_FIN;

    // TODO: FIN bit and offset

    return i;
}


uint16_t __attribute__((nonnull))
enc_padding_frame(uint8_t * restrict const buf, const uint16_t len)
{
    buf[0] = T_PADDING;
    memset(&buf[1], 0, len - 1);
    warn(debug, "inserting %d bytes of zero padding", len - 1);
    return len;
}
