
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include "debug.h"
#include "fnv_1a.h"
#include "pkt.h"
#include "quic.h"

// #define BIN_PATTERN "%c%c%c%c%c%c%c%c"
// #define BIN(byte)                                                              \
//     (byte & 0x80 ? '1' : '0'), (byte & 0x40 ? '1' : '0'),                      \
//         (byte & 0x20 ? '1' : '0'), (byte & 0x10 ? '1' : '0'),                  \
//         (byte & 0x08 ? '1' : '0'), (byte & 0x04 ? '1' : '0'),                  \
//         (byte & 0x02 ? '1' : '0'), (byte & 0x01 ? '1' : '0')

static int qs = 0;


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
