#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include "debug.h"
#include "fnv_1a.h"
#include "pkt.h"
#include "quic.h"


#define Q_TIMEOUT 3000

#define VERS_UINT32_T(v) (*(const uint32_t *)(const void *)(v))

const char * const q_vers[] = {"Q025", "Q036", 0};


static void q_pollin(const int s)
{
    struct pollfd fds = {.fd = s, .events = POLLIN};
    const int     n = poll(&fds, 1, Q_TIMEOUT);
    if (n <= 0)
        die("poll timeout");
}


static void q_send(const int s, struct q_pkt * const p, const uint16_t hash_pos)
{
    const uint128_t hash = fnv_1a(p->buf, p->len, hash_pos, HASH_LEN);
    memcpy(&p->buf[hash_pos], &hash, HASH_LEN);
    const ssize_t n = send(s, p->buf, p->len, 0);
    if (n < 0)
        die("send");
    warn(debug, "sent %ld bytes", n);
}


static void q_recv(const int s, struct q_pkt * const p)
{
    p->len = (uint16_t)recv(s, p->buf, MAX_PKT_LEN, 0);
    if (p->len < 0)
        die("recv");
    warn(debug, "received %d bytes, decoding", p->len);
    uint16_t pos = dec_pub_hdr(p, true);
    dec_frames(p, pos);
}


void q_connect(const int s)
{
    uint8_t i = 0;

    while (q_vers[i]) {
        struct q_pkt p = {.flags = F_VERS | F_CID,
                          .vers = VERS_UINT32_T(q_vers[i]),
                          .cid = 1,
                          .nr = 1};
        p.len = enc_pub_hdr(&p);

        // leave space for hash
        const uint16_t hash_pos = p.len;
        p.len += HASH_LEN;

        // char data[] = "GET /";
        // p.len += encode_stream_frame(1, 0, (uint16_t)strlen(data), p + len,
        //                                 MAX_PKT_LEN - len);
        // memcpy(p + len, "GET /", strlen(data));
        // len += strlen(data);

        warn(info, "trying to connect with vers 0x%08x %4s",
             VERS_UINT32_T(q_vers[i]), q_vers[i]);
        q_send(s, &p, hash_pos);

        // wait for response and read it
        q_pollin(s);
        q_recv(s, &p);

        if (p.flags & F_VERS) {
            warn(warn, "server didn't accept our vers 0x%08x %4s",
                 VERS_UINT32_T(q_vers[i]), q_vers[i]);
            i++;
        } else
            return;
    }

    die("server didn't accept any of our versions");
}


void q_serve(const int s)
{
    // wait for incoming packet,
    q_pollin(s);

    // read it
    struct q_pkt p;
    q_recv(s, &p);
}
