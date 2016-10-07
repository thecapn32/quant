#include <netinet/in.h>
#include <poll.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include "debug.h"
#include "fnv_1a.h"
#include "pkt.h"
#include "quic.h"


#define Q_TIMEOUT 3000

#define VERS_UINT32_T(v) (*(const uint32_t *)(const void *)(v))

static SLIST_HEAD(qc, q_conn) q_conns = SLIST_HEAD_INITIALIZER(q_conns);

const char * const q_vers[] = {"Q025", "Q036", 0};


static void q_pollin(const struct q_conn * const qc)
{
    struct pollfd fds = {.fd = qc->sock, .events = POLLIN};
    const int     n = poll(&fds, 1, Q_TIMEOUT);
    assert(n > 0, "poll timeout");
}


static void q_send(const struct q_conn * const qc,
                   struct q_pkt * const        p,
                   const uint16_t              hash_pos)
{
    const uint128_t hash = fnv_1a(p->buf, p->len, hash_pos, HASH_LEN);
    memcpy(&p->buf[hash_pos], &hash, HASH_LEN);
    const ssize_t n = send(qc->sock, p->buf, p->len, 0);
    assert(n > 0, "send error");
    warn(debug, "sent %zd bytes", n);
}


static void q_recv(const struct q_conn * const qc, struct q_pkt * const p)
{
    p->len = (uint16_t)recvfrom(qc->sock, p->buf, MAX_PKT_LEN, 0, 0, 0);
    assert(p->len >= 0, "recvfrom error");
    warn(debug, "received %d bytes, decoding", p->len);
    const uint16_t pos = dec_pub_hdr(qc, p);
    dec_frames(qc, p, pos);
}


void q_connect(const int s)
{
    uint8_t i = 0;

    // Create the new QUIC connection
    struct q_conn * qc = calloc(1, sizeof(struct q_conn));
    qc->sock = s;
    qc->nr = 1;
    arc4random_buf(&qc->id, sizeof(uint64_t));
    SLIST_INSERT_HEAD(&q_conns, qc, next);

    // Try to connect with the versions of QUIC we support
    while (q_vers[i]) {
        struct q_pkt p = {.flags = F_VERS | F_CID,
                          .vers = VERS_UINT32_T(q_vers[i]),
                          .cid = qc->id,
                          .nr = qc->nr};
        p.len = enc_pub_hdr(qc, &p);

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
        q_send(qc, &p, hash_pos);

        // wait for response and read it
        q_pollin(qc);
        q_recv(qc, &p);

        if (p.flags & F_VERS) {
            warn(warn, "server didn't accept our vers 0x%08x %4s",
                 VERS_UINT32_T(q_vers[i]), q_vers[i]);
            // TODO: we should check which versions the server supports and pick
            // a common one
            i++;
        } else {
            qc->r_nr = p.nr;
            return;
        }
    }

    die("server didn't accept any of our versions");
}


void q_serve(const int s)
{
    struct q_conn qc = {.sock = s};
    // wait for incoming packet
    q_pollin(&qc);

    // read it
    struct q_pkt p;
    q_recv(&qc, &p);
}
