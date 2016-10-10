#include <ev.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include "fnv_1a.h"
#include "pkt.h"
#include "quic.h"
#include "tommy.h"
#include "util.h"


// Convenience macro, in case the "loop" parameter defined by EV_P_ is unused
#define EV_PU_ struct ev_loop *loop __unused,

/// QUIC version supported by this implementation.
const char * const q_vers[] = {"Q025", "Q036", 0}; // "Q025" is draft-hamilton

/// Macro to interpret a @p q_vers[] string as a @p uint32_t.
#define VERS_UINT32_T(v) (*(const uint32_t *)(const void *)(v))

/// All open QUIC connections.
static hash qc;


static int q_conn_cmp(const void * const arg, const void * const obj)
{
    return *(const int *)arg != ((const struct q_conn *)obj)->sock;
}


static void quic_rx(EV_PU_ ev_io * w, int revents __unused)
{
    warn(info, "entering %s for desc %d", __func__, w->fd);

    struct q_pkt p = {0};
    p.len = (uint16_t)recvfrom(w->fd, p.buf, MAX_PKT_LEN, 0, 0, 0);
    assert(p.len >= 0, "recvfrom error");
    warn(debug, "received %d bytes, decoding", p.len);
    const uint16_t pos = dec_pub_hdr(&p);
    dec_frames(&p, pos);

    struct q_conn * c = hash_search(&qc, q_conn_cmp, &w->fd, hash_u32(w->fd));
    if (c == 0) {
        // this is a packet for a new connection, allocate it
        c = calloc(1, sizeof(*c));
        c->sock = w->fd;
        c->nr = 1;
        c->r_nr = p.nr;
        c->id = p.cid;
        warn(debug, "created new connection %" PRIu64 " for packet", c->id);
    } else
        warn(debug, "packet is for connection %" PRIu64, c->id);

    // // check that we support the desired QUIC version
    // warn(debug, "client-requested version %.4s", (char *)&p.vers);
    // uint8_t i = 0;
    // while (q_vers[i]) {
    //     if (p.vers == VERS_UINT32_T(q_vers[i])) {
    //         warn(debug,
    //              "supporting client-requested version %.4s with preference
    //              %d",
    //              (char *)&p.vers, i);
    //         break;
    //     }
    //     i++;
    // }
    // assert(q_vers[i], "client-requested version %.4s not supported",
    //        (char *)&p.vers);
}


static void quic_tx(EV_P_ ev_io * w, int revents __unused)
{
    warn(info, "entering %s for desc %d", __func__, w->fd);

    struct q_conn * c = hash_search(&qc, q_conn_cmp, &w->fd, hash_u32(w->fd));
    if (c == 0) {
        // this is a packet for a new connection, allocate it
        c = calloc(1, sizeof(*c));
        c->sock = w->fd;
        c->nr = 1;
        arc4random_buf(&c->id, sizeof(uint64_t));
        hash_insert(&qc, &c->node, c, hash_u32(w->fd));
        warn(debug, "created new connection %" PRIu64 " for packet", c->id);
    } else
        warn(debug, "packet is for connection %" PRIu64, c->id);

    // Try to connect with the versions of QUIC we support
    struct q_pkt p = {.flags = F_VERS | F_CID,
                      .vers = VERS_UINT32_T(q_vers[c->vers_idx]),
                      .cid = c->id,
                      .nr = c->nr};
    p.len = enc_pub_hdr(&p);

    // leave space for hash
    const uint16_t hash_pos = p.len;
    p.len += HASH_LEN;

    // TODO: add payload data

    // send
    const uint128_t hash = fnv_1a(p.buf, p.len, hash_pos, HASH_LEN);
    memcpy(&p.buf[hash_pos], &hash, HASH_LEN);
    const ssize_t n = send(c->sock, p.buf, p.len, 0);
    assert(n > 0, "send error");
    warn(debug, "sent %zd bytes", n);

    ev_io_stop(loop, w);

    // handle responses
    ev_io * rw = calloc(1, sizeof(*rw));
    ev_io_init(rw, quic_rx, w->fd, EV_READ);
    ev_io_start(loop, rw);
}


void q_connect(EV_P_ const int s)
{
    // warn(info, "entering %s", __func__);
    ev_io * ww = calloc(1, sizeof(*ww));
    ev_io_init(ww, quic_tx, s, EV_WRITE);
    ev_io_start(loop, ww);
}


void q_serve(EV_P_ const int s)
{
    // warn(info, "entering %s", __func__);
    ev_io * rw = calloc(1, sizeof(*rw));
    ev_io_init(rw, quic_rx, s, EV_READ);
    ev_io_start(loop, rw);
}


void q_init(void)
{
    hash_init(&qc);
}
