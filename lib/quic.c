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

/// QUIC version supported by this implementation in order of preference.
const char * const q_vers[] = {"Q025", 0}; // "Q025" is draft-hamilton

/// All open QUIC connections.
static hash qc;


static int q_conn_cmp(const void * const arg, const void * const obj)
{
    return *(const int *)arg != ((const struct q_conn *)obj)->s;
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
        // this is a packet for a new connection, create it
        c = calloc(1, sizeof(*c));
        assert(c, "could not calloc");
        c->s = w->fd;
        c->in = p.nr;
        assert(p.flags & F_CID, "no connection ID in initial packet");
        c->id = p.cid;
        hash_insert(&qc, &c->node, c, hash_u32(w->fd));
        warn(debug, "created new connection %" PRIu64 " for packet", c->id);
    } else
        warn(debug, "packet is for connection %" PRIu64, c->id);

    switch (c->state) {
    case CLOSED:
        assert(p.flags & F_VERS, "no version in initial packet");

        // respond to the initial version negotiation packet
        warn(debug, "client requested version %.4s", (char *)&p.vers);
        uint8_t i = 0;
        while (q_vers[i]) {
            if (p.vers == VERS_UINT32_T(q_vers[i]))
                break;
            i++;
        }

        c->out++;
        if (q_vers[i]) {
            warn(debug, "supporting client-requested version %.4s with "
                        "preference %d ",
                 (char *)&p.vers, i);
            // TODO: respond
        } else {
            assert(q_vers[i], "client-requested version %.4s not supported",
                   (char *)&p.vers);
            // TODO: offer our supported versions
        }

        // enc_init_pkt(c, &p);
        c->state++;
        break;

    default:
        die("TODO: state %d", c->state);
    }

    // // check that we support the desired QUIC version
}


static void quic_tx(EV_P_ ev_io * w, int revents __unused)
{
    warn(info, "entering %s for desc %d", __func__, w->fd);

    struct q_conn * c = hash_search(&qc, q_conn_cmp, &w->fd, hash_u32(w->fd));
    if (c == 0) {
        // this is a packet for a new connection, create it
        c = calloc(1, sizeof(*c));
        assert(c, "could not calloc");
        c->s = w->fd;
        arc4random_buf(&c->id, sizeof(uint64_t));
        hash_insert(&qc, &c->node, c, hash_u32(w->fd));
        warn(debug, "created new connection %" PRIu64 " for packet", c->id);
    } else
        warn(debug, "packet is for connection %" PRIu64, c->id);

    struct q_pkt p;
    switch (c->state) {
    case CLOSED:
        // send the initial version negotiation packet
        p = (struct q_pkt){.flags = F_VERS | F_CID,
                           .vers = VERS_UINT32_T(q_vers[c->vers]),
                           .cid = c->id,
                           .nr = c->out++};
        const uint16_t hash_pos = enc_pub_hdr(&p);
        p.len = hash_pos + HASH_LEN;

        // TODO: add payload data

        const uint128_t hash = fnv_1a(p.buf, p.len, hash_pos, HASH_LEN);
        memcpy(&p.buf[hash_pos], &hash, HASH_LEN);
        c->state++;
        break;

    default:
        die("TODO: state %d", c->state);
    }

    const ssize_t n = send(c->s, p.buf, p.len, 0);
    assert(n > 0, "send error");
    warn(debug, "sent %zd bytes", n);

    ev_io_stop(loop, w);

    // handle responses
    ev_io * rw = calloc(1, sizeof(*rw));
    assert(rw, "could not calloc");
    ev_io_init(rw, quic_rx, w->fd, EV_READ);
    ev_io_start(loop, rw);
}


void q_connect(EV_P_ const int s)
{
    // warn(info, "entering %s", __func__);
    ev_io * ww = calloc(1, sizeof(*ww));
    assert(ww, "could not calloc");
    ev_io_init(ww, quic_tx, s, EV_WRITE);
    ev_io_start(loop, ww);
}


void q_serve(EV_P_ const int s)
{
    // warn(info, "entering %s", __func__);
    ev_io * rw = calloc(1, sizeof(*rw));
    assert(rw, "could not calloc");
    ev_io_init(rw, quic_rx, s, EV_READ);
    ev_io_start(loop, rw);
}


void q_init(void)
{
    hash_init(&qc);
}
