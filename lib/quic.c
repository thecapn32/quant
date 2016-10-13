#include <ev.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>

#include "pkt.h"
#include "quic.h"
#include "tommy.h"
#include "util.h"


/// QUIC version supported by this implementation in order of preference.
const union q_vers vers[] = {{.as_str = "Q025"}, // "Q025" is draft-hamilton
                             {.as_str = "Q036"},
                             {.as_int = 0}};


/// All open QUIC connections.
static hash qc;


static void quic_tx(struct ev_loop * loop, ev_io * w, int revents);
static void quic_rx(struct ev_loop * loop, ev_io * w, int revents);


static int __attribute__((nonnull))
q_conn_cmp(const void * const arg, const void * const obj)
{
    return *(const int *)arg != ((const struct q_conn *)obj)->s;
}


static uint8_t __attribute__((nonnull)) pick_vers(const struct q_pkt * const p)
{
    // first, check if the version in the public header is acceptable to us
    for (uint8_t i = 0; vers[i].as_int; i++) {
        warn(debug, "checking server vers %s against our prio %d = %s",
             p->vers.as_str, i, vers[i].as_str);
        if (vers[i].as_int == p->vers.as_int)
            return i;
    }

    // if that didn't work, then we need to check the numbers in the nonce
    for (uint8_t i = 0; vers[i].as_int; i++)
        for (uint8_t j = 0; j < p->nonce_len; j += sizeof(uint32_t)) {
            union q_vers nv;
            memcpy(&nv.as_int, &p->nonce[j], sizeof(nv.as_int));
            nv.as_str[4] = 0;
            warn(debug,
                 "checking servers nonce pos %d = %s against our prio %d = %s",
                 j, nv.as_str, i, vers[i].as_str);
            if (vers[i].as_int == nv.as_int)
                return i;
        }

    // if we get here, we're out of matching candidates
    return 0;
}


static void __attribute__((nonnull))
quic_rx(struct ev_loop * loop __attribute__((unused)),
        ev_io * w,
        int revents __attribute__((unused)))
{
    warn(info, "entering %s for desc %d", __func__, w->fd);

    struct q_pkt p = {0};
    uint8_t buf[MAX_PKT_LEN];
    const ssize_t rlen = recvfrom(w->fd, buf, MAX_PKT_LEN, 0, 0, 0);
    assert(rlen >= 0, "recvfrom error");
    const uint16_t len = (uint16_t)rlen;
    warn(debug, "received %d bytes, decoding", len);
    const uint16_t pos = dec_pub_hdr(&p, buf, len);
    if (pos < len)
        warn(warn, "pub hdr ends at %d, packet has %d", pos, len);
    // dec_frames(&p, pos);

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
        c->state = VERS_RECV;

        // respond to the initial version negotiation packet
        warn(debug, "client requested version %s", p.vers.as_str);
        uint8_t i = 0;
        while (vers[i].as_int) {
            if (p.vers.as_int == vers[i].as_int)
                break;
            i++;
        }
        if (vers[i].as_int) {
            warn(debug, "supporting client-requested version %s with "
                        "preference %d ",
                 p.vers.as_str, i);
            // TODO: respond
        } else {
            assert(vers[i].as_int, "client-requested version %s not supported",
                   p.vers.as_str);
            // TODO: offer our supported versions
        }
        goto respond;

    case VERS_SENT:
        if (p.flags & F_VERS) {
            warn(info, "server didn't like our version %s",
                 vers[c->vers].as_str);
            const uint8_t v = pick_vers(&p);
            assert(v, "no version in common with server"); // TODO: send RST
            warn(info, "retrying with version %s", vers[v].as_str);
            c->vers = v;
            c->state = CLOSED;
        } else {
            warn(info, "server accepted version %s", vers[c->vers].as_str);
            c->state = ESTABLISHED;
        }
        goto respond;


    default:
        die("TODO: state %d", c->state);
    }
    die("unreachable");

respond:
    ev_io_stop(loop, w);
    ev_io * ww = calloc(1, sizeof(*ww));
    assert(ww, "could not calloc");
    ev_io_init(ww, quic_tx, w->fd, EV_WRITE);
    ev_io_start(loop, ww);


    // // check that we support the desired QUIC version
}


static void __attribute__((nonnull))
quic_tx(struct ev_loop * loop, ev_io * w, int revents __attribute__((unused)))
{
    warn(info, "entering %s for desc %d", __func__, w->fd);

    struct q_conn * c = hash_search(&qc, q_conn_cmp, &w->fd, hash_u32(w->fd));
    if (c == 0) {
        // this is a packet for a new connection, create it
        c = calloc(1, sizeof(*c));
        assert(c, "could not calloc");
        c->s = w->fd;
        c->id = (((uint64_t)random()) << 32) | (uint64_t)random();
        // c->out = 1;
        hash_insert(&qc, &c->node, c, hash_u32(w->fd));
        warn(debug, "created new connection %" PRIu64 " for packet", c->id);
    } else
        warn(debug, "packet is for connection %" PRIu64, c->id);

    // struct q_pkt p;
    uint8_t buf[MAX_PKT_LEN];
    uint16_t len = 0;
    switch (c->state) {
    case CLOSED:
        // send the initial version negotiation packet
        len = enc_init_pkt(c, buf, MAX_PKT_LEN);
        // TODO: add payload data
        c->state = VERS_SENT;
        break;

    default:
        die("TODO: state %d", c->state);
    }

    const ssize_t n = send(c->s, buf, len, 0);
    assert(n > 0, "send error");
    warn(debug, "sent %zd bytes", n);
    c->out++;

    ev_io_stop(loop, w);

    // handle responses
    ev_io * rw = calloc(1, sizeof(*rw));
    assert(rw, "could not calloc");
    ev_io_init(rw, quic_rx, w->fd, EV_READ);
    ev_io_start(loop, rw);
}


void __attribute__((nonnull)) q_connect(EV_P_ const int s)
{
    // warn(info, "entering %s", __func__);
    ev_io * ww = calloc(1, sizeof(*ww));
    assert(ww, "could not calloc");
    ev_io_init(ww, quic_tx, s, EV_WRITE);
    ev_io_start(loop, ww);
}


void __attribute__((nonnull)) q_serve(EV_P_ const int s)
{
    // warn(info, "entering %s", __func__);
    ev_io * rw = calloc(1, sizeof(*rw));
    assert(rw, "could not calloc");
    ev_io_init(rw, quic_rx, s, EV_READ);
    ev_io_start(loop, rw);
}


static void timeout_cb(struct ev_loop * loop __attribute__((unused)),
                       ev_timer * w __attribute__((unused)),
                       int revents __attribute__((unused)))
{
    warn(info, "event loop timeout");
    ev_break(EV_A_ EVBREAK_ALL);
}


void q_init(struct ev_loop * loop)
{
    warn(info, "have libev %d.%d", ev_version_major(), ev_version_minor());
    srandom((unsigned)time(0));
    hash_init(&qc);

    // during development, abort the event loop after some seconds of inactivity
    ev_timer * to = calloc(1, sizeof(*to));
    assert(to, "could not calloc");
    ev_timer_init(to, timeout_cb, 5, 0); // "to" works around gcc issue
    ev_timer_start(loop, to);
}
