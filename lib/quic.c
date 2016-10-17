#include <ev.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <time.h>

#include "pkt.h"
#include "quic.h"
#include "tommy.h"
#include "util.h"


/// QUIC version supported by this implementation in order of preference.
const union q_vers vers[3] = {{.as_str = "Q025"}, // "Q025" is draft-hamilton
                              {.as_str = "Q036"},
                              {.as_int = 0}};


/// All open QUIC connections.
static hash qc;

static ev_io rx_w, tx_w;
static ev_timer to_w;


static void quic_tx(struct ev_loop * const loop, ev_io * const w, int revents);
static void quic_rx(struct ev_loop * const loop, ev_io * const w, int revents);


static int __attribute__((nonnull))
q_conn_cmp(const void * const arg, const void * const obj)
{
    return *(const uint64_t *)arg != ((const struct q_conn *)obj)->id;
}


static uint8_t __attribute__((nonnull))
pick_vers(const struct q_pkt * const restrict p)
{
    uint8_t i = 0;
    while (vers[i].as_int) {
        if (p->vers.as_int == vers[i].as_int)
            return i;
        i++;
    }
    return i;
}


static struct q_conn * new_conn(const uint64_t id,
                                const struct sockaddr * const peer,
                                const socklen_t plen)
{
    struct q_conn * const c = calloc(1, sizeof(*c));
    assert(c, "could not calloc");
    c->id = id;
    char host[NI_MAXHOST] = "";
    char port[NI_MAXSERV] = "";
    if (peer) {
        getnameinfo((const struct sockaddr *)peer, plen, host, sizeof(host),
                    port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
        c->peer = *peer;
        c->plen = plen;
    }
    hash_insert(&qc, &c->node, c, (uint32_t)c->id);
    warn(debug, "created new connection %" PRIu64 " to %s:%s", c->id, host,
         port);
    return c;
}


static uint8_t __attribute__((nonnull))
pick_server_vers(const struct q_pkt * const restrict p)
{
    // first, check if the version in the public header is acceptable to us
    for (uint8_t i = 0; vers[i].as_int; i++) {
        warn(debug, "checking server vers %.4s against our prio %d = %.4s",
             p->vers.as_str, i, vers[i].as_str);
        if (vers[i].as_int == p->vers.as_int)
            return i;
    }

    // if that didn't work, then we need to check the numbers in the nonce
    for (uint8_t i = 0; vers[i].as_int; i++)
        for (uint8_t j = 0; j < p->nonce_len; j += sizeof(uint32_t)) {
            union q_vers v;
            memcpy(&v.as_int, &p->nonce[j], sizeof(v));
            warn(debug, "checking servers nonce pos %d = %.4s against our prio "
                        "%d = %.4s",
                 j, v.as_str, i, vers[i].as_str);
            if (vers[i].as_int == v.as_int)
                return i;
        }

    // if we get here, we're out of matching candidates
    return 0;
}


static void __attribute__((nonnull))
quic_rx(struct ev_loop * const loop,
        ev_io * const w,
        int revents __attribute__((unused)))
{
    warn(info, "entering %s for desc %d", __func__, w->fd);

    uint8_t buf[MAX_PKT_LEN];
    struct sockaddr peer;
    socklen_t plen = sizeof(peer);
    const ssize_t rlen =
        recvfrom(w->fd, buf, MAX_PKT_LEN, 0, (struct sockaddr *)&peer, &plen);
    assert(rlen >= 0, "recvfrom error");
    const uint16_t len = (uint16_t)rlen;
    warn(debug, "received %d bytes, decoding", len);

    // const uint16_t pos =
    struct q_pkt p = {0};
    dec_pub_hdr(&p, buf, len);
    // dec_frames(&p, pos);

    struct q_conn * c = hash_search(&qc, q_conn_cmp, &p.cid, (uint32_t)p.cid);
    if (c == 0) {
        // this is a packet for a new connection, create it
        assert(p.flags & F_CID, "no connection ID in initial packet");
        c = new_conn(p.cid, &peer, plen);
        c->in = p.nr;
    }

    switch (c->state) {
    case CLOSED:
        assert(p.flags & F_VERS, "no version in initial packet");
        c->state = VERS_RECV;

        // respond to the initial version negotiation packet
        c->vers = pick_vers(&p);
        if (vers[c->vers].as_int)
            warn(debug, "supporting client-requested version %.4s with "
                        "preference %d ",
                 p.vers.as_str, c->vers);
        // TODO: respond
        else
            warn(info, "client-requested version %.4s not supported",
                 p.vers.as_str);
        goto respond;

    case VERS_SENT:
        if (p.flags & F_VERS) {
            warn(info, "server didn't like our version %.4s",
                 vers[c->vers].as_str);
            const uint8_t v = pick_server_vers(&p);
            assert(v, "no version in common with server"); // TODO: send RST
            warn(info, "retrying with version %.4s", vers[v].as_str);
            c->vers = v;
            c->state = CLOSED;
        } else {
            warn(info, "server accepted version %.4s", vers[c->vers].as_str);
            c->state = ESTABLISHED;
        }
        goto respond;

    default:
        die("TODO: state %d", c->state);
    }
    die("unreachable");

respond:
    tx_w.data = c;
    ev_io_start(loop, &tx_w);
}


static void __attribute__((nonnull))
quic_tx(struct ev_loop * const loop,
        ev_io * const w,
        int revents __attribute__((unused)))
{
    struct q_conn * c = w->data;
    warn(info, "entering %s for conn %" PRIu64, __func__, c->id);

    uint8_t buf[MAX_PKT_LEN];
    uint16_t len = 0;

    switch (c->state) {
    case CLOSED:
    case VERS_SENT:
        // send (or re-send) the initial version negotiation packet
        len = enc_init_pkt(c, buf, MAX_PKT_LEN);
        // TODO: add payload data
        c->state = VERS_SENT;
        break;

    case VERS_RECV:
        // send a version-negotiation response from the server
        len = enc_init_pkt(c, buf, MAX_PKT_LEN);
        break;

    default:
        die("TODO: state %d", c->state);
    }

    const ssize_t n =
        sendto(w->fd, buf, len, 0, (struct sockaddr *)&c->peer, c->plen);
    assert(n > 0, "sendto error");
    warn(debug, "sent %zd bytes", n);
    c->out++;

    // handle responses
    ev_io_stop(loop, &tx_w);
    ev_io_start(loop, &rx_w);
}


void __attribute__((nonnull)) q_connect(struct ev_loop * const loop,
                                        const int s,
                                        const struct sockaddr * const peer,
                                        const socklen_t plen)
{
    // initialize the RX and TX watchers
    ev_io * const r = &rx_w; // works around a strict-aliasing bug in gcc 6.2
    ev_io * const t = &tx_w; // works around a strict-aliasing bug in gcc 6.2
    ev_io_init(r, quic_rx, s, EV_READ);
    ev_io_init(t, quic_tx, s, EV_WRITE);

    // make new connection
    const uint64_t id = (((uint64_t)random()) << 32) | (uint64_t)random();
    struct q_conn * const c = new_conn(id, peer, plen);

    // start sending
    tx_w.data = c;
    ev_io_start(loop, &tx_w);
}


void __attribute__((nonnull)) q_serve(struct ev_loop * const loop, const int s)
{
    // initialize the RX and TX watchers
    ev_io *r = &rx_w, *t = &tx_w;
    ev_io_init(r, quic_rx, s, EV_READ);
    ev_io_init(t, quic_tx, s, EV_WRITE);

    // start receiving
    ev_io_start(loop, &rx_w);
}


static void timeout_cb(struct ev_loop * const loop,
                       ev_timer * w __attribute__((unused)),
                       int revents __attribute__((unused)))
{
    warn(info, "event loop timeout");
    ev_break(loop, EVBREAK_ALL);
}


void q_init(struct ev_loop * const loop)
{
    warn(info, "have libev %d.%d", ev_version_major(), ev_version_minor());
    srandom((unsigned)time(0));
    hash_init(&qc);

    // during development, abort the event loop after some seconds of inactivity
    ev_timer * const t = &to_w; // works around a strict-aliasing bug in gcc 6.2
    ev_timer_init(t, timeout_cb, 5, 0);
    ev_timer_start(loop, &to_w);
}
