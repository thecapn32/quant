#include <ev.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <time.h>

#include "pkt.h"
#include "util.h"
#include "version.h"


/// QUIC version supported by this implementation in order of preference.
const q_tag vers[] = {{.as_str = "Q025"}, // "Q025" is draft-hamilton
                      // {.as_str = "Q036"},
                      {.as_int = 0}};

const size_t vers_len = sizeof(vers);


// All open QUIC connections.
static hash conns;

static ev_io rx_w;
static ev_timer to_w;


static int __attribute__((nonnull))
cmp_q_conn(const void * restrict const arg, const void * restrict const obj)
{
    return *(const uint64_t *)arg != ((const struct q_conn *)obj)->id;
}


static struct q_conn * __attribute__((nonnull))
new_conn(const uint64_t id,
         const struct sockaddr * restrict const peer,
         const socklen_t plen,
         const int fd)
{
    struct q_conn * const c = calloc(1, sizeof(*c));
    assert(c, "could not calloc");
    c->id = id;
    c->out = 1;
    c->fd = fd;
    hash_init(&c->streams);
    hash_insert(&conns, &c->node, c, (uint32_t)c->id);

    char host[NI_MAXHOST] = "";
    char port[NI_MAXSERV] = "";
    getnameinfo((const struct sockaddr *)peer, plen, host, sizeof(host), port,
                sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    c->peer = *peer;
    c->plen = plen;
    warn(debug, "created new connection %" PRIu64 " with peer %s:%s", c->id,
         host, port);

    return c;
}


static uint8_t __attribute__((nonnull))
pick_vers(const struct q_pkt * restrict const p)
{
    for (uint8_t i = 0; vers[i].as_int; i++)
        if (p->vers.as_int == vers[i].as_int)
            return i;

    // we're out of matching candidates, return index of final "zero" version
    warn(info, "no version in common with client");
    return vers_len / sizeof(vers[0]) - 1;
}


static uint8_t __attribute__((nonnull))
pick_server_vers(const struct q_pkt * restrict const p)
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
            q_tag v;
            memcpy(&v.as_int, &p->nonce[j], sizeof(v));
            warn(debug, "checking server vers prio %ld = %.4s against our prio "
                        "%d = %.4s",
                 j / sizeof(uint32_t), v.as_str, i, vers[i].as_str);
            if (vers[i].as_int == v.as_int)
                return i;
        }

    // we're out of matching candidates, return index of final "zero" version
    warn(info, "no version in common with server");
    return vers_len / sizeof(vers[0]) - 1;
}


static void __attribute__((nonnull)) q_tx(struct q_conn * restrict const c)
{
    warn(info, "entering %s for conn %" PRIu64, __func__, c->id);

    uint8_t buf[MAX_PKT_LEN];
    uint16_t len = 0;

    switch (c->state) {
    case CLOSED:
    case VERS_SENT:
        len = enc_pkt(c, buf, MAX_PKT_LEN);
        // TODO: add payload data
        c->state = VERS_SENT;
        break;

    case VERS_RECV:
        // send a version-negotiation response from the server
        len = enc_pkt(c, buf, MAX_PKT_LEN);
        break;

    case FIN_WAIT:
        len = enc_pkt(c, buf, MAX_PKT_LEN);
        break;

    default:
        die("TODO: state %d", c->state);
    }

    const ssize_t n =
        sendto(c->fd, buf, len, 0, (struct sockaddr *)&c->peer, c->plen);
    assert(n > 0, "sendto error"); // TODO: handle EAGAIN
    warn(debug, "sent %zd bytes", n);
    c->out++;
}


static void __attribute__((nonnull))
q_rx(struct ev_loop * restrict const loop __attribute__((unused)),
     ev_io * restrict const w,
     int revents __attribute__((unused)))
{
    warn(info, "entering %s for desc %d", __func__, w->fd);

    uint8_t buf[UINT16_MAX];
    struct sockaddr peer;
    socklen_t plen = sizeof(peer);
    const ssize_t rlen =
        recvfrom(w->fd, buf, UINT16_MAX, 0, (struct sockaddr *)&peer, &plen);
    assert(rlen >= 0, "recvfrom error");
    assert(rlen <= MAX_PKT_LEN,
           "received %zu-byte packet, larger than MAX_PKT_LEN of %d", rlen,
           MAX_PKT_LEN);
    const uint16_t len = (uint16_t)rlen;
    warn(debug, "received %d bytes", len);

    struct q_pkt p = {0}; // TODO: might be better to allocate dynamically
    dec_pub_hdr(&p, buf, len);

    struct q_conn * c =
        hash_search(&conns, cmp_q_conn, &p.cid, (uint32_t)p.cid);
    if (c == 0) {
        // this is a packet for a new connection, create it
        assert(p.flags & F_CID, "no connection ID in initial packet");
        c = new_conn(p.cid, &peer, plen, w->fd);
        c->in = p.nr;
    }

    switch (c->state) {
    case CLOSED:
        assert(p.flags & F_VERS, "no version in initial packet");
        c->state = VERS_RECV;

        // respond to the initial version negotiation packet
        c->vers = pick_vers(&p);
        if (vers[c->vers].as_int) {
            warn(debug, "supporting client-requested version %.4s with "
                        "preference %d ",
                 p.vers.as_str, c->vers);
            c->state = ESTABLISHED;
        } else
            warn(warn, "client-requested version %.4s not supported",
                 p.vers.as_str);
        goto respond;

    case VERS_SENT:
        if (p.flags & F_VERS) {
            warn(info, "server didn't like our version %.4s",
                 vers[c->vers].as_str);
            c->vers = pick_server_vers(&p);
            if (vers[c->vers].as_int)
                warn(info, "retrying with version %.4s", vers[c->vers].as_str);
            else {
                warn(info, "no version in common with server, closing");
                c->vers = 0; // send closing packets with our preferred version
                c->state = FIN_WAIT;
            }
        } else {
            warn(info, "server accepted version %.4s", vers[c->vers].as_str);
            c->state = ESTABLISHED;
        }
        goto respond;

    default:
        die("TODO: state %d", c->state);
    }
    assert(0, "unreachable");

respond:
    free_pkt(&p);
    q_tx(c);
}


void __attribute__((nonnull))
q_connect(struct ev_loop * restrict const loop,
          const int s,
          const struct sockaddr * restrict const peer,
          const socklen_t plen)
{
    // put the socket into non-blocking mode
    assert(fcntl(s, O_NONBLOCK) >= 0, "fcntl");

    // initialize the RX watcher
    ev_io * const r = &rx_w; // suppress erroneous warning in gcc 6.2
    ev_io_init(r, q_rx, s, EV_READ);
    ev_io_start(loop, &rx_w);

    // make new connection
    const uint64_t id = (((uint64_t)random()) << 32) | (uint64_t)random();
    struct q_conn * const c = new_conn(id, peer, plen, s);

    // send
    q_tx(c);
}


void __attribute__((nonnull))
q_serve(struct ev_loop * restrict const loop, const int s)
{
    // put the socket into non-blocking mode
    assert(fcntl(s, O_NONBLOCK) >= 0, "fcntl");

    // initialize the RX watcher
    ev_io * const r = &rx_w; // suppress erroneous warning in gcc 6.2
    ev_io_init(r, q_rx, s, EV_READ);
    ev_io_start(loop, &rx_w);
}


static void timeout_cb(struct ev_loop * restrict const loop,
                       ev_timer * restrict const w __attribute__((unused)),
                       int revents __attribute__((unused)))
{
    warn(info, "event loop timeout");
    ev_break(loop, EVBREAK_ALL);
}


void q_init(struct ev_loop * restrict const loop, const long timeout)
{
    warn(info, "%s %s with libev %d.%d", quickie_name, quickie_version,
         ev_version_major(), ev_version_minor());
    srandom((unsigned)time(0));
    hash_init(&conns);

    if (timeout) {
        // during development, abort event loop after some inactivity
        ev_timer * const t = &to_w; // suppress erroneous warning in gcc 6.2
        ev_timer_init(t, timeout_cb, timeout, 0);
        ev_timer_start(loop, &to_w);
    }
}
