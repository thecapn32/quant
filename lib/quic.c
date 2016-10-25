#include <ev.h>
#include <fcntl.h>
#include <inttypes.h>
#include <time.h>

#include "conn.h"
#include "frame.h"
#include "pkt.h"
#include "stream.h"
#include "util.h"
#include "version.h"


/// QUIC version supported by this implementation in order of preference.
const q_tag vers[] = {{.as_str = "Q025"}, // "Q025" is draft-hamilton
                      // {.as_str = "Q036"},
                      {.as_int = 0}};

const size_t vers_len = sizeof(vers);


static ev_io rx_w;
static ev_timer to_w;
ev_async q_async;
struct ev_loop * q_loop;


static uint8_t __attribute__((nonnull))
pick_vers(const struct q_pub_hdr * restrict const p)
{
    for (uint8_t i = 0; vers[i].as_int; i++)
        if (p->vers.as_int == vers[i].as_int)
            return i;

    // we're out of matching candidates, return index of final "zero" version
    warn(info, "no version in common with client");
    return vers_len / sizeof(vers[0]) - 1;
}


static uint8_t __attribute__((nonnull))
pick_server_vers(const struct q_pub_hdr * restrict const p)
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


static void __attribute__((nonnull)) tx(struct q_conn * restrict const c)
{
    warn(info, "entering %s for conn %" PRIu64, __func__, c->id);

    uint8_t buf[MAX_PKT_LEN];
    uint16_t len = 0;

    len = enc_pkt(c, buf, MAX_PKT_LEN);
    switch (c->state) {
    case CONN_CLSD:
    case CONN_VERS_SENT:
        c->state = CONN_VERS_SENT;
        warn(info, "conn %" PRIu64 " now in CONN_VERS_SENT", c->id);
        break;

    case CONN_VERS_RECV:
        // send a version-negotiation response from the server
        break;

    case CONN_FINW:
        break;

    default:
        die("TODO: state %d", c->state);
    }

    const ssize_t n =
        sendto(c->fd, buf, len, 0, (struct sockaddr *)&c->peer, c->peer_len);
    assert(n > 0, "sendto error"); // TODO: handle EAGAIN
    warn(debug, "sent %zd bytes", n);
    hexdump(buf, len);
    c->out++;
}


static void __attribute__((nonnull))
rx(struct ev_loop * restrict const loop __attribute__((unused)),
   ev_io * restrict const w,
   int revents __attribute__((unused)))
{
    warn(info, "entering %s for desc %d", __func__, w->fd);

    uint8_t buf[UINT16_MAX];
    struct sockaddr peer;
    socklen_t peer_len = sizeof(peer);
    const ssize_t n = recvfrom(w->fd, buf, UINT16_MAX, 0,
                               (struct sockaddr *)&peer, &peer_len);
    assert(n >= 0, "recvfrom error");
    assert(n <= MAX_PKT_LEN,
           "received %zu-byte packet, larger than MAX_PKT_LEN of %d", n,
           MAX_PKT_LEN);
    const uint16_t len = (uint16_t)n;
    warn(debug, "received %d bytes", len);
    hexdump(buf, len);

    struct q_pub_hdr p = {0};
    uint16_t i = dec_pub_hdr(&p, buf, len);

    struct q_conn * c = get_conn(p.cid);
    if (c == 0) {
        // this is a packet for a new connection, create it
        assert(p.flags & F_CID, "no conn ID in initial packet");
        c = new_conn(p.cid, &peer, peer_len, w->fd);
        c->in = p.nr;
        // if it gets created here, this is a server connection, so no need to
        // change c->flags
    }

    if (i <= len)
        // if there are bytes after the public header, we have frames
        i += dec_frames(c, &p, &buf[i], len - i);

    switch (c->state) {
    case CONN_CLSD:
        assert(p.flags & F_VERS, "no version in initial packet");
        c->state = CONN_VERS_RECV;
        warn(info, "conn %" PRIu64 " now in CONN_VERS_RECV", c->id);

        // respond to the initial version negotiation packet
        c->vers = pick_vers(&p);
        if (vers[c->vers].as_int) {
            warn(debug, "supporting client-requested version %.4s with "
                        "preference %d ",
                 p.vers.as_str, c->vers);
            c->state = CONN_ESTB;
            warn(info, "conn %" PRIu64 " now in CONN_ESTB", c->id);
            return;
        } else
            warn(warn, "client-requested version %.4s not supported",
                 p.vers.as_str);
        goto respond;

    case CONN_VERS_SENT:
        if (p.flags & F_VERS) {
            warn(info, "server didn't like our version %.4s",
                 vers[c->vers].as_str);
            c->vers = pick_server_vers(&p);
            if (vers[c->vers].as_int)
                warn(info, "retrying with version %.4s", vers[c->vers].as_str);
            else {
                warn(info, "no version in common with server, closing");
                c->vers = 0; // send closing packets with our preferred version
                c->state = CONN_FINW;
                warn(info, "conn %" PRIu64 " now in CONN_FINW", c->id);
            }
        } else {
            warn(info, "server accepted version %.4s", vers[c->vers].as_str);
            c->state = CONN_ESTB;
            warn(info, "conn %" PRIu64 " now in CONN_ESTB", c->id);
        }
        goto respond;

    default:
        die("TODO: state %d", c->state);
    }
    assert(0, "unreachable");

respond:
    tx(c);
}


uint64_t q_connect(const int s,
                   const struct sockaddr * restrict const peer,
                   const socklen_t peer_len)
{
    // put the socket into non-blocking mode
    assert(fcntl(s, O_NONBLOCK) >= 0, "fcntl");

    // initialize the RX watcher
    ev_io * const r = &rx_w; // suppress erroneous warning in gcc 6.2
    ev_io_init(r, rx, s, EV_READ);
    ev_io_start(q_loop, &rx_w);

    // make new connection
    const uint64_t id = (((uint64_t)random()) << 32) | (uint64_t)random();
    struct q_conn * restrict const c = new_conn(id, peer, peer_len, s);
    c->flags |= CONN_FLAG_CLNT;
    return id;
}


void q_write(const uint64_t cid,
             const uint32_t sid,
             const void * restrict const buf,
             const size_t len)
{
    struct q_conn * restrict const c = get_conn(cid);
    assert(c, "conn %" PRIu64 " does not exist", cid);

    struct q_stream * restrict s = get_stream(c, sid);
    assert(s, "stream %d on conn %" PRIu64 " does not exist", sid, cid);

    // append data
    warn(info, "%zu bytes on stream %d on conn %" PRIu64, len, sid, cid);
    s->out = realloc(s->out, s->out_len + len);
    assert(s->out, "realloc");
    memcpy(&s->out[s->out_len], buf, len);
    s->out_len += len;

    // send
    tx(c);
}


void q_serve(const int s, void (*cb)(struct ev_loop *, struct ev_async *, int))
{
    // put the socket into non-blocking mode
    assert(fcntl(s, O_NONBLOCK) >= 0, "fcntl");

    // initialize the RX watcher
    ev_io * const r = &rx_w; // suppress erroneous warning in gcc 6.2
    ev_io_init(r, rx, s, EV_READ);
    ev_io_start(q_loop, &rx_w);

    // initialize the app callback
    ev_async_init(&q_async, cb);
}


uint32_t q_rsv_stream(const uint64_t cid)
{
    struct q_conn * restrict const c = get_conn(cid);
    assert(c, "conn %" PRIu64 " does not exist", cid);
    return new_stream(c, 0)->id;
}


static void timeout_cb(struct ev_loop * restrict const l,
                       ev_timer * restrict const w __attribute__((unused)),
                       int revents __attribute__((unused)))
{
    warn(info, "event loop timeout");
    ev_break(l, EVBREAK_ALL);
}


void __attribute__((nonnull))
q_init(struct ev_loop * restrict const l, const long timeout)
{
    warn(info, "%s %s with libev %d.%d", quickie_name, quickie_version,
         ev_version_major(), ev_version_minor());
    srandom((unsigned)time(0));
    hash_init(&q_conns);
    q_loop = l;

    if (timeout) {
        // during development, abort event loop after some inactivity
        ev_timer * const t = &to_w; // suppress erroneous warning in gcc 6.2
        ev_timer_init(t, timeout_cb, timeout, 0);
        ev_timer_start(q_loop, &to_w);
    }
}
