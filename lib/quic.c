// #include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/param.h>
// #include <time.h>

#include "frame.h"
#include "pkt.h"
#include "version.h"

#include <warpcore.h>


/// QUIC version supported by this implementation in order of preference.
const q_tag vers[] = {{.as_str = "Q025"}, // "Q025" is draft-hamilton
                      // {.as_str = "Q036"},
                      {.as_int = 0}};

const size_t vers_len = sizeof(vers);

static struct ev_loop * loop;
static ev_io rx_w;
static ev_timer to_w;
static ev_async async_w;
static pthread_t tid;
static pthread_cond_t write_cv;
static pthread_cond_t accept_cv;

pthread_mutex_t lock;
pthread_cond_t read_cv;

static uint64_t accept_queue;


static uint8_t __attribute__((nonnull))
pick_vers(const struct q_pub_hdr * const p)
{
    for (uint8_t i = 0; vers[i].as_int; i++)
        if (p->vers.as_int == vers[i].as_int)
            return i;

    // we're out of matching candidates, return index of final "zero" version
    warn(info, "no version in common with client");
    return vers_len / sizeof(vers[0]) - 1;
}


static uint8_t __attribute__((nonnull))
pick_server_vers(const struct q_pub_hdr * const p)
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


static void __attribute__((nonnull)) tx(struct q_conn * const c)
{
    // warn(info, "entering %s for conn %" PRIu64, __func__, c->id);
    struct warpcore * const w = w_engine(c->s);
    struct w_iov * const v = w_alloc(w, MAX_PKT_LEN);

    const uint16_t len = enc_pkt(c, v->buf, MAX_PKT_LEN);
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

    w_tx(c->s, v);
    w_nic_tx(w);
    hexdump(v->buf, len);
    w_free(w, v);

    c->out++;

    pthread_mutex_lock(&lock);
    pthread_cond_signal(&write_cv);
    pthread_mutex_unlock(&lock);
}


static void __attribute__((nonnull))
rx(struct ev_loop * const l __attribute__((unused)),
   ev_io * const w,
   int e __attribute__((unused)))
{
    // warn(info, "entering %s for desc %d", __func__, w->fd);

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
    // hexdump(buf, len);

    struct q_pub_hdr p = {0};
    struct q_conn * c = 0;
    uint16_t i = dec_pub_hdr(&p, buf, len, &c);

    if (c == 0) {
        // this is a packet for a new connection, create it
        assert(p.flags & F_CID, "no conn ID in initial packet");
        c = new_conn(p.cid, &peer, peer_len);
        c->in = p.nr;
        // if it gets created here, this is a server connection, so no need to
        // change c->flags
        // XXX
        accept_queue = p.cid;
        pthread_mutex_lock(&lock);
        pthread_cond_signal(&accept_cv);
        pthread_mutex_unlock(&lock);
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
                c->vers = 0; // send closing packet with our preferred version
                c->state = CONN_FINW;
                warn(info, "conn %" PRIu64 " now in CONN_FINW", c->id);
            }
        } else {
            warn(info, "server accepted version %.4s", vers[c->vers].as_str);
            c->state = CONN_ESTB;
            warn(info, "conn %" PRIu64 " now in CONN_ESTB", c->id);
        }
        goto respond;

    case CONN_ESTB:
        return; // TODO: respond with ACK

    default:
        die("TODO: state %d", c->state);
    }
    assert(0, "unreachable");

respond:
    tx(c);
}


uint64_t q_connect(void * const q,
                   const struct sockaddr * const peer,
                   const socklen_t peer_len)
{
    // make new connection
    const uint64_t id = (((uint64_t)random()) << 32) | (uint64_t)random();
    struct q_conn * const c = new_conn(id, peer, peer_len);
    c->flags |= CONN_FLAG_CLNT;

    c->s = w_bind(q, (uint16_t)random());
    w_connect(c->s,
              ((const struct sockaddr_in *)(const void *)peer)->sin_addr.s_addr,
              ((const struct sockaddr_in *)(const void *)peer)->sin_port);

    // initialize the RX watcher
    ev_io * const r = &rx_w; // suppress erroneous warning in gcc 6.2
    ev_io_init(r, rx, w_fd(c->s), EV_READ);

    pthread_mutex_lock(&lock);
    ev_io_start(loop, &rx_w);
    ev_async_send(loop, &async_w);
    pthread_mutex_unlock(&lock);

    return id;
}


static void __attribute__((nonnull)) check_stream(void * arg, void * obj)
{
    struct q_conn * c = arg;
    struct q_stream * s = obj;
    if (s->out_len) {
        // warn(info, "buffered %" PRIu64 " byte%c on stream %d on conn %"
        // PRIu64
        //            ": %s ",
        //      s->out_len, plural(s->out_len), s->id, c->id, s->out);
        tx(c);
    }
}


static void __attribute__((nonnull)) check_conn(void * obj)
{
    struct q_conn * c = obj;
    hash_foreach_arg(&c->streams, &check_stream, c);
}


void q_write(const uint64_t cid,
             const uint32_t sid,
             const void * const buf,
             const size_t len)
{
    struct q_conn * const c = get_conn(cid);
    assert(c, "conn %" PRIu64 " does not exist", cid);
    struct q_stream * s = get_stream(c, sid);
    assert(s, "stream %d on conn %" PRIu64 " does not exist", sid, cid);

    // append data
    warn(info, "%zu bytes on stream %d on conn %" PRIu64, len, sid, cid);
    s->out = realloc(s->out, s->out_len + len);
    assert(s->out, "realloc");
    memcpy(&s->out[s->out_len], buf, len);
    s->out_len += len;

    pthread_mutex_lock(&lock);
    ev_io_start(loop, &rx_w);
    ev_async_send(loop, &async_w);
    warn(warn, "waiting for write to complete");
    pthread_cond_wait(&write_cv, &lock);
    pthread_mutex_unlock(&lock);
    warn(warn, "write done");
}


static void __attribute__((nonnull))
find_stream_with_data(void * arg, void * obj)
{
    uint32_t * sid = arg;
    struct q_stream * s = obj;
    if (s->in_len && *sid == 0) {
        // warn(info, "buffered %" PRIu64 " byte%c on stream %d: %s ",
        // s->in_len,
        //      plural(s->in_len), s->id, s->in);
        *sid = s->id;
    }
}


size_t q_read(const uint64_t cid,
              uint32_t * const sid,
              void * const buf,
              const size_t len)
{
    struct q_conn * const c = get_conn(cid);
    assert(c, "conn %" PRIu64 " does not exist", cid);

    pthread_mutex_lock(&lock);
    warn(warn, "waiting for data");
    pthread_cond_wait(&read_cv, &lock);
    pthread_mutex_unlock(&lock);
    warn(warn, "got data");

    *sid = 0;
    hash_foreach_arg(&c->streams, &find_stream_with_data, sid);
    struct q_stream * s = get_stream(c, *sid);
    assert(s, "stream %d on conn %" PRIu64 " does not exist", *sid, cid);

    if (s->in_len == 0) {
        pthread_mutex_lock(&lock);
        // ev_io_start(loop, &rx_w);
        // ev_async_send(loop, &async_w);
        warn(warn, "read waiting for data");
        pthread_cond_wait(&read_cv, &lock);
        pthread_mutex_unlock(&lock);
        warn(warn, "read done");
    }

    // append data
    const size_t data_len = MIN(len, s->in_len);
    memcpy(buf, s->in, data_len);
    warn(info, "%" PRIu64 " bytes on stream %d on conn %" PRIu64 ": %s",
         s->in_len, *sid, cid, (char *)buf);
    // TODO: proper buffer handling
    memmove(buf, &((uint8_t *)(buf))[data_len], data_len);
    s->in_len -= data_len;
    return data_len;
}


uint64_t q_bind(void * const q, const uint16_t port)
{
    warn(debug, "enter");

    // put the socket into non-blocking mode
    // assert(fcntl(s, O_NONBLOCK) >= 0, "fcntl");
    struct w_sock * s = w_bind(q, ntohs(port));

    // initialize the RX watcher
    ev_io * const r = &rx_w; // suppress erroneous warning in gcc 6.2
    ev_io_init(r, rx, w_fd(s), EV_READ);

    pthread_mutex_lock(&lock);
    ev_io_start(loop, &rx_w);
    ev_async_send(loop, &async_w);
    warn(warn, "waiting for incoming connection");
    pthread_cond_wait(&accept_cv, &lock);
    warn(warn, "COND waiting for incoming connection");
    const uint64_t cid = accept_queue;
    accept_queue = 0;
    pthread_mutex_unlock(&lock);
    warn(warn, "got connection %" PRIu64, cid);
    return cid;
}


uint32_t q_rsv_stream(const uint64_t cid)
{
    struct q_conn * const c = get_conn(cid);
    assert(c, "conn %" PRIu64 " does not exist", cid);
    return new_stream(c, 0)->id;
}


static void __attribute__((nonnull))
timeout_cb(struct ev_loop * const l,
           ev_timer * const w __attribute__((unused)),
           int e __attribute__((unused)))
{
    warn(warn, "event loop timeout");
    ev_break(l, EVBREAK_ALL);
}


static void * __attribute__((nonnull)) l_run(void * const arg)
{
    struct ev_loop * l = (struct ev_loop *)arg;
    assert(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0) == 0,
           "pthread_setcanceltype");
    ev_run(l, 0);
    warn(warn, "event loop ended");
    return 0;
}


static void __attribute__((nonnull))
async_cb(struct ev_loop * const l __attribute__((unused)),
         ev_async * const w __attribute__((unused)),
         int e __attribute__((unused)))
{
    // check if we need to send any data
    hash_foreach(&q_conns, &check_conn);
}


void * q_init(const char * const ifname, const long timeout)
{
    void * const w = w_init(ifname, 0);

    warn(info, "threaded %s %s with libev %d.%d ready", quickie_name,
         quickie_version, ev_version_major(), ev_version_minor());

    // initialize some things
    srandom((unsigned)time(0));
    hash_init(&q_conns);

    // initialize the event loop, synchronization helpers and async call handler
    loop = ev_default_loop(0);
    pthread_mutex_init(&lock, 0);
    pthread_cond_init(&read_cv, 0);
    pthread_cond_init(&write_cv, 0);
    pthread_cond_init(&accept_cv, 0);
    ev_async_init(&async_w, async_cb);
    ev_async_start(loop, &async_w);

    // during development, abort event loop after some time
    if (timeout) {
        warn(debug, "setting %ld sec timeout", timeout);
        ev_timer * const t = &to_w; // suppress erroneous warning in gcc 6.2
        ev_timer_init(t, timeout_cb, timeout, 0);
        ev_timer_start(loop, &to_w);
    }

    // create the thread running ev_run
    pthread_create(&tid, 0, l_run, loop);

    return w;
}


void q_close(const uint64_t cid)
{
    warn(debug, "enter");
    struct q_conn * const c = get_conn(cid);
    assert(c, "conn %" PRIu64 " does not exist", cid);
    // TODO: block until done
    w_close(c->s);
    warn(debug, "leave");
}


void q_cleanup(void * const q)
{
    warn(debug, "enter");

    // wait for the quickie thread to end and destroy lock
    assert(pthread_join(tid, 0) == 0, "pthread_join");
    assert(pthread_mutex_destroy(&lock) == 0, "pthread_mutex_init");
    assert(pthread_cond_destroy(&read_cv) == 0, "pthread_cond_destroy");
    assert(pthread_cond_destroy(&write_cv) == 0, "pthread_cond_destroy");
    assert(pthread_cond_destroy(&accept_cv) == 0, "pthread_cond_destroy");

    w_cleanup(q);
    warn(debug, "leave");
}
