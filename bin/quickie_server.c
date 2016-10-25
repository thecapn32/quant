#include <ev.h>
#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <unistd.h>

#include "quic.h"
#include "util.h"


static void usage(const char * const name,
                  const char * const ip,
                  const char * const port,
                  const long timeout)
{
    printf("%s\n", name);
    printf("\t[-i IP]\t\tIP address to bind to; default %s\n", ip);
    printf("\t[-p port]\tdestination port; default %s\n", port);
    printf("\t[-t sec]\texit after some seconds (0 to disable); default %ld\n",
           timeout);
}


static void check_stream(void * arg, void * obj)
{
    struct q_conn * c = arg;
    struct q_stream * s = obj;
    if (s->in_len)
        warn(info,
             "received %" PRIu64 " byte%c on stream %d on conn %" PRIu64 ": %s",
             s->in_len, plural(s->in_len), s->id, c->id, s->in);
}


static void check_conn(void * obj)
{
    struct q_conn * c = obj;
    hash_foreach_arg(&c->streams, &check_stream, c);
}


static void read_cb(struct ev_loop * restrict const loop
                    __attribute__((unused)),
                    ev_async * restrict const w __attribute__((unused)),
                    int revents)
{
    assert(revents = EV_READ, "unknown event %d", revents);
    hash_foreach(&q_conns, &check_conn);
}


int main(int argc, char * argv[])
{
    char * ip = "127.0.0.1";
    char * port = "8443";
    long timeout = 5;
    int ch;

    while ((ch = getopt(argc, argv, "hi:p:t:")) != -1) {
        switch (ch) {
        case 'i':
            ip = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 't':
            timeout = strtol(optarg, 0, 10);
            assert(errno != EINVAL, "could not convert to integer");
            break;
        case 'h':
        case '?':
        default:
            usage(BASENAME(argv[0]), ip, port, timeout);
            return 0;
        }
    }

    struct addrinfo *res, *res0;
    struct addrinfo hints = {.ai_family = PF_INET,
                             .ai_socktype = SOCK_DGRAM,
                             .ai_protocol = IPPROTO_UDP,
                             .ai_flags = AI_PASSIVE};
    const int err = getaddrinfo(ip, port, &hints, &res0);
    assert(err == 0, "getaddrinfo: %s", gai_strerror(err));

    int s = -1;
    for (res = res0; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            warn(err, "socket");
            continue;
        }

        if (bind(s, res->ai_addr, res->ai_addrlen) < 0) {
            close(s);
            warn(err, "bind");
            s = -1;
            continue;
        }

        break;
    }
    assert(s >= 0, "could not bind");
    freeaddrinfo(res);

    struct ev_loop * loop = ev_default_loop(0);
    q_init(loop, timeout);
    warn(debug, "%s ready on %s:%s", BASENAME(argv[0]), ip, port);
    q_serve(s, &read_cb);
    ev_loop(loop, 0);

    close(s);
    return 0;
}
