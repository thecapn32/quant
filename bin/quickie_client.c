#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <unistd.h>

#include "quic.h"
#include "util.h"

#define MAX_CONNS 10


static void usage(const char * const name,
                  const char * const dest,
                  const char * const port,
                  const long conns,
                  const long timeout)
{
    printf("%s\n", name);
    printf("\t[-d destination]\tdestination; default %s\n", dest);
    printf("\t[-n connections]\tnumber of connections to start; default %ld\n",
           conns);
    printf("\t[-p port]\t\tdestination port; default %s\n", port);
    printf("\t[-t sec]\t\texit after some seconds (0 to disable); "
           "default %ld\n",
           timeout);
}


int main(int argc, char * argv[])
{
    char * dest = "127.0.0.1";
    char * port = "6121";
    long conns = 1;
    long timeout = 3;
    int ch;

    while ((ch = getopt(argc, argv, "hd:p:n:t:")) != -1) {
        switch (ch) {
        case 'd':
            dest = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'n':
            conns = strtol(optarg, 0, 10);
            assert(errno != EINVAL, "could not convert to integer");
            assert(conns <= MAX_CONNS, "only support up to %d connections",
                   MAX_CONNS);
            break;
        case 't':
            timeout = strtol(optarg, 0, 10);
            assert(errno != EINVAL, "could not convert to integer");
            break;
        case 'h':
        case '?':
        default:
            usage(basename(argv[0]), dest, port, conns, timeout);
            return 0;
        }
    }

    struct addrinfo * res;
    struct addrinfo hints = {.ai_family = PF_INET,
                             .ai_socktype = SOCK_DGRAM,
                             .ai_protocol = IPPROTO_UDP};
    const int err = getaddrinfo(dest, port, &hints, &res);
    assert(err == 0, "getaddrinfo: %s", gai_strerror(err));
    assert(res->ai_next == 0, "multiple addresses not supported");

    // start some connections
    q_init(timeout);

    uint64_t cid[MAX_CONNS];
    char msg[1024];
    const size_t msg_len = sizeof(msg);
    for (int n = 0; n < conns; n++) {
        int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        assert(s >= 0, "socket");
        warn(info, "%s starting connection #%d (desc %d) to %s:%s",
             basename(argv[0]), n, s, dest, port);
        cid[n] = q_connect(s, res->ai_addr, res->ai_addrlen);

        for (int i = 0; i < 2; i++) {
            const uint32_t sid = q_rsv_stream(cid[n]);
            snprintf(msg, msg_len,
                     "Hello, stream %d on connection %" PRIu64 "!", sid,
                     cid[n]);
            warn(info, "writing: %s", msg);
            q_write(cid[n], sid, msg, strlen(msg));
        }
        q_close(cid[n]);
    }

    freeaddrinfo(res);
    q_cleanup();
    return 0;
}
