#include <getopt.h>
#include <netdb.h>

#include "debug.h"
#include "quic.h"


static void
usage(const char * const name, const char * const dest, const char * const port)
{
    printf("%s\n", name);
    printf("\t[-d destination]    destination; default %s\n", dest);
    printf("\t[-p port]           destination port; default %s\n", port);
}


int main(int argc, char * argv[])
{
    char * dest = "127.0.0.1";
    char * port = "6121";
    int    ch;

    while ((ch = getopt(argc, argv, "hd:p:")) != -1) {
        switch (ch) {
        case 'd':
            dest = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'h':
        case '?':
        default:
            usage(argv[0], dest, port);
            return 0;
        }
    }

    struct addrinfo *res, *res0;
    struct addrinfo  hints = {.ai_family  = PF_INET,
                             .ai_socktype = SOCK_DGRAM,
                             .ai_protocol = IPPROTO_UDP};
    const int err = getaddrinfo(dest, port, &hints, &res0);
    if (err)
        die("getaddrinfo: %s", gai_strerror(err));

    int s = -1;
    for (res = res0; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            warn(err, "socket");
            continue;
        }

        if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
            close(s);
            warn(err, "connect");
            s = -1;
            continue;
        }

        break;
    }
    freeaddrinfo(res0);

    if (s < 0) {
        die("could not connect");
    }

    warn(debug, "%s connecting to %s:%s", argv[0], dest, port);
    q_connect(s);

    close(s);
    return 0;
}
