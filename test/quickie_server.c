#include <getopt.h>
#include <netdb.h>

#include "debug.h"
#include "quic.h"


static void
usage(const char * const name, const char * const ip, const char * const port)
{
    printf("%s\n", name);
    printf("\t[-i IP]       IP address to bind to; default %s\n", ip);
    printf("\t[-p port]     destination port; default %s\n", port);
}


int main(int argc, char * argv[])
{
    char * ip   = "127.0.0.1";
    char * port = "8443";
    int    ch;

    while ((ch = getopt(argc, argv, "hi:p:")) != -1) {
        switch (ch) {
        case 'd':
            ip = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'h':
        case '?':
        default:
            usage(argv[0], ip, port);
            return 0;
        }
    }

    struct addrinfo *res, *res0;
    struct addrinfo  hints = {.ai_family  = PF_INET,
                             .ai_socktype = SOCK_DGRAM,
                             .ai_protocol = IPPROTO_UDP,
                             .ai_flags    = AI_PASSIVE};
    const int err = getaddrinfo(ip, port, &hints, &res0);
    if (err)
        die("getaddrinfo: %s", gai_strerror(err));

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

    freeaddrinfo(res);

    if (s < 0) {
        die("could not bind");
    }

    warn(debug, "%s ready on %s:%s", argv[0], ip, port);
    q_serve(s);

    close(s);
    return 0;
}
