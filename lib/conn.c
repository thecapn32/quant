#include <inttypes.h>
#include <netdb.h>

#include "conn.h"
#include "util.h"


// All open QUIC connections.
hash conns;


static int __attribute__((nonnull))
cmp_q_conn(const void * restrict const arg, const void * restrict const obj)
{
    return *(const uint64_t *)arg != ((const struct q_conn *)obj)->id;
}


struct q_conn * get_conn(const uint64_t id)
{
    return hash_search(&conns, cmp_q_conn, &id, (uint32_t)id);
}


struct q_conn * __attribute__((nonnull))
new_conn(const uint64_t id,
         const struct sockaddr * restrict const peer,
         const socklen_t plen,
         const int fd)
{
    assert(get_conn(id) == 0, "conn %" PRIu64 " already exists", id);

    struct q_conn * const c = calloc(1, sizeof(*c));
    assert(c, "could not calloc");
    c->id = id;
    c->out = 1;
    c->fd = fd;
    hash_init(&c->streams);
    hash_insert(&conns, &c->conn_node, c, (uint32_t)c->id);

    char host[NI_MAXHOST] = "";
    char port[NI_MAXSERV] = "";
    getnameinfo((const struct sockaddr *)peer, plen, host, sizeof(host), port,
                sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    c->peer = *peer;
    c->plen = plen;
    warn(info, "created new conn %" PRIu64 " with peer %s:%s", c->id, host,
         port);

    return c;
}
