#include <inttypes.h>
#include <netdb.h>

#include "conn.h"
#include "quic.h"
#include "util.h"


// All open QUIC connections.
hash q_conns;


static int __attribute__((nonnull))
cmp_q_conn(const void * const arg, const void * const obj)
{
    return *(const uint64_t *)arg != ((const struct q_conn *)obj)->id;
}


struct q_conn * get_conn(const uint64_t id)
{
    return hash_search(&q_conns, cmp_q_conn, &id, (uint32_t)id);
}


struct q_conn * __attribute__((nonnull))
new_conn(const uint64_t id,
         const struct sockaddr * const peer,
         const socklen_t peer_len)
{
    assert(get_conn(id) == 0, "conn %" PRIu64 " already exists", id);

    struct q_conn * const c = calloc(1, sizeof(*c));
    assert(c, "could not calloc");
    // c->rx_w will be allocated and initialized when a w_sock exists
    c->id = id;
    c->out = 1;
    hash_init(&c->streams);
    hash_insert(&q_conns, &c->conn_node, c, (uint32_t)c->id);

    char host[NI_MAXHOST] = "";
    char port[NI_MAXSERV] = "";
    getnameinfo((const struct sockaddr *)peer, peer_len, host, sizeof(host),
                port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    c->peer = *peer;
    c->peer_len = peer_len;
    warn(info, "created new conn %" PRIu64 " with peer %s:%s", c->id, host,
         port);

    return c;
}
