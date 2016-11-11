#include <inttypes.h>

#include "conn.h"
#include "frame.h"
#include "stream.h"
#include "util.h"


static void out_pending(void * arg, void * obj)
{
    const struct q_stream * restrict const s = obj;
    const struct q_stream ** restrict const which = arg;
    if (*which == 0 && s->out_len)
        *which = s;
}


static int __attribute__((nonnull))
cmp_q_stream(const void * restrict const arg, const void * restrict const obj)
{
    return *(const uint32_t * restrict const)arg !=
           ((const struct q_stream * restrict const)obj)->id;
}


uint16_t enc_stream_frames(struct q_conn * restrict const c,
                           uint8_t * restrict const buf,
                           const uint16_t len)
{
    uint16_t i = 0;

    struct q_stream * s = 0;
    hash_foreach_arg(&c->streams, out_pending, &s);
    if (s) {
        warn(debug, "stream %d has %" PRIu64 " pending data", s->id,
             s->out_len);
        i += enc_stream_frame(s, &buf[i], len - i);
    }
    // TODO: we may be able to include some a frame for some other stream here

    return i;
}

struct q_stream * get_stream(struct q_conn * restrict const c,
                             const uint32_t id)
{
    return hash_search(&c->streams, cmp_q_stream, &id, id);
}


struct q_stream * new_stream(struct q_conn * restrict const c,
                             const uint32_t id)
{
    struct q_stream * restrict const s = calloc(1, sizeof(*s));
    assert(c, "could not calloc");

    if (id) {
        // the peer has initiated this stream
        s->id = id;
    } else {
        // we are initiating this stream
        s->id = (uint32_t)random() + 1;
        if ((c->flags & CONN_FLAG_CLNT) != (s->id % 2))
            // need to make this odd
            s->id++;
    }
    assert(get_stream(c, s->id) == 0, "stream %d already exists", s->id);

    const uint8_t odd = s->id % 2; // NOTE: % in assert confuses printf
    assert((c->flags & CONN_FLAG_CLNT) == (id ? !odd : odd),
           "am %s, expected %s connection stream ID, got %d",
           c->flags & CONN_FLAG_CLNT ? "client" : "server",
           c->flags & CONN_FLAG_CLNT ? "odd" : "even", s->id);

    hash_insert(&c->streams, &s->stream_node, s, s->id);
    warn(info, "reserved new stream %d on conn %" PRIu64 " as %s", s->id, c->id,
         c->flags & CONN_FLAG_CLNT ? "client" : "server");
    return s;
}
