// Copyright (c) 2016, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include <warpcore.h>

#include "conn.h"
#include "frame.h"
#include "stream.h"
#include "tommy.h"


static void __attribute__((nonnull))
out_pending(void * const arg, void * const obj)
{
    const struct q_stream * const s = obj;
    const struct q_stream ** const which = arg;
    if (*which == 0 && !STAILQ_EMPTY(s->ov))
        *which = s;
}


static int __attribute__((nonnull))
cmp_q_stream(const void * const arg, const void * const obj)
{
    return *(const uint32_t * const)arg !=
           ((const struct q_stream * const)obj)->id;
}


uint16_t enc_stream_frames(struct q_conn * const c,
                           uint8_t * const buf,
                           const uint16_t len)
{
    uint16_t i = 0;

    struct q_stream * s = 0;
    hash_foreach_arg(&c->streams, out_pending, &s);
    if (s) {
        const uint32_t l = w_iov_chain_len(s->ov);
        warn(debug, "str %d has %d byte%s pending data", s->id, l, plural(l));
        i += enc_stream_frame(s, &buf[i], len - i);
    }
    // TODO: we may be able to include some a frame for some other stream here

    return i;
}

struct q_stream * get_stream(struct q_conn * const c, const uint32_t id)
{
    return hash_search(&c->streams, cmp_q_stream, &id, id);
}


struct q_stream * new_stream(struct q_conn * const c, const uint32_t id)
{
    struct q_stream * const s = calloc(1, sizeof(*s));
    ensure(c, "could not calloc q_stream");
    s->c = c;
    s->ov = calloc(1, sizeof(*s->ov));
    ensure(s->ov, "could not calloc w_chain");
    STAILQ_INIT(s->ov);

    if (id)
        // the peer has initiated this stream
        s->id = id;
    else {
        // we are initiating this stream
        s->id = plat_random() + 1;
        if ((c->flags & CONN_FLAG_CLNT) != (s->id % 2))
            // need to make this odd
            s->id++;
    }
    ensure(get_stream(c, s->id) == 0, "stream %d already exists", s->id);

    const uint8_t odd = s->id % 2; // NOTE: % in assert confuses printf
    ensure((c->flags & CONN_FLAG_CLNT) == (id ? !odd : odd),
           "am %s, expected %s connection stream ID, got %d",
           c->flags & CONN_FLAG_CLNT ? "client" : "server",
           c->flags & CONN_FLAG_CLNT ? "odd" : "even", s->id);

    hash_insert(&c->streams, &s->stream_node, s, s->id);
    warn(info, "reserved new str %d on conn %" PRIu64 " as %s", s->id, c->id,
         c->flags & CONN_FLAG_CLNT ? "client" : "server");
    return s;
}
