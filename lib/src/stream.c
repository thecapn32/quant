// Copyright (c) 2016-2017, NetApp, Inc.
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

#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "stream.h"


int32_t stream_cmp(const struct q_stream * const a,
                   const struct q_stream * const b)
{
    return (int32_t)a->id - (int32_t)b->id;
}


SPLAY_GENERATE(stream, q_stream, node, stream_cmp)


struct q_stream * get_stream(struct q_conn * const c, const uint32_t id)
{
    struct q_stream which = {.id = id};
    return splay_find(stream, &c->streams, &which);
}


struct q_stream * new_stream(struct q_conn * const c, const uint32_t id)
{
    ensure(get_stream(c, id) == 0, "stream already %u exists", id);

    struct q_stream * const s = calloc(1, sizeof(*s));
    ensure(s, "could not calloc q_stream");
    s->c = c;
    sq_init(&s->o);
    sq_init(&s->i);
    s->id = id;
    ensure(s->id <= c->max_stream_id, "sid %u <= max %u", s->id,
           c->max_stream_id);
    s->max_stream_data = c->max_stream_data;
    if (id)
        c->next_sid += 2;
    splay_insert(stream, &c->streams, s);
    warn(INF, "reserved str %u on %s conn %" PRIx64, id, conn_type(c), c->id);
    return s;
}


void free_stream(struct q_stream * const s)
{
    warn(INF, "freeing str %u on %s conn %" PRIx64, s->id, conn_type(s->c),
         s->c->id);

    diet_insert(&s->c->closed_streams, s->id);

    w_free(w_engine(s->c->sock), &s->o);
    w_free(w_engine(s->c->sock), &s->i);

    splay_remove(stream, &s->c->streams, s);
    free(s);
}
