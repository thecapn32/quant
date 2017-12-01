// SPDX-License-Identifier: BSD-2-Clause
//
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

#include <stdint.h>
#include <stdlib.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "quic.h"
#include "stream.h"


int stream_cmp(const struct q_stream * const a, const struct q_stream * const b)
{
    return (a->id > b->id) - (a->id < b->id);
}


SPLAY_GENERATE(stream, q_stream, node, stream_cmp)


struct q_stream * get_stream(struct q_conn * const c, const uint64_t id)
{
    struct q_stream which = {.id = id};
    return splay_find(stream, &c->streams, &which);
}


struct q_stream * new_stream(struct q_conn * const c, const uint64_t id)
{
    ensure(get_stream(c, id) == 0, "stream already %u exists", id);

    struct q_stream * const s = calloc(1, sizeof(*s));
    ensure(s, "could not calloc q_stream");
    s->c = c;
    sq_init(&s->out);
    sq_init(&s->in);
    s->id = id;
    s->in_off_max = c->local_max_strm_data;
    s->out_off_max = c->peer_max_strm_data;
    if (id)
        c->next_sid += 4;
    splay_insert(stream, &c->streams, s);
    warn(INF, "reserved str " FMT_SID " on %s conn " FMT_CID, id, conn_type(c),
         c->id);
    return s;
}


void free_stream(struct q_stream * const s)
{
    warn(INF, "freeing str " FMT_SID " on %s conn " FMT_CID, s->id,
         conn_type(s->c), s->c->id);

    diet_insert(&s->c->closed_streams, s->id);

    q_free(&s->out);
    q_free(&s->in);

    splay_remove(stream, &s->c->streams, s);
    free(s);
}
