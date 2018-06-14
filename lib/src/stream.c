// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2018, NetApp, Inc.
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


struct q_stream *
new_stream(struct q_conn * const c, const uint64_t id, const bool active)
{
    ensure(get_stream(c, id) == 0, "stream already %u exists", id);

    struct q_stream * const s = calloc(1, sizeof(*s));
    ensure(s, "could not calloc q_stream");
    s->c = c;
    sq_init(&s->out);
    sq_init(&s->in);
    s->id = id;
    s->in_data_max = id ? c->tp_local.max_strm_data : 0;
    s->out_data_max = id ? c->tp_peer.max_strm_data : 0;
    if (active) {
        if (c->next_sid == 0)
            c->next_sid = c->is_clnt ? 4 : 1;
        else
            c->next_sid += 4;
    }
    strm_to_state(s, STRM_STAT_OPEN);
    splay_insert(stream, &c->streams, s);
    warn(DBG, "reserved strm " FMT_SID " on %s conn %s", id, conn_type(c),
         scid2str(c));
    return s;
}


void free_stream(struct q_stream * const s)
{
    warn(DBG, "freeing strm " FMT_SID " on %s conn %s", s->id, conn_type(s->c),
         scid2str(s->c));

    diet_insert(&s->c->closed_streams, s->id, 0, 0);

    free_iov_sq(&s->out, s->c);
    free_iov_sq(&s->in, 0);

    splay_remove(stream, &s->c->streams, s);
    free(s);
}


void track_bytes_in(struct q_stream * const s, const uint64_t n)
{
    s->c->in_data += n;
    s->in_data += n;

    // warn(DBG,
    //      "IN: strm %u in_data=%" PRIu64 "/%" PRIu64 " in_off=%" PRIu64
    //      " C: in_data=%" PRIu64 "/%" PRIu64,
    //      s->id, s->in_data, s->in_data_max, s->in_off, s->c->in_data,
    //      s->c->tp_local.max_data);
}


void track_bytes_out(struct q_stream * const s, const uint64_t n)
{
    s->c->out_data += n;
    s->out_data += n;

    // warn(DBG,
    //      "OUT: strm %u out_data=%" PRIu64 "/%" PRIu64 " out_off=%" PRIu64
    //      " C: out_data=%" PRIu64 "/%" PRIu64,
    //      s->id, s->out_data, s->out_data_max, s->out_off, s->c->out_data,
    //      s->c->tp_peer.max_data);
}
