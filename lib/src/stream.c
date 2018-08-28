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

#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "quic.h"
#include "stream.h"


#undef STRM_STATE
#define STRM_STATE(k, v) [v] = #k

const char * const strm_state_str[] = {STRM_STATES};


int stream_cmp(const struct q_stream * const a, const struct q_stream * const b)
{
    return (a->id > b->id) - (a->id < b->id);
}


SPLAY_GENERATE(stream, q_stream, node, stream_cmp)


struct q_stream * get_stream(struct q_conn * const c, const int64_t id)
{
    struct q_stream which = {.id = id};
    return splay_find(stream, &c->streams, &which);
}


struct q_stream *
new_stream(struct q_conn * const c, const int64_t id, const bool active)
{
    if (id >= 0)
        ensure(get_stream(c, id) == 0, "stream already %u exists", id);

    struct q_stream * const s = calloc(1, sizeof(*s));
    ensure(s, "could not calloc q_stream");
    sq_init(&s->out);
    sq_init(&s->in);
    s->c = c;
    s->id = id;
    strm_to_state(s, strm_open);
    splay_insert(stream, &c->streams, s);

    if (id >= 0) {
        s->in_data_max = c->tp_local.max_strm_data_bidi_remote;
        s->out_data_max = c->tp_peer.max_strm_data_bidi_local;

        if (active) {
            if (c->next_sid == 0)
                c->next_sid = c->is_clnt ? 4 : 1;
            else
                c->next_sid += 4;
        }
    }

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if (s->id >= 0)
        warn(DBG, "reserved strm " FMT_SID " on %s conn %s", id, conn_type(c),
             scid2str(c));
#endif

    return s;
}


void free_stream(struct q_stream * const s)
{
    if (s->id >= 0)
        warn(DBG, "freeing strm " FMT_SID " on %s conn %s", s->id,
             conn_type(s->c), scid2str(s->c));

    if (s->id >= 0) {
        diet_insert(&s->c->closed_streams, (uint64_t)s->id, 0, 0);
    }

    splay_remove(stream, &s->c->streams, s);
    q_free(&s->out);
    q_free(&s->in);
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


void reset_stream(struct q_stream * const s)
{
    // reset stream offsets
    s->out_ack_cnt = s->in_off = s->out_off = 0;

    // forget we transmitted any data packets
    q_free(&s->in);
    q_free(&s->out);
}
