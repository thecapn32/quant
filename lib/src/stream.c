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
#include <netinet/in.h>
#include <stddef.h> // IWYU pragma: keep
#include <picotls.h>
#include <stdint.h>
#include <stdlib.h>

#include <warpcore/warpcore.h>

#include "conn.h"
#include "quic.h"
#include "stream.h"


int64_t stream_cmp(const struct q_stream * const a,
                   const struct q_stream * const b)
{
    return (int64_t)a->id - (int64_t)b->id;
}


SPLAY_GENERATE(stream, q_stream, next, stream_cmp)


struct q_stream * get_stream(struct q_conn * const c, const uint32_t id)
{
    struct q_stream which = {.id = id};
    return SPLAY_FIND(stream, &c->streams, &which);
}


struct q_stream * new_stream(struct q_conn * const c, const uint32_t id)
{
    struct q_stream * const s = calloc(1, sizeof(*s));
    ensure(c, "could not calloc q_stream");
    s->c = c;
    STAILQ_INIT(&s->o);
    STAILQ_INIT(&s->i);

    if (id)
        // the peer has initiated this stream
        s->id = id;
    else {
        // we are initiating this stream
        s->id = c->next_sid++;
        if ((c->flags & CONN_FLAG_CLNT) != (s->id % 2) && s->id)
            // need to make this odd
            s->id++;
    }
    ensure(get_stream(c, s->id) == 0, "stream %u already exists", s->id);

    const uint8_t odd = s->id % 2; // NOTE: % in assert confuses printf
    ensure((c->flags & CONN_FLAG_CLNT) == (id ? !odd : odd) || s->id == 0,
           "am %s, expected %s connection stream ID, got %u",
           c->flags & CONN_FLAG_CLNT ? "client" : "server",
           c->flags & CONN_FLAG_CLNT ? "odd" : "even", s->id);

    SPLAY_INSERT(stream, &c->streams, s);
    warn(info, "reserved new str %u on conn %" PRIx64 " as %s", s->id, c->id,
         c->flags & CONN_FLAG_CLNT ? "client" : "server");
    return s;
}


void stream_write(struct q_stream * const s,
                  const void * const data,
                  const uint16_t len)
{
    warn(debug, "writing %u byte%s on str %u: %.*s", len, plural(len), s->id,
         len, data);

    // allocate a w_iov
    struct w_iov_stailq o;
    w_alloc_cnt(w_engine(s->c->sock), &o, 1, Q_OFFSET);
    struct w_iov * const v = STAILQ_FIRST(&o);

    ptls_buffer_t sendbuf;
    ptls_buffer_init(&sendbuf, v->buf, v->len);
    ensure(ptls_handshake(s->c->tls, &sendbuf, 0, 0, 0) ==
               PTLS_ERROR_IN_PROGRESS,
           "ptls_handshake");


    // copy data
    // memcpy(v->buf, data, len);
    // v->len = (uint16_t)ptls_get_record_overhead(s->c->tls);

    // enqueue for TX
    v->ip = ((struct sockaddr_in *)(void *)&s->c->peer)->sin_addr.s_addr;
    v->port = ((struct sockaddr_in *)(void *)&s->c->peer)->sin_port;
    STAILQ_INSERT_TAIL(&s->o, v, next);
}
