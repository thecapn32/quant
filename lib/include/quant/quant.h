// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef PARTICLE
#include <sys/socket.h>
#endif

#include <quant/config.h> // IWYU pragma: export
#include <quant/tree.h>   // IWYU pragma: export


struct w_iov_sq;
struct q_stream;


struct q_conn_conf {
    uint64_t idle_timeout;
    uint64_t tls_key_update_frequency; // seconds
    uint8_t enable_spinbit : 1;
    uint8_t enable_udp_zero_checksums : 1;
    uint8_t enable_tls_key_updates : 1; // TODO default to on eventually
    uint8_t disable_migration : 1;
    uint8_t enable_zero_len_cid : 1;
    uint8_t : 3;
};


struct q_conf {
    const struct q_conn_conf * const conn_conf;
    const char * const ticket_store; // ignored for server
    const char * const tls_cert;     // required for server
    const char * const tls_key;      // required for server
    const char * const tls_log;
    uint64_t num_bufs;
    uint8_t enable_tls_cert_verify : 1;
    uint8_t : 7;
};


struct q_conn_info {
    uint64_t pkts_in_valid;
    uint64_t pkts_in_invalid;

    uint64_t pkts_out;
    uint64_t pkts_out_lost;
    uint64_t pkts_out_rtx;

    double rtt;
    double rttvar;
    uint64_t cwnd;
    uint64_t ssthresh;
    uint64_t pto_cnt;
};


extern struct w_engine * __attribute__((nonnull(1)))
q_init(const char * const ifname, const struct q_conf * const conf);

extern void __attribute__((nonnull)) q_cleanup(struct w_engine * const w);

extern struct q_conn * __attribute__((nonnull(1, 2, 3)))
q_connect(struct w_engine * const w,
          const struct sockaddr * const peer,
          const char * const peer_name,
          struct w_iov_sq * const early_data,
          struct q_stream ** const early_data_stream,
          const bool fin,
          const char * const alpn,
          const struct q_conn_conf * const conf);

extern void __attribute__((nonnull(1))) q_close(struct q_conn * const c,
                                                const uint16_t code,
                                                const char * const reason);

extern struct q_conn * __attribute__((nonnull))
q_bind(struct w_engine * const w, const uint16_t port);

extern struct q_conn * q_accept(const struct q_conn_conf * const conf);

extern bool __attribute__((nonnull))
q_write(struct q_stream * const s, struct w_iov_sq * const q, const bool fin);

extern struct q_stream * __attribute__((nonnull))
q_read(struct q_conn * const c, struct w_iov_sq * const q, const bool all);

extern struct q_stream * __attribute__((nonnull))
q_rsv_stream(struct q_conn * const c, const bool bidi);

extern void __attribute__((nonnull)) q_close_stream(struct q_stream * const s);

extern void __attribute__((nonnull)) q_free_stream(struct q_stream * const s);

extern void __attribute__((nonnull))
q_stream_get_written(struct q_stream * const s, struct w_iov_sq * const q);

extern void __attribute__((nonnull))
q_alloc(struct w_engine * const w, struct w_iov_sq * const q, const size_t len);

extern void __attribute__((nonnull)) q_free(struct w_iov_sq * const q);

extern const char * __attribute__((nonnull)) q_cid(struct q_conn * const c);

extern uint64_t __attribute__((nonnull)) q_sid(const struct q_stream * const s);

extern void __attribute__((nonnull)) q_chunk_str(struct w_engine * const w,
                                                 const char * const str,
                                                 const size_t len,
                                                 struct w_iov_sq * o);

extern void __attribute__((nonnull)) q_write_str(struct w_engine * const w,
                                                 struct q_stream * const s,
                                                 const char * const str,
                                                 const size_t len,
                                                 const bool fin);

extern void __attribute__((nonnull)) q_write_file(struct w_engine * const w,
                                                  struct q_stream * const s,
                                                  const int f,
                                                  const size_t len,
                                                  const bool fin);

extern bool __attribute__((nonnull))
q_is_stream_closed(const struct q_stream * const s);

extern bool __attribute__((nonnull))
q_peer_closed_stream(const struct q_stream * const s);

extern bool __attribute__((nonnull))
q_is_conn_closed(const struct q_conn * const c);

extern bool __attribute__((nonnull)) q_read_stream(struct q_stream * const s,
                                                   struct w_iov_sq * const q,
                                                   const bool all);

extern bool q_ready(const uint64_t timeout, struct q_conn ** const ready);

extern bool __attribute__((nonnull))
q_is_new_serv_conn(const struct q_conn * const c);

extern bool __attribute__((nonnull))
q_is_uni_stream(const struct q_stream * const s);

#ifndef NO_MIGRATION
extern void __attribute__((nonnull))
q_rebind_sock(struct q_conn * const c, const bool use_new_dcid);
#endif

extern void __attribute__((nonnull))
q_info(struct q_conn * const c, struct q_conn_info * const ci);


#define bps(bytes, secs)                                                       \
    __extension__({                                                            \
        static char _str[32];                                                  \
        const double _bps =                                                    \
            (bytes) && (fpclassify(secs) != FP_ZERO) ? (bytes)*8 / (secs) : 0; \
        if (_bps > NSECS_PER_SEC)                                              \
            snprintf(_str, sizeof(_str), "%.3f Gb/s", _bps / NSECS_PER_SEC);   \
        else if (_bps > USECS_PER_SEC)                                         \
            snprintf(_str, sizeof(_str), "%.3f Mb/s", _bps / USECS_PER_SEC);   \
        else if (_bps > MSECS_PER_SEC)                                         \
            snprintf(_str, sizeof(_str), "%.3f Kb/s", _bps / MSECS_PER_SEC);   \
        else                                                                   \
            snprintf(_str, sizeof(_str), "%.3f b/s", _bps);                    \
        _str;                                                                  \
    })


#define timespec_to_double(diff)                                               \
    ((double)(diff).tv_sec + (double)(diff).tv_nsec / NSECS_PER_SEC)

#ifdef __cplusplus
}
#endif
