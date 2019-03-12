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

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <ev.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#ifdef HAVE_ASAN
#include <sanitizer/asan_interface.h>
#else
#define ASAN_POISON_MEMORY_REGION(x, y)
#define ASAN_UNPOISON_MEMORY_REGION(x, y)
#endif

#include "bitset.h"
#include "frame.h"
#include "pn.h"


#define MAX_CID_LEN 18
#define SRT_LEN 16

struct cid {
    splay_entry(cid) node_seq;
    uint64_t seq; ///< Connection ID sequence number
    /// XXX len must precede id for cid_cmp() over both to work
    uint8_t len; ///< Connection ID length
    /// XXX id must precede srt for rand_bytes() w/both to work
    uint8_t id[MAX_CID_LEN]; ///< Connection ID
    uint8_t srt[SRT_LEN];    ///< Stateless Reset Token
    uint8_t retired : 1;
    uint8_t : 7;
    uint8_t _unused[4];
};


static inline int __attribute__((nonnull))
cids_by_seq_cmp(const struct cid * const a, const struct cid * const b)
{
    return (a->seq > b->seq) - (a->seq < b->seq);
}


static inline void __attribute__((nonnull))
cid_cpy(struct cid * const dst, const struct cid * const src)
{
    memcpy((uint8_t *)dst + offsetof(struct cid, seq),
           (const uint8_t *)src + offsetof(struct cid, seq),
           sizeof(struct cid) - offsetof(struct cid, seq) -
               sizeof(src->_unused));
}


sl_head(pm_sl, pkt_meta);


struct pkt_hdr {
    uint64_t nr;
    uint16_t len;     ///< Content of length field in long header.
    uint16_t hdr_len; ///< Length of entire QUIC header.
    uint32_t vers;
    struct cid dcid;
    struct cid scid;
    uint8_t flags; // first byte of packet
    uint8_t type;
    uint8_t _unused[6];
    // we do not store any token of LH packets in the metadata anymore
};


#define MAX_PKT_NR_LEN 4


/// Packet meta-data information associated with w_iov buffers
struct pkt_meta {
    // XXX need to potentially change pm_cpy() below if fields are reordered
    splay_entry(pkt_meta) off_node;
    sl_entry(pkt_meta) rtx_next;
    struct pm_sl rtx; ///< List of pkt_meta structs of previous TXs.

    // pm_cpy(true) starts copying from here:
    struct q_stream * stream;   ///< Stream this data was written on.
    uint64_t stream_off;        ///< Stream data offset.
    uint16_t stream_header_pos; ///< Offset of stream frame header.
    uint16_t stream_data_start; ///< Offset of first byte of stream frame data.
    uint16_t stream_data_len;   ///< Length of last stream frame data.

    uint16_t ack_block_pos; ///< Offset of first ACK block (for TX'ed pkt).
    uint64_t lg_acked; ///< "Largest Acknowledged" in ACK block (for TX'ed pkt).
    uint64_t ack_block_cnt; ///< "ACK Block Count" in ACK block (for TX'ed pkt).

    int64_t max_stream_data_sid; ///< MAX_STREAM_DATA sid, if sent.
    uint64_t max_stream_data;    ///< MAX_STREAM_DATA limit, if sent.
    uint64_t max_data;           ///< MAX_DATA limit, if sent.
    int64_t max_streams_bidi;    ///< MAX_STREAM_ID bidir limit, if sent.
    int64_t max_streams_uni;     ///< MAX_STREAM_ID unidir limit, if sent.
    struct frames frames;        ///< Frames present in pkt.

    // pm_cpy(false) starts copying from here:
    ev_tstamp tx_t;       ///< Transmission timestamp.
    struct pn_space * pn; ///< Packet number space; only set on TX.
    struct pkt_hdr hdr;

    uint16_t udp_len;     ///< Length of protected UDP packet at TX/RX.
    uint8_t has_rtx : 1;  ///< Does the w_iov hold truncated data?
    uint8_t is_acked : 1; ///< Is the w_iov ACKed?
    uint8_t is_lost : 1;  ///< Have we marked this w_iov as lost?
    uint8_t is_reset : 1; ///< This packet is a stateless reset.
    uint8_t is_fin : 1;   ///< This packet has a stream FIN bit.
    uint8_t : 3;

    uint8_t _unused[5];
};


/// Is flag @p f set in flags variable @p v?
///
/// @param      f     Flag.
/// @param      v     Variable.
///
/// @return     True if set, false otherwise.
///
#define is_set(f, v) (((v) & (f)) == (f))


static inline int __attribute__((nonnull, always_inline))
ooo_by_off_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b)
{
    return (a->stream_off > b->stream_off) - (a->stream_off < b->stream_off);
}


splay_head(ooo_by_off, pkt_meta);

SPLAY_PROTOTYPE(ooo_by_off, pkt_meta, off_node, ooo_by_off_cmp)


extern struct pkt_meta * pkt_meta;


/// Return the pkt_meta entry for a given w_iov.
///
/// @param      v     Pointer to a w_iov.
///
/// @return     Pointer to the pkt_meta entry for the w_iov.
///
#define meta(v) pkt_meta[w_iov_idx(v)]


/// Return the w_iov index of a given pkt_meta.
///
/// @param      m     Pointer to a pkt_meta entry.
///
/// @return     Index of the struct w_iov the struct pkt_meta holds meta data
///             for.
///
#define pm_idx(m) (uint32_t)((m)-pkt_meta)


static inline void __attribute__((nonnull))
pm_cpy(struct pkt_meta * const dst,
       const struct pkt_meta * const src,
       const bool also_frame_info)
{
    const size_t off = also_frame_info ? offsetof(struct pkt_meta, stream)
                                       : offsetof(struct pkt_meta, tx_t);
    memcpy((uint8_t *)dst + off, (const uint8_t *)src + off,
           sizeof(*dst) - off);
}


#define DATA_OFFSET 48 ///< Offsets of stream frame payload data we TX.

#define PATH_CHLG_LIMIT 2

#define CLNT_SCID_LEN 4
#define SERV_SCID_LEN 8

#define adj_iov_to_start(v)                                                    \
    do {                                                                       \
        (v)->buf -= meta(v).stream_data_start;                                 \
        (v)->len += meta(v).stream_data_start;                                 \
    } while (0)


#define adj_iov_to_data(v)                                                     \
    do {                                                                       \
        (v)->buf += meta(v).stream_data_start;                                 \
        (v)->len -= meta(v).stream_data_start;                                 \
    } while (0)


#define hex2str(buf, len)                                                      \
    __extension__({                                                            \
        static char _str[2 * 64 + 1] = "0";                                    \
        static const char _hex_str[] = "0123456789abcdef";                     \
        int _j;                                                                \
        for (_j = 0; (unsigned long)_j < (unsigned long)(len) && _j < 64;      \
             _j++) {                                                           \
            _str[_j * 2] =                                                     \
                _hex_str[(((const uint8_t *)(buf))[_j] >> 4) & 0x0f];          \
            _str[_j * 2 + 1] = _hex_str[((const uint8_t *)(buf))[_j] & 0x0f];  \
        }                                                                      \
        if (_j == 64)                                                          \
            _str[_j * 2 - 1] = _str[_j * 2 - 2] = _str[_j * 2 - 3] = '.';      \
        _str[_j * 2] = 0;                                                      \
        _str;                                                                  \
    })


#define has_stream_data(p) (p)->stream_header_pos


static inline bool __attribute__((nonnull))
is_ack_eliciting(const struct frames * const f)
{
    static const struct frames ack_or_pad =
        bitset_t_initializer(1 << FRM_ACK | 1 << FRM_PAD);
    struct frames not_ack_or_pad = *f;
    bit_nand(NUM_FRAM_TYPES, &not_ack_or_pad, &ack_or_pad);
    return !bit_empty(NUM_FRAM_TYPES, &not_ack_or_pad);
}


extern struct ev_loop * loop;
extern struct q_conn_sl accept_queue;

/// The versions of QUIC supported by this implementation
extern const uint32_t ok_vers[];
extern const uint8_t ok_vers_len;

// Maximum reordering in packets before packet threshold loss detection
// considers a packet lost. The RECOMMENDED value is 3.
#define kPacketThreshold 3

// Maximum reordering in time before time threshold loss detection considers a
// packet lost. Specified as an RTT multiplier. The RECOMMENDED value is 9/8.
#define kTimeThreshold 1.125

// Timer granularity. This is a system-dependent value. However, implementations
// SHOULD use a value no smaller than 1ms.
#define kGranularity 0.001

// The RTT used before an RTT sample is taken. The RECOMMENDED value is 100ms.
#define kInitialRtt 0.1

/// The sender's maximum payload size. Does not include UDP or IP overhead. The
/// max packet size is used for calculating initial and minimum congestion
/// windows.
#define kMaxDatagramSize 1200

/// Default limit on the initial amount of outstanding data in flight, in bytes.
/// Taken from [RFC6928]. The RECOMMENDED value is the minimum of 10 *
/// kMaxDatagramSize and max(2* kMaxDatagramSize, 14600)).
#define kInitialWindow                                                         \
    MIN(10 * kMaxDatagramSize, MAX(2 * kMaxDatagramSize, 14600))

/// Minimum congestion window in bytes.
#define kMinimumWindow (2 * kMaxDatagramSize)

/// Reduction in congestion window when a new loss event is detected.
#define kLossReductionDivisor 2 // kLossReductionFactor

/// Number of consecutive PTOs after which network is considered to be
/// experiencing persistent congestion. The RECOMMENDED value for
/// kPersistentCongestionThreshold is 2, which is equivalent to having two TLPs
/// before an RTO in TCP.
#define kPersistentCongestionThreshold 2


typedef void (*func_ptr)(void);
extern func_ptr api_func;
extern void *api_conn, *api_strm;


#ifndef NDEBUG
#define EV_VERIFY(l) ev_verify(l)
#else
#define EV_VERIFY(l)                                                           \
    do {                                                                       \
    } while (0)
#endif


// see https://stackoverflow.com/a/45600545/2240756
//
#define OVERLOADED_MACRO(M, ...) OVR(M, CNT_ARGS(__VA_ARGS__))(__VA_ARGS__)
#define OVR(macro_name, nargs) OVR_EXPAND(macro_name, nargs)
#define OVR_EXPAND(macro_name, nargs) macro_name##nargs
#define CNT_ARGS(...) ARG_MATCH(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1)
#define ARG_MATCH(_1, _2, _3, _4, _5, _6, _7, _8, _9, N, ...) N


#define maybe_api_return(...)                                                  \
    __extension__(OVERLOADED_MACRO(maybe_api_return, __VA_ARGS__))


/// If current API function and argument match @p func and @p arg - and @p strm
/// if it is non-zero - exit the event loop.
///
/// @param      func  The API function to potentially return to.
/// @param      conn  The connection to check API activity on.
/// @param      strm  The stream to check API activity on.
///
/// @return     True if the event loop was exited.
///
#define maybe_api_return3(func, conn, strm)                                    \
    __extension__({                                                            \
        EV_VERIFY(loop);                                                       \
        if (api_func == (func_ptr)(&(func)) && api_conn == (conn) &&           \
            ((strm) == 0 || api_strm == (strm))) {                             \
            ev_break(loop, EVBREAK_ALL);                                       \
            warn(DBG,                                                          \
                 #func "(" #conn ", " #strm ") done, exiting event loop");     \
            api_func = api_conn = api_strm = 0;                                \
        }                                                                      \
        api_func == 0;                                                         \
    })


/// If current API argument matches @p arg - and @p strm if it is non-zero -
/// exit the event loop (for any active API function).
///
/// @param      conn  The connection to check API activity on.
/// @param      strm  The stream to check API activity on.
///
/// @return     True if the event loop was exited.
///
#define maybe_api_return2(conn, strm)                                          \
    __extension__({                                                            \
        EV_VERIFY(loop);                                                       \
        if (api_conn == (conn) && ((strm) == 0 || api_strm == (strm))) {       \
            ev_break(loop, EVBREAK_ALL);                                       \
            warn(DBG, "<any>(" #conn ", " #strm ") done, exiting event loop"); \
            api_func = api_conn = api_strm = 0;                                \
        }                                                                      \
        api_func == 0;                                                         \
    })


static inline void __attribute__((nonnull)) free_iov(struct w_iov * const v)
{
    // warn(CRT, "free_iov idx %u (avail %" PRIu64 ") nr=%" PRIu64,
    // w_iov_idx(v), sq_len(&v->w->iov) + 1, meta(v).hdr.nr);

    if (meta(v).pn && meta(v).pn->sent_pkts &&
        find_sent_pkt(meta(v).pn, meta(v).hdr.nr))
        pm_by_nr_del(meta(v).pn->sent_pkts, &meta(v));

    struct pkt_meta * rm = sl_first(&meta(v).rtx);
    while (rm) {
        // ensure(rm->has_rtx, "was RTX'ed");
        sl_remove_head(&meta(v).rtx, rtx_next);
        struct pkt_meta * const next_rm = sl_next(rm, rtx_next);
        pm_by_nr_del(rm->pn->sent_pkts, rm);
        free_iov(w_iov(v->w, pm_idx(rm)));
        rm = next_rm;
    }

    memset(&meta(v), 0, sizeof(meta(v)));
    ASAN_POISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
    w_free_iov(v);
}


static inline struct w_iov * __attribute__((nonnull))
alloc_iov(struct w_engine * const w, const uint16_t len, const uint16_t off)
{
    struct w_iov * const v = w_alloc_iov(w, len, off);
    ensure(v, "w_alloc_iov failed");
    ASAN_UNPOISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
    meta(v).stream_data_start = off;
    // warn(CRT, "alloc_iov idx %u (avail %" PRIu64 ") len %u off %u",
    //      w_iov_idx(v), sq_len(&w->iov), v->len, off);
    return v;
}


extern void __attribute__((nonnull)) alloc_off(struct w_engine * const w,
                                               struct w_iov_sq * const q,
                                               const uint32_t len,
                                               const uint16_t off);


static inline struct w_iov * __attribute__((nonnull))
w_iov_dup(const struct w_iov * const v)
{
    struct w_iov * const vdup = w_alloc_iov(v->w, v->len, 0);
    ensure(vdup, "w_alloc_iov failed");
    // warn(CRT, "w_alloc_iov idx %u (avail %" PRIu64 ") len %u",
    // w_iov_idx(vdup), sq_len(&v->w->iov), vdup->len);
    ASAN_UNPOISON_MEMORY_REGION(&meta(vdup), sizeof(meta(vdup)));
    memcpy(vdup->buf, v->buf, v->len);
    memcpy(&vdup->addr, &v->addr, sizeof(v->addr));
    vdup->flags = v->flags;
    return vdup;
}


#define NRM "\x1B[0m" ///< ANSI escape sequence: reset all to normal
#define BLD "\x1B[1m" ///< ANSI escape sequence: bold
// #define DIM "\x1B[2m"   ///< ANSI escape sequence: dim
// #define ULN "\x1B[3m"   ///< ANSI escape sequence: underline
// #define BLN "\x1B[5m"   ///< ANSI escape sequence: blink
#define REV "\x1B[7m" ///< ANSI escape sequence: reverse
// #define HID "\x1B[8m"   ///< ANSI escape sequence: hidden
// #define BLK "\x1B[30m"  ///< ANSI escape sequence: black
#define RED "\x1B[31m" ///< ANSI escape sequence: red
#define GRN "\x1B[32m" ///< ANSI escape sequence: green
#define YEL "\x1B[33m" ///< ANSI escape sequence: yellow
#define BLU "\x1B[34m" ///< ANSI escape sequence: blue
#define MAG "\x1B[35m" ///< ANSI escape sequence: magenta
#define CYN "\x1B[36m" ///< ANSI escape sequence: cyan
// #define WHT "\x1B[37m"  ///< ANSI escape sequence: white

#define FMT_PNR_IN BLU "%" PRIu64 NRM
#define FMT_PNR_OUT GRN "%" PRIu64 NRM

#define FMT_SID BLD YEL "%" PRId64 NRM


#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
extern int corpus_pkt_dir, corpus_frm_dir;

extern void __attribute__((nonnull))
write_to_corpus(const int dir, const void * const data, const size_t len);
#endif
