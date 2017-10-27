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

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ev.h>
#include <warpcore/warpcore.h>


/// Packet meta-data information associated with w_iov buffers
struct pkt_meta {
    splay_entry(pkt_meta) nr_node;
    splay_entry(pkt_meta) off_node;
    ev_tstamp tx_t;             ///< Transmission timestamp.
    uint64_t nr;                ///< Packet number.
    uint64_t in_off;            ///< Packet number.
    struct q_stream * str;      ///< Stream this data was written on.
    uint16_t stream_header_pos; ///< Offset of stream frame header.
    uint16_t stream_data_end;   ///< Offset of last byte of stream frame data.
    uint16_t ack_header_pos;    ///< Offset of ACK frame header.
    uint16_t tx_len;            ///< Length of protected packet at TX.
    uint8_t is_rtxable : 1;     ///< Is this packet retransmittable?
    uint8_t is_rtxed : 1;       ///< Does the w_iov hold truncated data?
    uint8_t is_acked : 1;       ///< Is the w_iov ACKed?
    uint8_t : 5;
    uint8_t _unused[7];
};


extern int __attribute__((nonnull))
pm_nr_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b);

extern int __attribute__((nonnull))
pm_off_cmp(const struct pkt_meta * const a, const struct pkt_meta * const b);

splay_head(pm_nr_splay, pkt_meta);
splay_head(pm_off_splay, pkt_meta);

SPLAY_PROTOTYPE(pm_nr_splay, pkt_meta, nr_node, pm_nr_cmp)
SPLAY_PROTOTYPE(pm_off_splay, pkt_meta, off_node, pm_off_cmp)


extern struct pkt_meta * pm;


/// Return the pkt_meta entry for a given w_iov.
///
/// @param      v     Pointer to a w_iov.
///
/// @return     Pointer to the pkt_meta entry for the w_iov.
///
#define meta(v) pm[(v)->idx]


/// Return the w_iov index of a given pkt_meta.
///
/// @param      m     Pointer to a pkt_meta entry.
///
/// @return     Index of the w_iov of the pkt_meta.
///
#define w_iov_idx(m) ((m)-pm)


#define pm_cpy(dst, src)                                                       \
    memcpy((uint8_t *)(dst) + offsetof(struct pkt_meta, nr),                   \
           (uint8_t *)(src) + offsetof(struct pkt_meta, nr),                   \
           sizeof(struct pkt_meta) -                                           \
               (sizeof(struct pkt_meta) - offsetof(struct pkt_meta, nr)))

/// Offset of stream frame payload data in w_iov buffers.
#define Q_OFFSET 64


#define adj_iov_to_start(v)                                                    \
    do {                                                                       \
        (v)->buf -= Q_OFFSET;                                                  \
        (v)->len += Q_OFFSET;                                                  \
    } while (0)


#define adj_iov_to_data(v)                                                     \
    do {                                                                       \
        (v)->buf += Q_OFFSET;                                                  \
        (v)->len -= Q_OFFSET;                                                  \
    } while (0)


extern struct ev_loop * loop;

/// The versions of QUIC supported by this implementation
extern const uint32_t ok_vers[];
extern const uint8_t ok_vers_len;

/// Maximum number of tail loss probes before an RTO fires.
#define kMaxTLPs 2

/// Maximum reordering in packet number space before FACK style loss detection
/// considers a packet lost.
#define kReorderingThreshold 3

/// Maximum reordering in time space before time based loss detection considers
/// a packet lost. In fraction of an RTT.
#define kTimeReorderingFraction (1 / 8)

/// Minimum time in the future a tail loss probe alarm may be set for (in sec).
#define kMinTLPTimeout 0.01

/// Minimum time in the future an RTO alarm may be set for (in sec).
#define kMinRTOTimeout 0.2

/// The length of the peer’s delayed ack timer (in sec).
#define kDelayedAckTimeout 0.025

/// The default RTT used before an RTT sample is taken (in sec).
#define kDefaultInitialRtt 0.1

/// The default max packet size used for calculating default and minimum
/// congestion windows.
#define kDefaultMss 1460

/// Default limit on the amount of outstanding data in bytes.
#define kInitialWindow 10 * kDefaultMss

/// Default minimum congestion window.
#define kMinimumWindow 2 * kDefaultMss

/// Reduction in congestion window when a new loss event is detected.
#define kLossReductionFactor 0.5

/// Default idle timeout.
#define kIdleTimeout 10


/// Is flag @p f set in flags variable @p v?
///
/// @param      f     Flag.
/// @param      v     Variable.
///
/// @return     True if set, false otherwise.
///
#define is_set(f, v) (((v) & (f)) == (f))


typedef void (*func_ptr)(void);
extern func_ptr api_func;
extern void * api_arg;


/// If current API function and argument match @p func and @p arg, exit the
/// event loop.
///
/// @param      func  The API function currently active.
/// @param      arg   The API argument currently active.
///
#define maybe_api_return(func, arg)                                            \
    do {                                                                       \
        ensure(api_func && api_arg, "API call active");                        \
        if (api_func == (func_ptr)(&(func)) && api_arg == (arg)) {             \
            ev_break(loop, EVBREAK_ALL);                                       \
            warn(DBG, #func "(" #arg ") done, exiting event loop");            \
        }                                                                      \
    } while (0)


#define q_free_iov(c, v)                                                       \
    do {                                                                       \
        w_free_iov(w_engine((c)->sock), (v));                                  \
        meta(v) = (struct pkt_meta){0};                                        \
    } while (0)
