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

#include <ev.h>
#include <picotls.h>
#include <pthread.h>
#include <stdint.h>


/// Packet meta-data associated with w_iov buffers
struct pkt_meta {
    ev_tstamp time;   ///< Transmission timestamp.
    uint32_t ack_cnt; ///< Number of ACKs we have seen for this packet.
    uint32_t ref_cnt; ///< Reference count. Increase on assign, free when zero.
    ptls_buffer_t tb; ///< PicoTLS send buffer.
};

extern struct pkt_meta * q_pkt_meta;

#define Q_OFFSET 64

extern pthread_mutex_t lock;

extern pthread_cond_t read_cv;
extern pthread_cond_t write_cv;
extern pthread_cond_t accept_cv;
extern pthread_cond_t connect_cv;

extern struct ev_loop * loop;

/// The versions of QUIC supported by this implementation
extern const uint32_t ok_vers[];
extern const uint8_t ok_vers_len;


/// The accept "queue" - currently one deep.
extern uint64_t accept_queue;

/// TLS context.
extern ptls_context_t tls_ctx;

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
