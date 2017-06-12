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
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <stddef.h> // IWYU pragma: keep
// picotls doesn't include stddef.h
#include <picotls.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#include <ev.h>
#pragma clang diagnostic pop

#include <warpcore/warpcore.h>

#include "conn.h"
#include "fnv_1a.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"

struct ev_loop;

// All open QUIC connections.
struct conn q_conns = SPLAY_INITIALIZER();


int64_t conn_cmp(const struct q_conn * const a, const struct q_conn * const b)
{
    return (int64_t)a->id - (int64_t)b->id;
}


SPLAY_GENERATE(conn, q_conn, next, conn_cmp)


static bool __attribute__((const)) vers_supported(const uint32_t v)
{
    // force version negotiation for values reserved for the purpose
    if ((v & 0x0f0f0f0f) == 0x0a0a0a0a)
        return false;

    for (uint8_t i = 0; i < ok_vers_len; i++)
        if (v == ok_vers[i])
            return true;

    // we're out of matching candidates
    warn(info, "no version in common with client");
    return false;
}


static uint32_t __attribute__((nonnull))
pick_from_server_vers(const void * const buf, const uint16_t len)
{
    const uint16_t pos = pkt_hdr_len(buf, len);
    for (uint8_t i = 0; i < ok_vers_len; i++)
        for (uint8_t j = 0; j < len - pos; j += sizeof(uint32_t)) {
            uint32_t vers = 0;
            uint16_t x = j + pos;
            dec(vers, buf, len, x, 0, "0x%08x");
            warn(debug, "server prio %ld = 0x%08x; our prio %u = 0x%08x",
                 j / sizeof(uint32_t), vers, i, ok_vers[i]);
            if (ok_vers[i] == vers)
                return vers;
        }

    // we're out of matching candidates
    warn(info, "no version in common with server");
    return 0;
}


struct q_conn * get_conn(const uint64_t id)
{
    struct q_conn which = {.id = id};
    return SPLAY_FIND(conn, &q_conns, &which);
}


void tx(struct w_sock * const ws, struct q_conn * const c)
{
    struct w_engine * const w = w_engine(ws);

    // check if there is any stream with pending data
    struct q_stream * s = 0;
    SPLAY_FOREACH(s, stream, &c->streams)
    if (!STAILQ_EMPTY(&s->o))
        break;
    if (s == 0) {
        // don't have any stream data to piggyback on, so abuse stream zero by
        // inserting an empty w_iov to carry the ACK frame
        s = get_stream(c, 0);
        stream_write(s, 0, 0);
    }

    struct w_iov_stailq q = STAILQ_HEAD_INITIALIZER(q);
    const ev_tstamp now = ev_now(loop);
    const struct w_iov * const last_sent =
        STAILQ_LAST(&c->sent_pkts, w_iov, next);
    const ev_tstamp last_sent_t =
        last_sent ? q_pkt_meta[last_sent->idx].time : -HUGE_VAL;

    while (!STAILQ_EMPTY(&s->o)) {
        struct w_iov * v = STAILQ_FIRST(&s->o);

        // see TimeToSend pseudo code
        warn(debug, "in_flight %" PRIu64 " + v->len %u vs cwnd %" PRIu64,
             c->in_flight, v->len, c->cwnd);
        warn(debug, "last_sent_t %f + (v->len %u * srtt %f) / cwnd %" PRIu64,
             last_sent_t - now, v->len, c->srtt, c->cwnd);
        if (c->in_flight + v->len > c->cwnd ||
            last_sent_t - now + (v->len * c->srtt) / c->cwnd > 0) {
            warn(warn, "out of cwnd/pacing headroom");
            break;
        }

        // move w_iov into outbound queue
        STAILQ_REMOVE_HEAD(&s->o, next);
        STAILQ_INSERT_TAIL(&q, v, next);

        switch (c->state) {
        case CONN_CLSD:
        case CONN_VERS_SENT:
            c->state = CONN_VERS_SENT;
            warn(info, "conn %" PRIx64 " now in CONN_VERS_SENT", c->id);
            break;

        case CONN_VERS_RECV:
        case CONN_ESTB:
        case CONN_FINW:
            break;

        default:
            die("TODO: state %u", c->state);
        }
        v->len = enc_pkt(c, s, v);

        // store packet info (see OnPacketSent pseudo code)
        q_pkt_meta[v->idx].time = now;
        q_pkt_meta[v->idx].ref_cnt++;

        if (v->len > Q_OFFSET) {
            // packet is retransmittable
            c->in_flight += v->len;
            set_ld_alarm(c);
        }

        warn(notice, "sending pkt %" PRIu64, c->lg_sent);
        hexdump(v->buf, v->len);
    }

    // transmit packets
    w_tx(ws, &q);
    w_nic_tx(w);
    STAILQ_CONCAT(&c->sent_pkts, &q);
}


void rx(struct ev_loop * const l __attribute__((unused)),
        ev_io * const rx_w,
        int e __attribute__((unused)))
{
    struct w_sock * const ws = rx_w->data;
    w_nic_rx(w_engine(ws), -1);
    struct w_iov_stailq i = STAILQ_HEAD_INITIALIZER(i);
    w_rx(ws, &i);

    bool tx_needed = false;
    while (!STAILQ_EMPTY(&i)) {
        struct w_iov * const v = STAILQ_FIRST(&i);
        STAILQ_REMOVE_HEAD(&i, next);

        hexdump(v->buf, v->len);
        ensure(v->len <= MAX_PKT_LEN,
               "received %u-byte packet, larger than MAX_PKT_LEN of %u", v->len,
               MAX_PKT_LEN);
        const uint16_t hdr_len = pkt_hdr_len(v->buf, v->len);
        ensure(v->len >= hdr_len,
               "%u-byte packet not large enough for %u-byte header", v->len,
               hdr_len);

        if (hdr_len + HASH_LEN < v->len) {
            // verify hash, if there seems to be one
            warn(debug, "verifying %lu-byte hash at [%u..%lu] over [0..%u]",
                 HASH_LEN, hdr_len, hdr_len + HASH_LEN - 1, v->len - 1);
            const uint64_t hash = fnv_1a(v->buf, v->len, hdr_len, HASH_LEN);
            if (memcmp(&v->buf[hdr_len], &hash, HASH_LEN) != 0)
                die("hash mismatch");
        }

        // TODO: support short headers w/o cid
        const uint64_t cid = pkt_cid(v->buf, v->len);
        struct q_conn * c = get_conn(cid);
        if (c == 0) {
            // this is a packet for a new connection, create it
            const struct sockaddr_in peer = {.sin_family = AF_INET,
                                             .sin_port = v->port,
                                             .sin_addr = {.s_addr = v->ip}};
            socklen_t peer_len = sizeof(peer);
            c = new_conn(cid, (const struct sockaddr *)&peer, peer_len, true);
            accept_queue = cid;
        }

        const uint64_t nr = pkt_nr(v->buf, v->len);
        c->lg_recv = MAX(c->lg_recv, nr);
        warn(notice, "received pkt %" PRIu64 " (max %" PRIu64 ")", nr,
             c->lg_recv);

        switch (c->state) {
        case CONN_CLSD:
        case CONN_VERS_RECV: {
            // store the socket with the connection
            c->sock = ws;

            // validate minimum packet size
            ensure(v->len >= MIN_IP4_INI_LEN, "initial packet len %u too short",
                   v->len);

            ensure(pkt_flags(v->buf) & F_LONG_HDR, "short header");
            c->state = CONN_VERS_RECV;
            warn(info, "conn %" PRIx64 " now in CONN_VERS_RECV", c->id);

            // respond to the initial version negotiation packet
            c->vers = pkt_vers(v->buf, v->len);
            struct q_stream * const s = new_stream(c, 0);
            tx_needed = true;
            if (vers_supported(c->vers)) {
                warn(debug, "supporting client-requested version 0x%08x",
                     c->vers);
                c->state = CONN_ESTB;
                warn(info, "conn %" PRIx64 " now in CONN_ESTB", c->id);
                dec_frames(c, v);

                // we should have received a ClientHello
                struct w_iov * const iv = STAILQ_FIRST(&s->i);
                ensure(memcmp((char *)iv->buf, "ClientHello", 11) == 0,
                       "no ClientHello");

                // respond with ServerHello
                stream_write(s, "ServerHello", strlen("ServerHello"));

                // this is a new connection we just accepted
                pthread_mutex_lock(&lock);
                pthread_cond_signal(&accept_cv);
                pthread_mutex_unlock(&lock);

            } else
                warn(warn, "client-requested version 0x%08x not supported",
                     c->vers);
            break;
        }

        case CONN_VERS_SENT: {
            struct q_stream * const s = get_stream(c, 0);
            tx_needed = true;
            if (pkt_flags(v->buf) & F_LONG_HDR) {
                warn(info, "server didn't like our version 0x%08x", c->vers);
                ensure(c->vers == pkt_vers(v->buf, v->len),
                       "server did not echo our version back");
                c->vers = pick_from_server_vers(v->buf, v->len);
                if (c->vers)
                    warn(info, "retrying with version 0x%08x", c->vers);
                else {
                    warn(info, "no version in common with server, closing");
                    c->vers = 0;
                    c->state = CONN_FINW;
                    warn(info, "conn %" PRIx64 " now in CONN_FINW", c->id);
                }
                tx(ws, c);
            } else {
                warn(info, "server accepted version 0x%08x", c->vers);
                c->state = CONN_ESTB;
                warn(info, "conn %" PRIx64 " now in CONN_ESTB", c->id);
                dec_frames(c, v);

                // we should have received a ServerHello
                struct w_iov * const iv = STAILQ_FIRST(&s->i);
                ensure(memcmp(iv->buf, "ServerHello", 11) == 0,
                       "no ServerHello");

                // this is a new connection we just connected
                pthread_mutex_lock(&lock);
                pthread_cond_signal(&connect_cv);
                pthread_mutex_unlock(&lock);
            }
            break;
        }

        case CONN_ESTB:
            tx_needed |= dec_frames(c, v);
            break;

        default:
            die("TODO: state %u", c->state);
        }

        // TODO: would be better to kick each connection only once
        if (tx_needed) {
            warn(info, "triggering TX");
            tx(ws, c);
        }
    }
}

static void __attribute__((nonnull))
ld_alarm_cb(struct ev_loop * const l __attribute__((unused)),
            ev_timer * const w,
            int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;

    // see OnLossDetectionAlarm pseudo code
    if (c->state < CONN_ESTB) {
        warn(info, "handshake retransmission alarm");
        tx(c->sock, c);
        c->handshake_cnt++;

    } else if (fpclassify(c->loss_t) != FP_ZERO) {
        warn(info, "early retransmit or time loss detection alarm");
        detect_lost_pkts(c);

    } else if (c->tlp_cnt < kMaxTLPs) {
        warn(info, "TLP alarm");
        // TODO: SendOnePacket()
        c->tlp_cnt++;

    } else {
        warn(info, "RTO alarm");
        if (c->rto_cnt == 0)
            c->lg_sent_before_rto = c->lg_sent;
        // TODO: SendTwoPackets();
        c->rto_cnt++;
    }

    set_ld_alarm(c);
}


void detect_lost_pkts(struct q_conn * const c)
{
    // see DetectLostPackets pseudo code
    c->loss_t = 0;
    ev_tstamp delay_until_lost = HUGE_VAL;
    if (fpclassify(c->reorder_fract) != FP_INFINITE)
        delay_until_lost = (1 + c->reorder_fract) * MAX(c->latest_rtt, c->srtt);
    else if (c->lg_acked == c->lg_sent)
        // Early retransmit alarm.
        delay_until_lost = 1.125 * MAX(c->latest_rtt, c->srtt);

    const ev_tstamp now = ev_now(loop);
    uint64_t largest_lost_packet = 0;
    struct w_iov *v, *tmp;
    STAILQ_FOREACH_SAFE (v, &c->sent_pkts, next, tmp) {
        const uint64_t nr = pkt_nr(v->buf, v->len);
        if (q_pkt_meta[v->idx].ack_cnt == 0 && nr < c->lg_acked) {
            const ev_tstamp time_since_sent = now - q_pkt_meta[v->idx].time;
            const uint64_t packet_delta = c->lg_acked - nr;
            if (time_since_sent > delay_until_lost ||
                packet_delta > c->reorder_thresh) {
                // Inform the congestion controller of lost packets and
                // lets it decide whether to retransmit immediately.
                largest_lost_packet = MAX(largest_lost_packet, nr);
                STAILQ_REMOVE(&c->sent_pkts, v, w_iov, next);

                // if this packet was retransmittable, update in_flight
                if (v->len > Q_OFFSET)
                    c->in_flight -= v->len;

                warn(info, "pkt %" PRIu64 " considered lost", nr);
            } else if (fpclassify(c->loss_t) == FP_ZERO &&
                       fpclassify(delay_until_lost) != FP_INFINITE)
                c->loss_t = now + delay_until_lost - time_since_sent;
        }
    }

    // see OnPacketsLost pseudo code

    // Start a new recovery epoch if the lost packet is larger
    // than the end of the previous recovery epoch.
    if (c->rec_end < largest_lost_packet) {
        c->rec_end = c->lg_sent;
        c->cwnd *= kLossReductionFactor;
        c->cwnd = MAX(c->cwnd, kMinimumWindow);
        c->ssthresh = c->cwnd;
    }
}


struct q_conn * new_conn(const uint64_t id,
                         const struct sockaddr * const peer,
                         const socklen_t peer_len,
                         const bool am_server)
{
    ensure(get_conn(id) == 0, "conn %" PRIx64 " already exists", id);

    struct q_conn * const c = calloc(1, sizeof(*c));
    ensure(c, "could not calloc");
    c->id = id;

    // initialize LD state
    // XXX: UsingTimeLossDetection not defined?
    c->ld_alarm.data = c;
    ev_init(&c->ld_alarm, ld_alarm_cb);
    c->reorder_thresh = kReorderingThreshold;
    c->reorder_fract = HUGE_VAL;

    // initialize CC state
    c->cwnd = kInitialWindow;
    c->ssthresh = UINT64_MAX;

    // initialize TLS state
    ensure((c->tls = ptls_new(&tls_ctx, am_server)) != 0, "alloc TLS state");

    STAILQ_INIT(&c->sent_pkts);
    SPLAY_INIT(&c->streams);
    SPLAY_INSERT(conn, &q_conns, c);

    char host[NI_MAXHOST] = "";
    char port[NI_MAXSERV] = "";
    getnameinfo((const struct sockaddr *)peer, peer_len, host, sizeof(host),
                port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    c->peer = *peer;
    c->peer_len = peer_len;
    warn(info, "creating new conn %" PRIx64 " with %s %s:%s", c->id,
         am_server ? "client" : "server", host, port);

    return c;
}


void set_ld_alarm(struct q_conn * const c)
{
    // see SetLossDetectionAlarm pseudo code

    if (c->in_flight == 0) {
        ev_timer_stop(loop, &c->ld_alarm);
        warn(debug, "no retransmittable pkts outstanding, stopping LD alarm");
        return;
    }

    ev_tstamp dur = 0;
    const ev_tstamp now = ev_now(loop);
    if (c->state < CONN_ESTB) {
        if (fpclassify(c->srtt) == FP_ZERO)
            dur = 2 * kDefaultInitialRtt;
        else
            dur = 2 * c->srtt;
        dur = MAX(dur, kMinTLPTimeout);
        dur *= 2 ^ c->handshake_cnt;
        warn(info, "handshake retransmission alarm in %f sec", dur);

    } else if (fpclassify(c->loss_t) != FP_ZERO) {
        dur = c->loss_t - now;
        warn(info, "early retransmit or time loss detection alarm in %f sec",
             dur);

    } else if (c->tlp_cnt < kMaxTLPs) {
        if (c->in_flight)
            dur = 1.5 * c->srtt + kDelayedAckTimeout;
        else
            dur = kMinTLPTimeout;
        dur = MAX(dur, 2 * c->srtt);
        warn(info, "TLP alarm in %f sec", dur);

    } else {
        dur = c->srtt + 4 * c->rttvar;
        dur = MAX(dur, kMinRTOTimeout);
        dur *= 2 ^ c->rto_cnt;
        warn(info, "RTO alarm in %f sec", dur);
    }

    c->ld_alarm.repeat = dur;
    ev_timer_again(loop, &c->ld_alarm);
}
