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

#include <arpa/inet.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ev.h>
#include <picotls.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "fnv_1a.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"


struct ipnp_splay conns_by_ipnp = splay_initializer(&conns_by_ipnp);
struct cid_splay conns_by_cid = splay_initializer(&conns_by_cid);


uint16_t initial_idle_timeout = 600;
uint64_t initial_max_data = 0xFFFF;        // <= uint32_t for trans param
uint64_t initial_max_stream_data = 0x1000; // <= uint32_t for trans param
uint32_t initial_max_stream_id = 0xFF;


int ipnp_splay_cmp(const struct q_conn * const a, const struct q_conn * const b)
{
    ensure((a->peer.sin_family == AF_INET || a->peer.sin_family == 0) &&
               (b->peer.sin_family == AF_INET || b->peer.sin_family == 0),
           "limited to AF_INET");

    int diff = memcmp(&a->peer.sin_addr.s_addr, &b->peer.sin_addr.s_addr,
                      sizeof(a->peer.sin_addr.s_addr));
    if (likely(diff))
        return diff;

    diff = (a->peer.sin_port > b->peer.sin_port) -
           (a->peer.sin_port < b->peer.sin_port);
    if (likely(diff))
        return diff;

    // include only the client flag in the comparison
    return (a->flags & CONN_FLAG_CLNT) - (b->flags & CONN_FLAG_CLNT);
}


int cid_splay_cmp(const struct q_conn * const a, const struct q_conn * const b)
{
    const int diff = (a->id > b->id) - (a->id < b->id);
    if (likely(diff))
        return diff;
    // include only the client flags in the comparison
    return (a->flags & CONN_FLAG_CLNT) - (b->flags & CONN_FLAG_CLNT);
}


SPLAY_GENERATE(ipnp_splay, q_conn, node_ipnp, ipnp_splay_cmp)
SPLAY_GENERATE(cid_splay, q_conn, node_cid, cid_splay_cmp)


static bool __attribute__((const)) vers_supported(const uint32_t v)
{
    for (uint8_t i = 0; i < ok_vers_len; i++)
        if (v == ok_vers[i])
            return true;

    // we're out of matching candidates
    warn(INF, "no vers in common with clnt");
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
            warn(DBG, "server prio %ld = 0x%08x; our prio %u = 0x%08x",
                 j / sizeof(uint32_t), vers, i, ok_vers[i]);
            if (ok_vers[i] == vers)
                return vers;
        }

    // we're out of matching candidates
    warn(INF, "no vers in common with serv");
    return 0;
}


struct q_conn * get_conn_by_ipnp(const struct sockaddr_in * const peer,
                                 const uint8_t type)
{
    struct q_conn which = {.peer = *peer, .flags = type};
    return splay_find(ipnp_splay, &conns_by_ipnp, &which);
}


struct q_conn * get_conn_by_cid(const uint64_t id, const uint8_t type)
{
    struct q_conn which = {.id = id, .flags = type};
    return splay_find(cid_splay, &conns_by_cid, &which);
}


static bool tx_stream(struct q_stream * const s,
                      const bool rtx,
                      const uint8_t limit __attribute__((unused)))
{
    struct q_conn * const c = s->c;
    const ev_tstamp now = ev_now(loop);
    const struct pkt_meta * const last_tx =
        splay_max(pm_splay, &c->unacked_pkts);
    const ev_tstamp last_tx_t = last_tx ? last_tx->time : -HUGE_VAL;

    struct w_iov_sq x = sq_head_initializer(x);
    bool did_enc = false;
    struct w_iov * v;
    sq_foreach (v, &s->out, next) {
        if (meta(v).ack_cnt) {
            warn(DBG, "skipping ACKed pkt %" PRIu64, meta(v).nr);
            continue;
        }

        if (rtx != (meta(v).tx_cnt > 0)) {
            warn(DBG, "skipping %s pkt %" PRIu64 " during %s",
                 meta(v).tx_cnt ? "already-tx'ed" : "fresh", meta(v).nr,
                 rtx ? "RTX" : "TX");
            continue;
        }

        // see TimeToSend pseudo code
        if (c->in_flight + v->len > c->cwnd ||
            last_tx_t - now + (v->len * c->srtt) / c->cwnd > 0) {
            warn(DBG, "in_flight %" PRIu64 " + v->len %u vs cwnd %" PRIu64,
                 c->in_flight, v->len, c->cwnd);
            warn(DBG,
                 "last_tx_t - now %f + (v->len %u * srtt %f) / cwnd "
                 "%" PRIu64,
                 last_tx_t - now, v->len, c->srtt, c->cwnd);
            // warn(CRT, "out of cwnd/pacing headroom, ignoring");
        }

        // store packet info (see OnPacketSent pseudo code)
        meta(v).time = now; // remember TX time

        if (rtx) {
            // on RTX, remember orig pkt number (enc_pkt overwrites with new)
            diet_insert(&c->acked_pkts, meta(v).nr);
            splay_remove(pm_splay, &c->unacked_pkts, &meta(v));
        }

        enc_pkt(s, rtx, v, &x);
        did_enc = true;
        if (is_rtxable(&meta(v)))
            splay_insert(pm_splay, &c->unacked_pkts, &meta(v));
        else
            diet_insert(&c->acked_pkts, meta(v).nr);

        char buf[1024];
        diet_to_str(buf, sizeof(buf), &c->acked_pkts);
        if (!splay_empty(&c->unacked_pkts))
            warn(DBG, "unacked: %" PRIu64 "-%" PRIu64 ", acked: %s",
                 splay_min(pm_splay, &c->unacked_pkts)->nr,
                 splay_max(pm_splay, &c->unacked_pkts)->nr, buf);
        else
            warn(DBG, "unacked: -, acked: %s", buf);
    }

    if (did_enc) {
        // transmit encrypted/protected packets and then free the chain
        if (is_serv(c))
            w_connect(c->sock, c->peer.sin_addr.s_addr, c->peer.sin_port);
        w_tx(c->sock, &x);
        w_nic_tx(w_engine(c->sock));
        if (is_serv(c))
            w_disconnect(c->sock);
        // since we never touched the meta-data for x, no need for q_free()
        w_free(w_engine(c->sock), &x);
    }
    return did_enc;
}


static bool
tx_other(struct q_stream * const s, const bool rtx, const uint8_t limit)
{
    warn(DBG,
         "other %s on %s conn %" PRIx64 " str %u w/%" PRIu64 " pkt%s in queue",
         rtx ? "RTX" : "TX", conn_type(s->c), s->c->id, s->id, sq_len(&s->out),
         plural(sq_len(&s->out)));

    struct w_iov * const v =
        w_alloc_iov(w_engine(s->c->sock), Q_OFFSET, Q_OFFSET);
    struct w_iov * const last = sq_last(&s->out, w_iov, next);
    sq_insert_tail(&s->out, v, next);
    const bool did_tx = tx_stream(s, rtx, limit);
    ensure(sq_last(&s->out, w_iov, next) == v, "queue mixed up");

    // pure FINs are rtxable
    if (!is_rtxable(&meta(v))) {
        if (last)
            sq_remove_after(&s->out, last, next);
        else
            sq_remove_head(&s->out, next);
        q_free_iov(w_engine(s->c->sock), v);
    }
    return did_tx;
}


static void tx(struct q_conn * const c, const bool rtx, const uint8_t limit)
{
    bool did_tx = false;
    struct q_stream * s;
    splay_foreach (s, stream, &c->streams) {
        if (s->state != STRM_STAT_CLSD && !sq_empty(&s->out) &&
            sq_len(&s->out) > s->out_ack_cnt) {
            warn(DBG,
                 "data %s on %s conn %" PRIx64 " str %u w/%" PRIu64
                 " pkt%s in queue",
                 rtx ? "RTX" : "TX", conn_type(c), c->id, s->id,
                 sq_len(&s->out), plural(sq_len(&s->out)));
            did_tx |= tx_stream(s, rtx, limit);
        } else if ((s->state == STRM_STAT_HCLO || s->state == STRM_STAT_CLSD) &&
                   !s->fin_sent)
            did_tx |= tx_other(s, rtx, limit);
    }

    if (did_tx == false) {
        // need to ACK w/o any stream data to piggyback on, so abuse stream 0
        s = get_stream(c, 0);
        ensure(s, "no stream 0");
        tx_other(s, rtx, limit);
    }
}


void tx_w(struct ev_loop * const l __attribute__((unused)),
          ev_async * const w,
          int e __attribute__((unused)))
{
    tx(w->data, false, 0);
}


static bool __attribute__((nonnull))
verify_hash(const uint8_t * buf, const uint16_t len)
{
    uint64_t hash_rx;
    uint16_t i = len - sizeof(hash_rx);
    dec(hash_rx, buf, len, i, 0, "%" PRIx64);
    warn(DBG, "verifying %lu-byte hash %" PRIx64 " in [%lu..%u] over [0..%lu]",
         sizeof(hash_rx), hash_rx, len - sizeof(hash_rx), len - 1,
         len - sizeof(hash_rx) - 1);
    const uint64_t hash_comp = fnv_1a(buf, len - sizeof(hash_rx));
    if (hash_rx != hash_comp)
        warn(WRN, "hash mismatch: computed %" PRIx64 " vs. %" PRIx64, hash_comp,
             hash_rx);
    return hash_rx == hash_comp;
}


static uint16_t __attribute__((nonnull)) dec_aead(struct q_conn * const c,
                                                  const struct w_iov * v,
                                                  const uint16_t hdr_len)
{
    const size_t len =
        ptls_aead_decrypt(c->in_kp0, &v->buf[hdr_len], &v->buf[hdr_len],
                          v->len - hdr_len, meta(v).nr, v->buf, hdr_len);
    if (len == SIZE_MAX)
        return 0; // AEAD decrypt error
    warn(DBG, "verifying %lu-byte AEAD over [0..%u] in [%u..%u]",
         v->len - len - hdr_len, v->len - (v->len - len - hdr_len) - 1,
         v->len - (v->len - len - hdr_len), v->len - 1);
    return hdr_len + (uint16_t)len;
}


static void __attribute__((nonnull))
update_cid(struct q_conn * const c, const uint64_t cid)
{
    splay_remove(cid_splay, &conns_by_cid, c);
    c->id = cid;
    splay_insert(cid_splay, &conns_by_cid, c);
}


static void __attribute__((nonnull))
update_ipnp(struct q_conn * const c, const struct sockaddr_in * const peer)
{
    splay_remove(ipnp_splay, &conns_by_ipnp, c);
    c->peer = *peer;
    splay_insert(ipnp_splay, &conns_by_ipnp, c);
}


static void __attribute__((nonnull)) process_pkt(struct q_conn * const c,
                                                 struct w_iov * const v,
                                                 const uint16_t prot_len)
{
    struct w_engine * const w = w_engine(c->sock);
    const uint8_t flags = pkt_flags(v->buf);

    switch (c->state) {
    case CONN_STAT_IDLE:
    case CONN_STAT_VERS_REJ: {
        // validate minimum packet size
        if (v->len + prot_len < MIN_INI_LEN) {
            warn(ERR, "initial %u-byte pkt too short (< %u)", v->len + prot_len,
                 MIN_INI_LEN);
#ifndef NDEBUG
            if (util_dlevel == DBG)
                hexdump(v->buf, v->len);
#endif
            q_free_iov(w, v);
            return;
        }

        ensure(is_set(F_LONG_HDR, flags), "have a long header");

        // respond to the version negotiation packet
        c->vers = pkt_vers(v->buf, v->len);
        c->flags |= CONN_FLAG_TX;
        diet_insert(&c->recv, meta(v).nr);
        if (c->vers_initial == 0)
            c->vers_initial = c->vers;
        if (vers_supported(c->vers) && !is_force_neg_vers(c->vers)) {
            warn(INF, "supporting clnt-requested vers 0x%08x", c->vers);

            // this is a new connection; server picks a new random cid
            uint64_t cid;
            tls_ctx.random_bytes(&cid, sizeof(cid));
            warn(NTE, "picked new cid %" PRIx64 " for %s conn %" PRIx64, cid,
                 conn_type(c), c->id);
            update_cid(c, cid);
            init_tls(c);
            ensure(dec_frames(c, v), "got ClientHello");

        } else {
            c->state = CONN_STAT_VERS_REJ;
            warn(WRN,
                 "%s conn %" PRIx64
                 " clnt-requested vers 0x%08x not supported ",
                 conn_type(c), c->id, c->vers);
        }
        break;
    }

    case CONN_STAT_VERS_SENT: {
        if (is_set(F_LH_TYPE_VNEG, flags)) {
            const uint32_t vers = pkt_vers(v->buf, v->len);
            if (c->vers != vers) {
                warn(NTE,
                     "ignoring vers neg response for 0x%08x "
                     "since we're trying 0x%08x",
                     vers, c->vers);
                break;
            }

            warn(INF, "server didn't like our vers 0x%08x", vers);
            ensure(vers_supported(vers), "vers 0x%08x not one of ours", vers);
            ensure(find_sent_pkt(c, meta(v).nr, 0), "did not send pkt %" PRIu64,
                   meta(v).nr);
            if (c->vers_initial == 0)
                c->vers_initial = c->vers;
            c->vers = pick_from_server_vers(v->buf, v->len);
            if (c->vers)
                warn(INF, "retrying with vers 0x%08x", c->vers);
            else
                die("no vers in common with server");

            // retransmit the ClientHello
            init_tls(c);
            struct q_stream * s = get_stream(c, 0);
            // free the previous ClientHello
            struct w_iov * ch;
            sq_foreach (ch, &s->out, next) {
                splay_remove(pm_splay, &c->unacked_pkts, &meta(ch));
                diet_insert(&c->acked_pkts, meta(ch).nr);
            }
            q_free(w_engine(c->sock), &s->out);
            s->out_off = 0;
            tls_handshake(s);
            c->flags |= CONN_FLAG_TX;

        } else {
            warn(INF, "server accepted vers 0x%08x", c->vers);
            diet_insert(&c->recv, meta(v).nr);
            c->state = CONN_STAT_VERS_OK;
            ensure(dec_frames(c, v), "got ServerHello");
        }
        break;
    }

    case CONN_STAT_VERS_OK: {
        // pass any further data received on stream 0 to TLS and check
        // whether that completes the client handshake
        if (!is_set(F_LONG_HDR, flags) || pkt_type(flags) >= F_LH_CLNT_CTXT) {
            maybe_api_return(q_accept, c);
            c->state = CONN_STAT_ESTB;
        }
        diet_insert(&c->recv, meta(v).nr);
        c->flags |= dec_frames(c, v) ? CONN_FLAG_TX : 0;
        break;
    }

    case CONN_STAT_ESTB:
    case CONN_STAT_CLSD:
        diet_insert(&c->recv, meta(v).nr);
        c->flags |= dec_frames(c, v) ? CONN_FLAG_TX : 0;
        break;

    default:
        die("TODO: state %u", c->state);
    }
}


void rx(struct ev_loop * const l,
        ev_io * const rx_w,
        int e __attribute__((unused)))
{
    // read from NIC
    struct w_sock * const ws = rx_w->data;
    struct w_engine * const w = w_engine(ws);
    w_nic_rx(w, -1);
    struct w_iov_sq i = sq_head_initializer(i);
    sl_head(, q_conn) crx = sl_head_initializer();
    w_rx(ws, &i);

    while (!sq_empty(&i)) {
        struct w_iov * const v = sq_first(&i);
        sq_remove_head(&i, next);
        if (v->len > MAX_PKT_LEN)
            warn(WRN, "received %u-byte pkt (> %u max)", v->len, MAX_PKT_LEN);
        const uint16_t hdr_len = pkt_hdr_len(v->buf, v->len);
        if (v->len < hdr_len) {
            warn(ERR, "%u-byte pkt < %u-byte hdr; ignoring", v->len, hdr_len);
#ifndef NDEBUG
            if (util_dlevel == DBG)
                hexdump(v->buf, v->len);
#endif
            q_free_iov(w, v);
            continue;
        }

        const uint8_t flags = pkt_flags(v->buf);
        const uint8_t type = w_connected(ws) ? CONN_FLAG_CLNT : 0;
        uint64_t cid = 0;
        struct q_conn * c = 0;

        if (is_set(F_LONG_HDR, flags) || is_set(F_SH_CID, flags)) {
            cid = pkt_cid(v->buf, v->len);
            c = get_conn_by_cid(cid, type);
        }

        if (c == 0) {
            const struct sockaddr_in peer = {.sin_family = AF_INET,
                                             .sin_port = v->port,
                                             .sin_addr = {.s_addr = v->ip}};
            if (is_set(F_LONG_HDR, flags)) {
                if (type == CONN_FLAG_CLNT) {
                    // server may have picked a new cid
                    c = get_conn_by_ipnp(&peer, type);
                    warn(DBG, "got new cid %" PRIx64 " for %s conn %" PRIx64,
                         cid, conn_type(c), c->id);
                    update_cid(c, cid);
                } else {
                    warn(CRT, "new serv conn from %s:%u",
                         inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
                    const struct sockaddr_in none = {0};
                    c = get_conn_by_ipnp(&none, type);
                    if (c == 0) {
                        // TODO: maintain accept queue
                        warn(CRT, "app is not in q_accept(), ignoring");
                        continue;
                    }
                    update_ipnp(c, &peer);
                    update_cid(c, cid);
                    new_stream(c, 0);
                }

            } else
                c = get_conn_by_ipnp(&peer, type);
        }
        ensure(c, "managed to find conn");

        meta(v).nr = pkt_nr(v->buf, v->len, c);
        uint16_t prot_len = 0;
        if (is_set(F_LONG_HDR, flags) && pkt_type(flags) != F_LH_1RTT_KPH0)
            if (pkt_type(flags) == F_LH_TYPE_VNEG)
                // version negotiation responses do not carry a hash
                prot_len = UINT16_MAX;
            else
                prot_len = verify_hash(v->buf, v->len) ? sizeof(uint64_t) : 0;
        else {
            const uint16_t len = dec_aead(c, v, hdr_len);
            prot_len = len != 0 ? v->len - len : 0;
        }

        if (prot_len == 0) {
            warn(ERR, "hash mismatch or AEAD decrypt error; ignoring pkt");
#ifndef NDEBUG
            if (util_dlevel == DBG)
                hexdump(v->buf, v->len);
#endif
            q_free_iov(w, v);
            continue;
        }

        // remember that we had a RX event on this connection
        if (!is_set(CONN_FLAG_RX, c->flags)) {
            c->flags |= CONN_FLAG_RX;
            sl_insert_head(&crx, c, next);
        }

        warn(NTE,
             "recv pkt %" PRIu64
             " (len %u, idx %u, type 0x%02x = " bitstring_fmt
             ") on %s conn %" PRIx64,
             meta(v).nr, v->len, v->idx, flags, to_bitstring(flags),
             conn_type(c), cid);
        v->len -= prot_len == UINT16_MAX ? 0 : prot_len;

        process_pkt(c, v, prot_len);
    }

    // for all connections that had RX events, reset idle timeout and check if
    // we need to do a TX
    struct q_conn * c;
    sl_foreach (c, &crx, next) {
        // reset idle timeout
        ev_timer_again(l, &c->idle_alarm);

        // is a TX needed for this connection?
        if (is_set(CONN_FLAG_TX, c->flags))
            tx(c, false, 0);

        // clear the helper flags set above
        c->flags &= ~(CONN_FLAG_RX | CONN_FLAG_TX);
    }
}

#if 0
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
    struct pkt_meta *p, *nxt;

    for (p = splay_min(pm_splay, &c->unacked_pkts); p; p = nxt) {
        nxt = splay_next(pm_splay, &c->unacked_pkts, p);

        if (p->ack_cnt == 0 && p->nr < c->lg_acked) {
            const ev_tstamp time_since_sent = now - p->time;
            const uint64_t packet_delta = c->lg_acked - p->nr;
            if (time_since_sent > delay_until_lost ||
                packet_delta > c->reorder_thresh) {
                // Inform the congestion controller of lost packets and
                // lets it decide whether to retransmit immediately.
                largest_lost_packet = MAX(largest_lost_packet, p->nr);
                splay_remove(pm_splay, &c->unacked_pkts, p);
                diet_insert(&c->acked_pkts, p->nr);

                // if this packet was retransmittable, update in_flight
                if (is_rtxable(p)) {
                    c->in_flight -= stream_data_len(p);
                    warn(INF, "in_flight -%u = %" PRIu64, stream_data_len(p),
                         c->in_flight);
                }

                warn(WRN, "pkt %" PRIu64 " considered lost", p->nr);
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
#endif

void set_ld_alarm(struct q_conn * const c)
{
    // see SetLossDetectionAlarm pseudo code

    if (c->in_flight == 0) {
        ev_timer_stop(loop, &c->ld_alarm);
        warn(DBG, "no RTX-able pkts outstanding, stopping LD alarm");
        return;
    }

    ev_tstamp dur = 0;
    const ev_tstamp now = ev_now(loop);
    if (c->state < CONN_STAT_ESTB) {
        dur = fpclassify(c->srtt) == FP_ZERO ? kDefaultInitialRtt : c->srtt;
        dur = MAX(2 * dur, kMinTLPTimeout) * (1 << c->hshake_cnt);
        warn(DBG, "handshake RTX alarm in %f sec on %s conn %" PRIx64, dur,
             conn_type(c), c->id);

    } else if (fpclassify(c->loss_t) != FP_ZERO) {
        dur = c->loss_t - now;
        warn(DBG, "early RTX or time LD alarm in %f sec on %s conn %" PRIx64,
             dur, conn_type(c), c->id);

    } else if (c->tlp_cnt < kMaxTLPs) {
        if (c->in_flight)
            dur = 1.5 * c->srtt + kDelayedAckTimeout;
        else
            dur = kMinTLPTimeout;
        dur = MAX(dur, 2 * c->srtt);
        warn(DBG, "TLP alarm in %f sec on %s conn %" PRIx64, dur, conn_type(c),
             c->id);

    } else {
        dur = c->srtt + 4 * c->rttvar;
        dur = MAX(dur, kMinRTOTimeout);
        dur *= 2 ^ c->rto_cnt;
        warn(DBG, "RTO alarm in %f sec on %s conn %" PRIx64, dur, conn_type(c),
             c->id);
    }

    c->ld_alarm.repeat = dur;
    ev_timer_again(loop, &c->ld_alarm);
}


void ld_alarm(struct ev_loop * const l __attribute__((unused)),
              ev_timer * const w,
              int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    // XXX: we simply retransmit *all* unACKed packets here

    // see OnLossDetectionAlarm pseudo code
    if (c->state < CONN_STAT_ESTB) {
        c->hshake_cnt++;
        warn(INF, "handshake RTX #%u on %s conn %" PRIx64, c->hshake_cnt,
             conn_type(c), c->id);
        tx(c, true, 0);
        return;
    }

    if (fpclassify(c->loss_t) != FP_ZERO) {
        warn(INF, "early RTX or time loss detection alarm on %s conn %" PRIx64,
             conn_type(c), c->id);
        // detect_lost_pkts(c);

    } else if (c->tlp_cnt < kMaxTLPs) {
        c->tlp_cnt++;
        warn(INF, "TLP alarm #%u on %s conn %" PRIx64, c->tlp_cnt, conn_type(c),
             c->id);
        tx(c, true, 1);

    } else {
        if (c->rto_cnt == 0)
            c->lg_sent_before_rto = c->lg_sent;
        c->rto_cnt++;
        warn(INF, "RTO alarm #%u on %s conn %" PRIx64, c->rto_cnt, conn_type(c),
             c->id);
        tx(c, true, 2);
    }
    set_ld_alarm(c);
}


bool find_sent_pkt(struct q_conn * const c,
                   const uint64_t nr,
                   struct w_iov ** v)
{
    struct pkt_meta which = {.nr = nr};
    const struct pkt_meta * const p =
        splay_find(pm_splay, &c->unacked_pkts, &which);
    if (p) {
        ensure(p && p->nr == nr, "found pkt");
        struct w_iov * const f = w_iov(w_engine(c->sock), w_iov_idx(p));
        // warn(DBG, "found pkt %" PRIu64 " in idx %u len %u", nr, w_iov_idx(p),
        //      f->len);
        if (v)
            *v = f;
        return true;
    }

    // check if packet was sent and already ACKed
    if (v)
        *v = 0;
    return diet_find(&c->acked_pkts, nr);
}
