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
#include <stdio.h>
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
    return a->is_clnt - b->is_clnt;
}


int cid_splay_cmp(const struct q_conn * const a, const struct q_conn * const b)
{
    const int diff = (a->id > b->id) - (a->id < b->id);
    if (likely(diff))
        return diff;
    // include only the client flags in the comparison
    return a->is_clnt - b->is_clnt;
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
            warn(DBG, "serv prio %ld = 0x%08x; our prio %u = 0x%08x",
                 j / sizeof(uint32_t), vers, i, ok_vers[i]);
            if (ok_vers[i] == vers)
                return vers;
        }

    // we're out of matching candidates
    warn(INF, "no vers in common with serv");
    return 0;
}


struct q_conn * get_conn_by_ipnp(const struct sockaddr_in * const peer,
                                 const bool is_clnt)
{
    struct q_conn which = {.peer = *peer, .is_clnt = is_clnt};
    return splay_find(ipnp_splay, &conns_by_ipnp, &which);
}


struct q_conn * get_conn_by_cid(const uint64_t id, const bool is_clnt)
{
    struct q_conn which = {.id = id, .is_clnt = is_clnt};
    return splay_find(cid_splay, &conns_by_cid, &which);
}


static uint32_t
tx_stream(struct q_stream * const s, const bool rtx, const uint32_t limit)
{
    struct q_conn * const c = s->c;
    const ev_tstamp now = ev_now(loop);
#if 0
    const struct pkt_meta * const last_tx =
        splay_max(pm_splay, &c->unacked_pkts);
    const ev_tstamp last_tx_t = last_tx ? last_tx->time : -HUGE_VAL;
#endif

    struct w_iov_sq x = sq_head_initializer(x);
    uint32_t encoded = 0;
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

#if 0
        // see TimeToSend pseudo code
        if (c->in_flight + v->len > c->cwnd ||
            last_tx_t - now + (v->len * c->srtt) / c->cwnd > 0) {
            warn(INF, "in_flight %" PRIu64 " + v->len %u vs cwnd %" PRIu64,
                 c->in_flight, v->len, c->cwnd);
            warn(INF,
                 "last_tx_t - now %f + (v->len %u * srtt %f) / cwnd "
                 "%" PRIu64,
                 last_tx_t - now, v->len, c->srtt, c->cwnd);
            warn(CRT, "out of cwnd/pacing headroom, ignoring");
        }
#endif

        if (rtx) {
            ensure(meta(v).is_rtxed == false, "cannot RTX an RTX");
            // on RTX, remember orig pkt meta data
            struct w_iov * const r =
                w_alloc_iov(w_engine(c->sock), Q_OFFSET, 0);
            meta(r) = meta(v);                           // copy pkt meta data
            memcpy(r->buf, v->buf - Q_OFFSET, Q_OFFSET); // copy pkt data
            meta(r).is_rtxed = true;

            // we reinsert meta(v) with its new pkt nr below
            splay_remove(pm_splay, &c->unacked_pkts, &meta(v));
            splay_insert(pm_splay, &c->unacked_pkts, &meta(r));
        }

        // store packet info (see OnPacketSent pseudo code)
        meta(v).time = now; // remember TX time

        enc_pkt(s, rtx, v, &x);
        if (meta(v).is_rtxable) {
            splay_insert(pm_splay, &c->unacked_pkts, &meta(v));
            c->in_flight += meta(v).tx_len;
            warn(INF, "in_flight +%u = %" PRIu64, meta(v).tx_len, c->in_flight);
        } else
            diet_insert(&c->acked_pkts, meta(v).nr);

        char a_buf[1024] = "";
        char ua_buf[1024] = "";
        diet_to_str(a_buf, sizeof(a_buf), &c->acked_pkts);
        for (struct pkt_meta * p = splay_min(pm_splay, &c->unacked_pkts); p;
             p = splay_next(pm_splay, &c->unacked_pkts, p)) {
            char tmp[1024] = "";
            snprintf(tmp, sizeof(tmp), "%" PRIu64 ", ", p->nr);
            strncat(ua_buf, tmp, sizeof(ua_buf) - strlen(ua_buf) - 1);
        }
        warn(CRT, "unacked: %sacked: %s", ua_buf, a_buf);

        encoded++;
        if (limit && encoded == limit) {
            warn(NTE, "tx limit %u reached", limit);
            break;
        }
    }

    if (encoded) {
        set_ld_alarm(c);
        // transmit encrypted/protected packets and then free the chain
        if (!c->is_clnt)
            w_connect(c->sock, c->peer.sin_addr.s_addr, c->peer.sin_port);
        w_tx(c->sock, &x);
        w_nic_tx(w_engine(c->sock));
        if (!c->is_clnt)
            w_disconnect(c->sock);
        // since we never touched the meta-data for x, no need for q_free()
        w_free(w_engine(c->sock), &x);
    }
    return encoded;
}


static uint32_t
tx_other(struct q_stream * const s, const bool rtx, const uint32_t limit)
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
    if (!meta(v).is_rtxable) {
        if (last)
            sq_remove_after(&s->out, last, next);
        else
            sq_remove_head(&s->out, next);
        q_free_iov(w_engine(s->c->sock), v);
    }
    return did_tx;
}


static void tx(struct q_conn * const c, const bool rtx, const uint32_t limit)
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
        c->needs_tx = true;
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
            dec_frames(c, v);

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
            struct w_iov * p;
            ensure(find_sent_pkt(c, meta(v).nr, &p),
                   "did not send pkt %" PRIu64, meta(v).nr);

            const uint32_t vers = pkt_vers(v->buf, v->len);
            if (c->vers != vers) {
                warn(NTE,
                     "ignoring vers neg response for 0x%08x "
                     "since we're trying 0x%08x",
                     vers, c->vers);
                break;
            }

            warn(INF, "serv didn't like our vers 0x%08x", vers);
            ensure(vers_supported(vers), "vers 0x%08x not one of ours", vers);

            if (c->vers_initial == 0)
                c->vers_initial = c->vers;
            c->vers = pick_from_server_vers(v->buf, v->len);
            if (c->vers)
                warn(INF, "retrying with vers 0x%08x", c->vers);
            else
                die("no vers in common with serv");

            // retransmit the ClientHello
            init_tls(c);
            // free the previous ClientHello
            struct pkt_meta *ch, *nxt;
            for (ch = splay_min(pm_splay, &c->unacked_pkts); ch; ch = nxt) {
                nxt = splay_next(pm_splay, &c->unacked_pkts, ch);
                c->in_flight -= ch->tx_len;
                splay_remove(pm_splay, &c->unacked_pkts, ch);
                diet_insert(&c->acked_pkts, ch->nr);
                q_free_iov(w_engine(c->sock),
                           w_iov(w_engine(c->sock), w_iov_idx(ch)));
            }
            struct q_stream * s = get_stream(c, 0);
            q_free(w_engine(c->sock), &s->out);
            s->out_off = 0;
            tls_handshake(s);
            c->needs_tx = true;

        } else {
            warn(INF, "serv accepted vers 0x%08x", c->vers);
            diet_insert(&c->recv, meta(v).nr);
            c->state = CONN_STAT_VERS_OK;
            dec_frames(c, v);
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
        dec_frames(c, v);
        break;
    }

    case CONN_STAT_ESTB:
    case CONN_STAT_CLSD:
        diet_insert(&c->recv, meta(v).nr);
        dec_frames(c, v);
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
        const bool is_clnt = w_connected(ws);
        uint64_t cid = 0;
        struct q_conn * c = 0;

        if (is_set(F_LONG_HDR, flags) || is_set(F_SH_CID, flags)) {
            cid = pkt_cid(v->buf, v->len);
            c = get_conn_by_cid(cid, is_clnt);
        }

        if (c == 0) {
            const struct sockaddr_in peer = {.sin_family = AF_INET,
                                             .sin_port = v->port,
                                             .sin_addr = {.s_addr = v->ip}};
            if (is_set(F_LONG_HDR, flags)) {
                if (is_clnt) {
                    // server may have picked a new cid
                    c = get_conn_by_ipnp(&peer, is_clnt);
                    warn(DBG, "got new cid %" PRIx64 " for %s conn %" PRIx64,
                         cid, conn_type(c), c->id);
                    update_cid(c, cid);
                } else {
                    warn(CRT, "new serv conn from %s:%u",
                         inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
                    const struct sockaddr_in none = {0};
                    c = get_conn_by_ipnp(&none, is_clnt);
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
                c = get_conn_by_ipnp(&peer, is_clnt);
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
        if (!c->had_rx) {
            c->had_rx = true;
            sl_insert_head(&crx, c, next);
        }

        warn(NTE,
             "rx pkt %" PRIu64 " (len %u, idx %u, type 0x%02x = " bitstring_fmt
             ") on %s conn %" PRIx64,
             meta(v).nr, v->len, v->idx, flags, to_bitstring(flags),
             conn_type(c), cid);
        v->len -= prot_len == UINT16_MAX ? 0 : prot_len;

        process_pkt(c, v, prot_len);
    }

    // for all connections that had RX events, reset idle timeout and check
    // if we need to do a TX
    struct q_conn * c;
    sl_foreach (c, &crx, next) {
        // reset idle timeout
        ev_timer_again(l, &c->idle_alarm);

        // is a TX needed for this connection?
        if (c->needs_tx)
            tx(c, false, 0);

        // clear the helper flags set above
        c->needs_tx = c->had_rx = false;

        char a_buf[1024] = "";
        char ua_buf[1024] = "";
        diet_to_str(a_buf, sizeof(a_buf), &c->acked_pkts);
        for (struct pkt_meta * p = splay_min(pm_splay, &c->unacked_pkts); p;
             p = splay_next(pm_splay, &c->unacked_pkts, p)) {
            char tmp[1024] = "";
            snprintf(tmp, sizeof(tmp), "%" PRIu64 ", ", p->nr);
            strncat(ua_buf, tmp, sizeof(ua_buf) - strlen(ua_buf) - 1);
        }
        warn(CRT, "unacked: %sacked: %s", ua_buf, a_buf);
    }
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
    struct pkt_meta *p, *nxt;

    for (p = splay_min(pm_splay, &c->unacked_pkts); p && p->nr < c->lg_acked;
         p = nxt) {
        nxt = splay_next(pm_splay, &c->unacked_pkts, p);

        const ev_tstamp time_since_sent = now - p->time;
        const uint64_t delta = c->lg_acked - p->nr;
        warn(INF,
             "pkt %" PRIu64
             ": time_since_sent %f > delay_until_lost %f || delta %" PRIu64
             " > c->reorder_thresh %" PRIu64,
             p->nr, time_since_sent, delay_until_lost, delta,
             c->reorder_thresh);
        if (time_since_sent > delay_until_lost || delta > c->reorder_thresh) {
            // Inform the congestion controller of lost packets and
            // lets it decide whether to retransmit immediately.
            largest_lost_packet = MAX(largest_lost_packet, p->nr);
            splay_remove(pm_splay, &c->unacked_pkts, p);
            diet_insert(&c->acked_pkts, p->nr);

            // if this packet was retransmittable, update in_flight
            if (p->is_rtxable) {
                c->in_flight -= p->tx_len;
                warn(INF, "in_flight -%u = %" PRIu64, p->tx_len, c->in_flight);
            }

            warn(WRN, "pkt %" PRIu64 " considered lost", p->nr);
        } else if (fpclassify(c->loss_t) == FP_ZERO &&
                   fpclassify(delay_until_lost) != FP_INFINITE)
            c->loss_t = now + delay_until_lost - time_since_sent;
    }

    // see OnPacketsLost pseudo code

    // Start a new recovery epoch if the lost packet is larger
    // than the end of the previous recovery epoch.
    if (c->rec_end < largest_lost_packet) {
        c->rec_end = c->lg_sent;
        c->cwnd *= kLossReductionFactor;
        c->cwnd = MAX(c->cwnd, kMinimumWindow);
        c->ssthresh = c->cwnd;
        warn(INF, "cwnd %" PRIu64 ", ssthresh %" PRIu64, c->cwnd, c->ssthresh);
    }
}


void set_ld_alarm(struct q_conn * const c)
{
    // see SetLossDetectionAlarm pseudo code

    if (splay_empty(&c->unacked_pkts)) {
        if (ev_is_active(&c->ld_alarm)) {
            ev_timer_stop(loop, &c->ld_alarm);
            warn(INF, "no RTX-able pkts outstanding, stopping LD alarm");
        }
        return;
    }

    ev_tstamp dur = 0;
    const ev_tstamp now = ev_now(loop);
    if (c->state < CONN_STAT_ESTB) {
        dur = fpclassify(c->srtt) == FP_ZERO ? kDefaultInitialRtt : c->srtt;
        dur = MAX(2 * dur, kMinTLPTimeout) * (1 << c->hshake_cnt);
        warn(INF, "handshake RTX alarm in %f sec on %s conn %" PRIx64, dur,
             conn_type(c), c->id);

    } else if (fpclassify(c->loss_t) != FP_ZERO) {
        dur = c->loss_t - now;
        warn(INF, "early RTX or time LD alarm in %f sec on %s conn %" PRIx64,
             dur, conn_type(c), c->id);

    } else if (c->tlp_cnt < kMaxTLPs) {
        if (!splay_empty(&c->unacked_pkts))
            dur = 1.5 * c->srtt + kDelayedAckTimeout;
        else
            dur = kMinTLPTimeout;
        dur = MAX(dur, 2 * c->srtt);
        warn(INF, "TLP alarm in %f sec on %s conn %" PRIx64, dur, conn_type(c),
             c->id);

    } else {
        dur = c->srtt + 4 * c->rttvar;
        dur = MAX(dur, kMinRTOTimeout);
        dur *= (1 << c->rto_cnt);
        warn(INF, "RTO alarm in %f sec on %s conn %" PRIx64, dur, conn_type(c),
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
        detect_lost_pkts(c);

    } else if (c->tlp_cnt < kMaxTLPs) {
        warn(INF, "TLP alarm #%u on %s conn %" PRIx64, c->tlp_cnt, conn_type(c),
             c->id);
        tx(c, true, 1);
        c->tlp_cnt++;

    } else {
        warn(INF, "RTO alarm #%u on %s conn %" PRIx64, c->rto_cnt, conn_type(c),
             c->id);
        if (c->rto_cnt == 0)
            c->lg_sent_before_rto = c->lg_sent;
        tx(c, true, 2);
        c->rto_cnt++;
    }
    set_ld_alarm(c);
}


bool find_sent_pkt(struct q_conn * const c,
                   const uint64_t nr,
                   struct w_iov ** v)
{
    struct pkt_meta which_meta = {.nr = nr};
    const struct pkt_meta * const p =
        splay_find(pm_splay, &c->unacked_pkts, &which_meta);
    if (p) {
        *v = w_iov(w_engine(c->sock), w_iov_idx(p));
        return true;
    }

    // check if packet was sent and already ACKed
    *v = 0;
    return diet_find(&c->acked_pkts, nr);
}
