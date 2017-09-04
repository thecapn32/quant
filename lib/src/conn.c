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
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <picotls.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#include <ev.h>
#pragma clang diagnostic pop

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


// Embryonic and established (actually, non-embryonic) QUIC connections.
struct ipnp_splay conns_by_ipnp = SPLAY_INITIALIZER(&conns_by_ipnp);
struct cid_splay conns_by_cid = SPLAY_INITIALIZER(&conns_by_cid);


int64_t ipnp_splay_cmp(const struct q_conn * const a,
                       const struct q_conn * const b)
{
    // warn(DBG, "%s conn %s:%u vs. %s conn %s:%u", conn_type(a),
    //      inet_ntoa(a->peer.sin_addr), ntohs(a->peer.sin_port), conn_type(b),
    //      inet_ntoa(b->peer.sin_addr), ntohs(b->peer.sin_port));
    ensure((a->peer.sin_family == AF_INET || a->peer.sin_family == 0) &&
               (b->peer.sin_family == AF_INET || b->peer.sin_family == 0),
           "limited to AF_INET");

    int diff = memcmp(&a->peer.sin_addr.s_addr, &b->peer.sin_addr.s_addr,
                      sizeof(a->peer.sin_addr.s_addr));
    if (likely(diff))
        return diff;

    diff = a->peer.sin_port - b->peer.sin_port;
    if (likely(diff))
        return diff;

    // include only the client flag in the comparison
    return (int8_t)(a->flags & CONN_FLAG_CLNT) -
           (int8_t)(b->flags & CONN_FLAG_CLNT);
}


int64_t cid_splay_cmp(const struct q_conn * const a,
                      const struct q_conn * const b)
{
    const int64_t diff = (int64_t)a->id - (int64_t)b->id;
    if (likely(diff))
        return diff;
    // include only the client and embryonic flags in the comparison
    return (int8_t)(a->flags & (CONN_FLAG_CLNT | CONN_FLAG_EMBR)) -
           (int8_t)(b->flags & (CONN_FLAG_CLNT | CONN_FLAG_EMBR));
}


SPLAY_GENERATE(ipnp_splay, q_conn, node_ipnp, ipnp_splay_cmp)
SPLAY_GENERATE(cid_splay, q_conn, node_cid, cid_splay_cmp)


#define PTLS_CLNT_LABL "EXPORTER-QUIC client 1-RTT Secret"
#define PTLS_SERV_LABL "EXPORTER-QUIC server 1-RTT Secret"


static void __attribute__((nonnull))
conn_setup_1rtt_secret(struct q_conn * const c,
                       ptls_cipher_suite_t * const cipher,
                       ptls_aead_context_t ** aead,
                       uint8_t * const sec,
                       const char * const label,
                       uint8_t is_enc)
{
    int ret = ptls_export_secret(c->tls, sec, cipher->hash->digest_size, label,
                                 ptls_iovec_init(0, 0));
    ensure(ret == 0, "ptls_export_secret");
    *aead = ptls_aead_new(cipher->aead, cipher->hash, is_enc, sec);
    ensure(aead, "ptls_aead_new");
}


static void __attribute__((nonnull)) conn_setup_1rtt(struct q_conn * const c)
{
    ptls_cipher_suite_t * const cipher = ptls_get_cipher(c->tls);
    conn_setup_1rtt_secret(c, cipher, &c->in_kp0, c->in_sec,
                           is_clnt(c) ? PTLS_SERV_LABL : PTLS_CLNT_LABL, 0);
    conn_setup_1rtt_secret(c, cipher, &c->out_kp0, c->out_sec,
                           is_clnt(c) ? PTLS_CLNT_LABL : PTLS_SERV_LABL, 1);

    c->state = CONN_STAT_VERS_OK;
    warn(INF, "%s conn %" PRIx64 " now in state %u", conn_type(c), c->id,
         c->state);
}


uint32_t tls_handshake(struct q_stream * const s)
{
    // get pointer to any received handshake data
    // XXX there is an assumption here that we only have one inbound packet
    struct w_iov * const iv = STAILQ_FIRST(&s->i);
    size_t in_len = iv ? iv->len : 0;

    // allocate a new w_iov
    struct w_iov * ov =
        w_alloc_iov(w_engine(s->c->sock), MAX_PKT_LEN, Q_OFFSET);
    ptls_buffer_init(&meta(ov).tb, ov->buf, ov->len);
    const int ret =
        ptls_handshake(s->c->tls, &meta(ov).tb, iv ? iv->buf : 0, &in_len, 0);
    ov->len = (uint16_t)meta(ov).tb.off;
    warn(INF, "TLS handshake: recv %u, gen %u, in_len %lu, ret %u: %.*s",
         iv ? iv->len : 0, ov->len, in_len, ret, ov->len, ov->buf);
    ensure(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS, "TLS error: %u", ret);
    ensure(iv == 0 || iv->len && iv->len == in_len, "TLS data remaining");

    if (iv)
        // the assumption is that ptls_handshake has consumed all stream-0 data
        w_free(w_engine(s->c->sock), &s->i);
    else {
        s->c->state = CONN_STAT_VERS_SENT;
        warn(INF, "%s conn %" PRIx64 " now in state %u", conn_type(s->c),
             s->c->id, s->c->state);
    }

    if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && ov->len != 0)
        // enqueue for TX
        STAILQ_INSERT_TAIL(&s->o, ov, next);
    else
        // we are done with the handshake, no need to TX after all
        w_free_iov(w_engine(s->c->sock), ov);

    if (ret == 0)
        conn_setup_1rtt(s->c);

    return (uint32_t)ret;
}


static bool __attribute__((const)) vers_supported(const uint32_t v)
{
    // force version negotiation for values reserved for the purpose
    if ((v & 0x0f0f0f0f) == 0x0a0a0a0a)
        return false;

    for (uint8_t i = 0; i < ok_vers_len; i++)
        if (v == ok_vers[i])
            return true;

    // we're out of matching candidates
    warn(INF, "no version in common with client");
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
    warn(INF, "no version in common with server");
    return 0;
}


struct q_conn * get_conn_by_ipnp(const struct sockaddr_in * const peer,
                                 const uint8_t type)
{
    struct q_conn which = {.peer = *peer, .flags = type};
    // warn(DBG, "looking up conn to %s:%u", inet_ntoa(peer->sin_addr),
    //      ntohs(peer->sin_port));
    return SPLAY_FIND(ipnp_splay, &conns_by_ipnp, &which);
}


struct q_conn * get_conn_by_cid(const uint64_t id, const uint8_t type)
{
    struct q_conn which = {.id = id, .flags = type};
    return SPLAY_FIND(cid_splay, &conns_by_cid, &which);
}


static void __attribute__((nonnull(1, 3))) do_tx(struct q_conn * const c,
                                                 struct q_stream * const s,
                                                 struct w_iov_stailq * const q)
{
    const ev_tstamp now = ev_now(loop);
    const struct w_iov * const last_tx =
        STAILQ_LAST(&c->sent_pkts, w_iov, next);
    const ev_tstamp last_tx_t = last_tx ? meta(last_tx).time : -HUGE_VAL;

    struct w_iov * v;
    struct w_iov_stailq x = STAILQ_HEAD_INITIALIZER(x);
    STAILQ_FOREACH (v, q, next) {
        if (s == 0 && v->len == 0) {
            warn(DBG,
                 "ignoring non-retransmittable pkt %" PRIu64 " (len %u %u)",
                 meta(v).nr, v->len, meta(v).buf_len);
            continue;
        }

        // see TimeToSend pseudo code
        if (c->in_flight + v->len > c->cwnd ||
            last_tx_t - now + (v->len * c->srtt) / c->cwnd > 0) {
            warn(DBG, "in_flight %" PRIu64 " + v->len %u vs cwnd %" PRIu64,
                 c->in_flight, v->len, c->cwnd);
            warn(DBG,
                 "last_tx_t - now %f + (v->len %u * srtt %f) / cwnd %" PRIu64,
                 last_tx_t - now, v->len, c->srtt, c->cwnd);
            warn(CRT, "out of cwnd/pacing headroom, ignoring");
        }

        // store packet info (see OnPacketSent pseudo code)
        meta(v).time = now;        // remember TX time
        meta(v).data_len = v->len; // v->len is len of stream data here

        if (s == 0) {
            warn(DBG, "RTX pkt %" PRIu64 " (len %u %u)", meta(v).nr, v->len,
                 meta(v).buf_len);

            // on RTX, remember original packet number (will be resent with new)
            diet_insert(&c->acked_pkts, meta(v).nr);
        } else
            meta(v).str = s; // remember stream this buf belongs to

        enc_pkt(c, s, v, &x);
    }

    // transmit encrypted/protected packets and then free the chain
    if (is_serv(c))
        w_connect(c->sock, c->peer.sin_addr.s_addr, c->peer.sin_port);
    w_tx(c->sock, &x);
    w_nic_tx(w_engine(c->sock));
    if (is_serv(c))
        w_disconnect(c->sock);
    w_free(w_engine(c->sock), &x);
}


static __attribute__((nonnull)) void
rtx(struct q_conn * const c, const uint32_t __attribute__((unused)) n)
{
    // we simply retransmit *all* unACKed packets here
    warn(CRT, "RTX on %s conn %" PRIx64, conn_type(c), c->id);
    do_tx(c, 0, &c->sent_pkts);
}


static void tx_ack_or_fin(struct q_stream * const s)
{
    struct w_iov * const ov =
        w_alloc_iov(w_engine(s->c->sock), MAX_PKT_LEN, Q_OFFSET);
    ov->len = 0;
    STAILQ_INSERT_TAIL(&s->o, ov, next);
    do_tx(s->c, s, &s->o);
    // ACKs and FINs are never RTXable
    STAILQ_CONCAT(&s->c->sent_pkts, &s->o);
    diet_insert(&s->c->acked_pkts, meta(ov).nr);
}


void tx(struct ev_loop * const l __attribute__((unused)),
        ev_async * const w,
        int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    struct q_stream * s = 0;
    bool did_tx = false;
    SPLAY_FOREACH (s, stream, &c->streams) {
        if (!STAILQ_EMPTY(&s->o)) {
            warn(DBG, "data TX needed on %s conn %" PRIx64 " str %u",
                 conn_type(c), c->id, s->id);
            do_tx(c, s, &s->o);
            STAILQ_CONCAT(&c->sent_pkts, &s->o);
            did_tx = true;
        } else if (s->state == STRM_STATE_HCLO || s->state == STRM_STATE_CLSD) {
            warn(DBG, "FIN needed on %s conn %" PRIx64 " str %u", conn_type(c),
                 c->id, s->id);
            tx_ack_or_fin(s);
            did_tx = true;
        }
    }

    if (did_tx == false) {
        // need to send ACKs but don't have any stream data to piggyback on
        s = get_stream(c, s ? s->id : 0);
        warn(DBG, "ACK needed on %s conn %" PRIx64, conn_type(c), c->id);
        tx_ack_or_fin(s);
    }
}


static bool __attribute__((nonnull))
verify_hash(const uint8_t * buf, const uint16_t len)
{
    uint16_t i = len - FNV_1A_LEN;
    uint64_t hash_rx;
    dec(hash_rx, buf, len, i, 0, "%" PRIx64);
    warn(DBG, "verifying %lu-byte hash %" PRIx64 " in [%lu..%u] over [0..%lu]",
         FNV_1A_LEN, hash_rx, len - FNV_1A_LEN, len - 1, len - FNV_1A_LEN - 1);
    const uint64_t hash_comp = fnv_1a(buf, len - FNV_1A_LEN);
    ensure(hash_rx == hash_comp,
           "hash mismatch: computed %" PRIx64 " vs. %" PRIx64, hash_comp,
           hash_rx);
    return hash_rx == hash_comp;
}


static uint16_t __attribute__((nonnull)) dec_aead(struct q_conn * const c,
                                                  const struct w_iov * v,
                                                  const uint16_t hdr_len)
{
    const uint16_t len = (uint16_t)ptls_aead_decrypt(
        c->in_kp0, &v->buf[hdr_len], &v->buf[hdr_len], v->len - hdr_len,
        meta(v).nr, v->buf, hdr_len);
    warn(DBG, "removing %u-byte AEAD over [0..%u]", v->len - len - hdr_len,
         v->len - hdr_len);
    return hdr_len + len;
}


void rx(struct ev_loop * const l,
        ev_io * const rx_w,
        int e __attribute__((unused)))
{
    struct w_sock * const ws = rx_w->data;
    w_nic_rx(w_engine(ws), -1);
    struct w_iov_stailq i = STAILQ_HEAD_INITIALIZER(i);
    SLIST_HEAD(, q_conn) crx = SLIST_HEAD_INITIALIZER();
    w_rx(ws, &i);

    while (!STAILQ_EMPTY(&i)) {
        struct w_iov * const v = STAILQ_FIRST(&i);
        STAILQ_REMOVE_HEAD(&i, next);
        if (v->len == 0)
            // TODO figure out why recvmmsg returns zero-length iovecs
            continue;
        // warn(DBG, "recv %u bytes", v->len);
        if (v->len > MAX_PKT_LEN)
            warn(ERR, "received %u-byte packet (> %u max); accepting", v->len,
                 MAX_PKT_LEN);
        const uint16_t hdr_len = pkt_hdr_len(v->buf, v->len);
        ensure(v->len >= hdr_len,
               "%u-byte packet not large enough for %u-byte header", v->len,
               hdr_len);

        // #ifndef NDEBUG
        //         if (_dlevel == debug)
        //             hexdump(v->buf, v->len);
        // #endif
        // TODO: support short headers w/o cid
        const uint64_t nr = meta(v).nr = pkt_nr(v->buf, v->len);
        const uint64_t cid = pkt_cid(v->buf, v->len);
        const uint8_t type = w_connected(ws) ? CONN_FLAG_CLNT : 0;
        struct q_conn * c = get_conn_by_cid(cid, type);
        bool prot_verified = false;
        if (c == 0) {
            if (is_set(F_LONG_HDR, pkt_flags(v->buf)) &&
                pkt_type(v->buf) != F_LH_1RTT_KPH0) {
                verify_hash(v->buf, v->len);
                v->len -= FNV_1A_LEN;
                prot_verified = true;
            }

            // this might be the first packet for a new connection, or a dup CH
            warn(DBG, "conn %" PRIx64 " may be new", cid);
            const struct sockaddr_in peer = {.sin_family = AF_INET,
                                             .sin_port = v->port,
                                             .sin_addr = {.s_addr = v->ip}};
            c = get_conn_by_ipnp(&peer, type | CONN_FLAG_EMBR);
            if (c == 0) {
                warn(DBG, "conn %" PRIx64 " definitely new", cid);
                struct sockaddr_in none = {0};
                c = get_conn_by_ipnp(&none, type | CONN_FLAG_EMBR);
                ensure(c, "no embr conn");
                // update the conn in the global structs (TODO make less ugly)
                c->peer = (struct sockaddr_in){.sin_family = AF_INET,
                                               .sin_port = v->port,
                                               .sin_addr = {.s_addr = v->ip}};
                // this is a new connection; server picks a new random cid
                c->id = ((((uint64_t)plat_random()) << 32) |
                         ((uint64_t)plat_random()));
                warn(NTE, "%s picked new cid %" PRIx64 " for conn %" PRIx64,
                     conn_type(c), c->id, cid);

            } else {
                // we have a connection from this peer
                ensure(c->state < CONN_STAT_ESTB, "handshaking");
                warn(DBG, "%s conn %" PRIx64 " is in handshake", conn_type(c),
                     cid);
                c->id = cid;
                c->flags &= ~CONN_FLAG_EMBR;
            }
            SPLAY_REMOVE(ipnp_splay, &conns_by_ipnp, c);
            SPLAY_INSERT(ipnp_splay, &conns_by_ipnp, c);
            SPLAY_REMOVE(cid_splay, &conns_by_cid, c);
            SPLAY_INSERT(cid_splay, &conns_by_cid, c);
        }

        if (is_set(F_LONG_HDR, pkt_flags(v->buf)) &&
            pkt_type(v->buf) != F_LH_1RTT_KPH0) {
            if (prot_verified == false) {
                verify_hash(v->buf, v->len);
                v->len -= FNV_1A_LEN;
            }
        } else
            v->len = dec_aead(c, v, hdr_len);

        // #ifndef NDEBUG
        //         if (_dlevel == debug)
        //             hexdump(v->buf, v->len);
        // #endif

        // remember that we had a RX event on this connection
        if (!is_set(CONN_FLAG_RX, c->flags)) {
            c->flags |= CONN_FLAG_RX;
            SLIST_INSERT_HEAD(&crx, c, next);
        }

        diet_insert(&c->recv, nr);
        warn(NTE, "recv pkt %" PRIu64
                  " (len %u, idx %u, type 0x%02x = " bitstring_fmt
                  ") on %s conn %" PRIx64,
             nr, v->len, v->idx, pkt_flags(v->buf),
             to_bitstring(pkt_flags(v->buf)), conn_type(c), c->id);

        switch (c->state) {
        case CONN_STAT_IDLE:
            new_stream(c, 0); // create stream 0 (server case)
        // fall-through

        case CONN_STAT_VERS_REJ: {
            // store the socket with the connection
            c->sock = ws;

            // validate minimum packet size
            ensure(v->len >= MIN_INI_LEN, "initial packet len %u too short",
                   v->len);

            ensure(is_set(F_LONG_HDR, pkt_flags(v->buf)), "short header");

            // respond to the version negotiation packet
            c->vers = pkt_vers(v->buf, v->len);
            struct q_stream * const s = get_stream(c, 0);
            c->flags |= CONN_FLAG_TX;
            if (vers_supported(c->vers)) {
                warn(INF, "supporting client-requested version 0x%08x",
                     c->vers);

                dec_frames(c, v);

                // we should have received a ClientHello
                ensure(!STAILQ_EMPTY(&s->i), "no ClientHello");
                tls_handshake(s);

                warn(INF, "%s conn %" PRIx64 " now in state %u", conn_type(c),
                     c->id, c->state);

            } else {
                c->state = CONN_STAT_VERS_REJ;
                warn(INF, "%s conn %" PRIx64 " now in state %u", conn_type(c),
                     c->id, c->state);
                warn(WRN, "%s conn %" PRIx64
                          " client-requested version 0x%08x not supported ",
                     conn_type(c), c->id, c->vers);
            }
            break;
        }

        case CONN_STAT_VERS_SENT: {
            struct q_stream * const s = get_stream(c, 0);
            c->flags |= CONN_FLAG_TX;
            if (is_set(F_LH_TYPE_VNEG, pkt_flags(v->buf))) {
                warn(INF, "server didn't like our version 0x%08x", c->vers);
                ensure(c->vers == pkt_vers(v->buf, v->len),
                       "server did not echo our version back");
                c->vers = pick_from_server_vers(v->buf, v->len);
                if (c->vers)
                    warn(INF, "retrying with version 0x%08x", c->vers);
                else
                    die("no version in common with server");
                rtx(c, UINT32_MAX); // retransmit the ClientHello
            } else {
                warn(INF, "server accepted version 0x%08x", c->vers);
                c->state = CONN_STAT_VERS_OK;

                // we should have received a ServerHello
                c->flags |= dec_frames(c, v) ? CONN_FLAG_TX : 0;
                ensure(!STAILQ_EMPTY(&s->i), "no ServerHello");
                if (tls_handshake(s) == 0)
                    maybe_api_return(q_connect, c);
            }
            break;
        }

        case CONN_STAT_VERS_OK: {
            // pass any further data received on stream 0 to TLS and check
            // whether that completes the client handshake
            c->flags |= dec_frames(c, v) ? CONN_FLAG_TX : 0;
            struct q_stream * const s = get_stream(c, 0);
            if (!STAILQ_EMPTY(&s->i) && tls_handshake(s) == 0) {
                maybe_api_return(q_accept, c);
                maybe_api_return(q_connect, c);
            }
        } break;

        case CONN_STAT_ESTB:
        case CONN_STAT_CLSD:
            c->flags |= dec_frames(c, v) ? CONN_FLAG_TX : 0;
            break;

        default:
            die("TODO: state %u", c->state);
        }
    }

    // for all connections that had RX events, reset idle timeout and check if
    // we need to do a TX
    struct q_conn * c;
    SLIST_FOREACH (c, &crx, next) {
        // reset idle timeout
        ev_timer_again(loop, &c->idle_alarm);

        // is a TX needed for this connection?
        if (is_set(CONN_FLAG_TX, c->flags))
            tx(l, &c->tx_w, 0);

        // clear the helper flags set above
        c->flags &= ~(CONN_FLAG_RX | CONN_FLAG_TX);
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
    struct w_iov *v, *tmp;
    STAILQ_FOREACH_SAFE (v, &c->sent_pkts, next, tmp) {
        const uint64_t nr = meta(v).nr;
        if (meta(v).ack_cnt == 0 && nr < c->lg_acked) {
            const ev_tstamp time_since_sent = now - meta(v).time;
            const uint64_t packet_delta = c->lg_acked - nr;
            if (time_since_sent > delay_until_lost ||
                packet_delta > c->reorder_thresh) {
                // Inform the congestion controller of lost packets and
                // lets it decide whether to retransmit immediately.
                largest_lost_packet = MAX(largest_lost_packet, nr);
                STAILQ_REMOVE(&c->sent_pkts, v, w_iov, next);

                // if this packet was retransmittable, update in_flight
                if (v->len > Q_OFFSET) {
                    c->in_flight -= v->len;
                    warn(INF, "in_flight -%u = %" PRIu64, v->len, c->in_flight);
                }

                warn(WRN, "pkt %" PRIu64 " considered lost", nr);
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
        dur = MAX(2 * dur, kMinTLPTimeout) * (1 << c->handshake_cnt);
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

    // see OnLossDetectionAlarm pseudo code
    if (c->state < CONN_STAT_ESTB) {
        warn(INF, "handshake RTX alarm on %s conn %" PRIx64, conn_type(c),
             c->id);
        rtx(c, UINT32_MAX);
        // tx above already calls set_ld_alarm(c)
        c->handshake_cnt++;
        return;
    }

    if (fpclassify(c->loss_t) != FP_ZERO) {
        warn(INF, "early RTX or time loss detection alarm on %s conn %" PRIx64,
             conn_type(c), c->id);
        detect_lost_pkts(c);

    } else if (c->tlp_cnt < kMaxTLPs) {
        warn(INF, "TLP alarm on %s conn %" PRIx64, conn_type(c), c->id);
        rtx(c, 1);
        c->tlp_cnt++;

    } else {
        warn(INF, "RTO alarm on %s conn %" PRIx64, conn_type(c), c->id);
        if (c->rto_cnt == 0)
            c->lg_sent_before_rto = c->lg_sent;
        rtx(c, 2);
        c->rto_cnt++;
    }
    set_ld_alarm(c);
}
