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

#include <arpa/inet.h>
#include <bitstring.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ev.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#ifdef HAVE_ASAN
#include <sanitizer/asan_interface.h>
#endif

#include "conn.h"
#include "diet.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"


struct ipnp_splay conns_by_ipnp = splay_initializer(&conns_by_ipnp);
struct cid_splay conns_by_cid = splay_initializer(&conns_by_cid);


int ipnp_splay_cmp(const struct q_conn * const a, const struct q_conn * const b)
{
    ensure((a->peer.sin_family == AF_INET || a->peer.sin_family == 0) &&
               (b->peer.sin_family == AF_INET || b->peer.sin_family == 0),
           "limited to AF_INET");

    int diff = (a->sport > b->sport) - (a->sport < b->sport);
    if (diff)
        return diff;

    diff = memcmp(&a->peer.sin_addr.s_addr, &b->peer.sin_addr.s_addr,
                  sizeof(a->peer.sin_addr.s_addr));
    if (likely(diff))
        return diff;

    diff = (a->peer.sin_port > b->peer.sin_port) -
           (a->peer.sin_port < b->peer.sin_port);
    if (likely(diff))
        return diff;

    // include only the client flag in the comparison
    return (a->is_clnt > b->is_clnt) - (a->is_clnt < b->is_clnt);
}


int cid_splay_cmp(const struct q_conn * const a, const struct q_conn * const b)
{
    // intentionally including id + len in this memcmp
    const int diff = memcmp(&a->scid, &b->scid, sizeof(a->scid));
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
pick_from_server_vers(const struct w_iov * const v)
{
    const uint16_t pos = meta(v).hdr.hdr_len;
    for (uint8_t i = 0; i < ok_vers_len; i++)
        for (uint8_t j = 0; j < v->len - pos; j += sizeof(uint32_t)) {
            uint32_t vers = 0;
            uint16_t x = j + pos;
            dec(&vers, v->buf, v->len, x, sizeof(vers), "0x%08x");
            warn(DBG, "serv prio %ld = 0x%08x; our prio %u = 0x%08x",
                 j / sizeof(uint32_t), vers, i, ok_vers[i]);
            if (ok_vers[i] == vers)
                return vers;
        }

    // we're out of matching candidates
    warn(INF, "no vers in common with serv");
    return 0;
}


struct q_conn * get_conn_by_ipnp(const uint16_t sport,
                                 const struct sockaddr_in * const peer,
                                 const bool is_clnt)
{
    const struct q_conn which = {
        .peer = *peer, .is_clnt = is_clnt, .sport = sport};
    return splay_find(ipnp_splay, &conns_by_ipnp, &which);
}


struct q_conn * get_conn_by_cid(const struct cid * const scid,
                                const bool is_clnt)
{
    const struct q_conn which = {.scid = *scid, .is_clnt = is_clnt};
    return splay_find(cid_splay, &conns_by_cid, &which);
}


static void log_sent_pkts(struct q_conn * const c)
{
    char sent_pkts_buf[1024] = "";
    uint64_t prev = 0;
    struct pkt_meta * p = 0;
    splay_foreach (p, pm_nr_splay, &c->rec.sent_pkts) {
        char tmp[1024] = "";
        const bool ack_only = is_ack_only(p);
        snprintf(tmp, sizeof(tmp), "%s%s" FMT_PNR_OUT "%s ",
                 is_rtxable(p) ? "*" : "", ack_only ? "(" : "",
                 shorten_ack_nr(p->hdr.nr, p->hdr.nr - prev),
                 ack_only ? ")" : "");
        strncat(sent_pkts_buf, tmp,
                sizeof(sent_pkts_buf) - strlen(sent_pkts_buf) - 1);
        prev = p->hdr.nr;
    }
    warn(DBG, "unacked: %s", sent_pkts_buf);
}


static void __attribute__((nonnull))
rtx_pkt(struct q_stream * const s, struct w_iov * const v)
{
    ensure(meta(v).is_rtxed == false, "cannot RTX an RTX");
    // on RTX, remember orig pkt meta data
    struct w_iov * const r = q_alloc_iov(s->c->w, 0, Q_OFFSET);
    pm_cpy(&meta(r), &meta(v));                  // copy pkt meta data
    memcpy(r->buf, v->buf - Q_OFFSET, Q_OFFSET); // copy pkt headers
    meta(r).is_rtxed = true;
    meta(r).rtx = &meta(v);
    adj_iov_to_data(r);

    // we reinsert meta(v) with its new pkt nr in on_pkt_sent()
    splay_remove(pm_nr_splay, &s->c->rec.sent_pkts, &meta(v));
    splay_insert(pm_nr_splay, &s->c->rec.sent_pkts, &meta(r));
}


static uint32_t __attribute__((nonnull(1))) tx_stream(struct q_stream * const s,
                                                      const bool rtx,
                                                      const uint32_t limit,
                                                      struct w_iov * const from)
{
    struct w_iov_sq x = sq_head_initializer(x);
    uint32_t encoded = 0;
    struct w_iov * v = from;
    sq_foreach (v, &s->out, next) {
        if (meta(v).is_acked) {
            warn(DBG,
                 "skipping ACKed pkt " FMT_PNR_OUT " on str " FMT_SID
                 " during %s",
                 meta(v).hdr.nr, s->id, rtx ? "RTX" : "TX");
            continue;
        }

        if (s->c->state == CONN_STAT_ESTB &&
            s->out_off + v->len > s->out_data_max) {
            warn(INF, "out of FC window for str " FMT_SID, meta(v).hdr.nr,
                 s->id);
            s->blocked = true;
            break;
        }

        if (!rtx && meta(v).tx_len != 0) {
            warn(DBG,
                 "skipping %s pkt " FMT_PNR_OUT " on str " FMT_SID " during %s",
                 meta(v).tx_len ? "already-tx'ed" : "fresh", meta(v).hdr.nr,
                 s->id, rtx ? "RTX" : "TX");
            continue;
        }

        if (rtx)
            rtx_pkt(s, v);

        if (s->c->state >= CONN_STAT_ESTB) {
            // if we have less than two full packet's worth of window, block
            if (s->out_data + 2 * MAX_PKT_LEN > s->out_data_max)
                s->blocked = true;
            if (s->c->out_data + 2 * MAX_PKT_LEN > s->c->tp_peer.max_data)
                s->c->blocked = true;
        }

        if (enc_pkt(s, rtx, v, &x) == false)
            continue;

        on_pkt_sent(s->c, v);
        encoded++;

        // if this packet contains an ACK frame, stop the timer
        if (s->c->state >= CONN_STAT_ESTB &&
            bit_test(meta(v).frames, FRAM_TYPE_ACK)) {
            warn(DBG, "ACK sent, stopping ACK timer");
            ev_timer_stop(loop, &s->c->ack_alarm);
        }

        if (limit && encoded == limit) {
            warn(NTE, "tx limit %u reached", limit);
            break;
        }
    }

    if (encoded) {
        // transmit encrypted/protected packets and then free the chain
        w_tx(s->c->sock, &x);
        while (w_tx_pending(&x))
            w_nic_tx(s->c->w);
        q_free(s->c, &x);
    }

    log_sent_pkts(s->c);
    return encoded;
}


static uint32_t
tx_other(struct q_stream * const s, const bool rtx, const uint32_t limit)
{
    warn(DBG, "other %s on %s conn %s str " FMT_SID " w/%u pkt%s in queue",
         rtx ? "RTX" : "TX", conn_type(s->c), cid2str(&s->c->scid), s->id,
         sq_len(&s->out), plural(sq_len(&s->out)));

    struct w_iov *v = 0, *last = 0;
    if (!rtx) {
        v = q_alloc_iov(s->c->w, 0, Q_OFFSET);
        v->len = 0; // this packet will have no stream data
        last = sq_last(&s->out, w_iov, next);
        sq_insert_tail(&s->out, v, next);
    }

    const bool did_tx = tx_stream(s, rtx, limit, v);

    if (!rtx && !is_rtxable(&meta(v))) {
        ensure(sq_last(&s->out, w_iov, next) == v, "queue mixed up");
        if (last)
            sq_remove_after(&s->out, last, next);
        else
            sq_remove_head(&s->out, next);
    }

    if (s->c->state == CONN_STAT_VERS_NEG_SENT)
        // if we sent a version negotiation response, forget all rx'ed packets
        diet_free(&s->c->recv);

    return did_tx;
}


static void __attribute__((nonnull)) do_conn_fc(struct q_conn * const c)
{
    if (c->state < CONN_STAT_ESTB)
        return;

    // check if we need to do connection-level flow control
    if (c->in_data + 2 * MAX_PKT_LEN > c->tp_local.max_data) {
        c->tx_max_data = true;
        c->tp_local.max_data += 0x1000;
    }

    if (splay_max(stream, &c->streams)->id + 4 > c->tp_local.max_strm_bidi) {
        c->tx_max_stream_id = true;
        c->tp_local.max_strm_bidi += 4;
    }
}


static void __attribute__((nonnull)) do_stream_fc(struct q_stream * const s)
{
    if (s->c->state < CONN_STAT_ESTB)
        return;

    if (s->in_data + 2 * MAX_PKT_LEN > s->in_data_max) {
        s->tx_max_stream_data = true;
        s->in_data_max += 0x1000;
    }
}


#define stream_needs_ctrl(s)                                                   \
    ((s)->tx_max_stream_data || (s)->c->tx_max_data ||                         \
     (((s)->state == STRM_STAT_HCLO || (s)->state == STRM_STAT_CLSD) &&        \
      (s)->fin_acked == false))


void tx(struct q_conn * const c, const bool rtx, const uint32_t limit)
{
    if (rtx == false && c->blocked)
        return;

    do_conn_fc(c);

    bool did_tx = false;
    struct q_stream * s = 0;
    splay_foreach (s, stream, &c->streams) {
        if ((is_fully_acked(s) && !stream_needs_ctrl(s)) ||
            (rtx == false && s->blocked))
            continue;

        do_stream_fc(s);

        if (!sq_empty(&s->out)) {
            warn(DBG,
                 "data %sTX on %s conn %s str " FMT_SID " w/%u pkt%s in queue",
                 rtx ? "R" : "", conn_type(c), cid2str(&c->scid), s->id,
                 sq_len(&s->out), plural(sq_len(&s->out)));
            did_tx |= tx_stream(s, rtx, limit, 0);
        } else
            did_tx |= tx_other(s, rtx, limit);

        if (s->c->state <= CONN_STAT_HSHK_DONE && s->c->try_0rtt == false)
            // only send stream-0 during handshake, unless we're doing 0-RTT
            break;
    }

    if (did_tx == false && c->state != CONN_STAT_VERS_NEG_SENT)
        // need to ACK or handshake, use stream zero
        tx_other(get_stream(c, 0), rtx, limit);

    c->needs_tx = false;
}


void tx_w(struct ev_loop * const l __attribute__((unused)),
          ev_async * const w,
          int e __attribute__((unused)))
{
    tx(w->data, false, 0);
}


static void __attribute__((nonnull))
update_scid(struct q_conn * const c, const struct cid * const scid)
{
    splay_remove(cid_splay, &conns_by_cid, c);
    c->scid = *scid;
    splay_insert(cid_splay, &conns_by_cid, c);
}


static bool __attribute__((nonnull))
verify_prot(struct q_conn * const c, struct w_iov * const v)
{
    if (is_set(F_LONG_HDR, meta(v).hdr.flags) && meta(v).hdr.vers == 0)
        // version negotiation responses do not carry protection
        return true;

    const uint16_t len = dec_aead(c, v);
    if (len == 0)
        return false;
    v->len -= AEAD_LEN;
    return true;
}


static void __attribute__((nonnull))
track_recv(struct q_conn * const c, const uint64_t nr, const uint8_t type)
{
    diet_insert(&c->recv, nr, type, ev_now(loop));
}


static void __attribute__((nonnull)) process_stream0(struct q_conn * const c)
{
    struct q_stream * const s = get_stream(c, 0);
    while (!sq_empty(&s->in)) {
        struct w_iov * iv = sq_first(&s->in);
        sq_remove_head(&s->in, next);
        if (tls_io(s, iv) == 0)
            maybe_api_return(q_connect, c);
        q_free_iov(c, iv);
    }
}


static void __attribute__((nonnull))
reset_conn(struct q_conn * const c, const bool also_stream0_in)
{
    // reset CC state
    c->rec.in_flight = 0;

    // reset FC state
    c->in_data = c->out_data = 0;

    // forget we received any packets
    diet_free(&c->recv);

    // remove all meta-data about RTX'ed packets
    struct pkt_meta *p, *tmp;
    for (p = splay_min(pm_nr_splay, &c->rec.sent_pkts); p != 0; p = tmp) {
        tmp = splay_next(pm_nr_splay, &c->rec.sent_pkts, p);
        if (p->is_rtxed) {
            splay_remove(pm_nr_splay, &c->rec.sent_pkts, p);
            *p = (struct pkt_meta){0};
            ASAN_POISON_MEMORY_REGION(p, sizeof(*p));
        }
    }

    struct q_stream * s = 0;
    splay_foreach (s, stream, &c->streams) {
        // reset stream offsets
        s->out_ack_cnt = s->out_off = s->in_off = 0;

        if (s->id) {
            // forget we transmitted any packets
            struct w_iov * v = 0;
            sq_foreach (v, &s->out, next) {
                meta(v).tx_len = meta(v).is_acked = 0;
                splay_remove(pm_nr_splay, &c->rec.sent_pkts, &meta(v));
            }
        } else {
            // free (some) stream-0 data
            if (also_stream0_in)
                q_free(c, &s->in);
            q_free(c, &s->out);
        }
    }
}


#define ignore_sh_pkt(v)                                                       \
    do {                                                                       \
        if (!is_set(F_LONG_HDR, meta(v).hdr.flags)) {                          \
            warn(NTE, "ignoring unexpected 0x%02x-type SH pkt",                \
                 pkt_type((v)->buf[0]));                                       \
            goto done;                                                         \
        }                                                                      \
    } while (0)


#define ignore_prot_fail_pkt(c, v)                                             \
    do {                                                                       \
        if (verify_prot(c, v) == false) {                                      \
            err_close(c, ERR_TLS_HSHAKE_FAIL,                                  \
                      "AEAD fail on 0x%02x-type %s pkt",                       \
                      pkt_type((v)->buf[0]),                                   \
                      is_set(F_LONG_HDR, meta(v).hdr.flags) ? "LH" : "SH");    \
            goto done;                                                         \
        }                                                                      \
    } while (0)


static void __attribute__((nonnull))
process_pkt(struct q_conn * const c, struct w_iov * const v)
{
    switch (c->state) {
    case CONN_STAT_IDLE:
    case CONN_STAT_VERS_NEG:
    case CONN_STAT_VERS_NEG_SENT:
        // respond to a client-initial
        if (meta(v).hdr.vers == 0) {
            warn(INF, "ignoring spurious vers neg response");
            goto done;
        }

        ignore_sh_pkt(v);

        c->vers = meta(v).hdr.vers;
        c->needs_tx = true;
        track_recv(c, meta(v).hdr.nr, meta(v).hdr.flags);
        if (c->vers_initial == 0)
            c->vers_initial = c->vers;
        if (vers_supported(c->vers) && !is_force_neg_vers(c->vers)) {
            warn(INF, "supporting clnt-requested vers 0x%08x", c->vers);

            init_hshk_prot(c);
            ignore_prot_fail_pkt(c, v);

            // this is a new connection; server picks a new random cid
            struct cid new_scid = {.len = SERV_SCID_LEN};
            arc4random_buf(new_scid.id, new_scid.len);
            warn(NTE, "picked new scid %s for %s conn (was %s)",
                 cid2str(&new_scid), conn_type(c), cid2str(&c->scid));
            update_scid(c, &new_scid);
            init_tls(c);
            dec_frames(c, v);

            // if the CH doesn't include any stream-0 data, bail
            if (meta(v).stream == 0 || meta(v).stream->id != 0) {
                warn(ERR, "Initial pkt w/o stream data");
                goto done;
            }

        } else {
            conn_to_state(c, CONN_STAT_VERS_NEG);
            warn(WRN, "%s conn %s clnt-requested vers 0x%08x not supported ",
                 conn_type(c), cid2str(&c->scid), c->vers);
        }
        break;

    case CONN_STAT_CH_SENT:
        ignore_sh_pkt(v);

        if (meta(v).hdr.vers == 0) {
            // handle an incoming vers-neg packet
            const uint32_t try_vers = pick_from_server_vers(v);
            if (try_vers == 0) {
                // no version in common ith serv
                conn_to_state(c, CONN_STAT_DRNG);
                return;
            }

            if (try_vers == c->vers) {
                warn(INF, "ignoring spurious vers neg response");
                break;
            }

            if (c->vers_initial == 0)
                c->vers_initial = c->vers;
            c->vers = try_vers;
            warn(INF, "serv didn't like vers 0x%08x, retrying with 0x%08x",
                 c->vers_initial, c->vers);

            // reset connection and free previous ClientHello flight
            reset_conn(c, true);

            // reset TLS state and create new CH
            init_tls(c);
            tls_io(get_stream(c, 0), 0);

            q_free_iov(c, v);
            conn_to_state(c, CONN_STAT_IDLE);
            if (c->try_0rtt)
                init_0rtt_prot(c);
            c->needs_tx = true;
            return;
        }

        if (meta(v).hdr.type == F_LH_RTRY) {
            // verify retry
            struct w_iov * const ci = find_sent_pkt(c, meta(v).hdr.nr);
            if (ci) {
                if (meta(ci).hdr.type != F_LH_INIT) {
                    warn(NTE,
                         "pkt nr " FMT_PNR_OUT
                         " was not a CI (0x%0x), ignoring retry",
                         meta(ci).hdr.nr, meta(ci).hdr.type);
                    goto done;
                }
            } else {
                warn(NTE,
                     "could not find sent pkt nr " FMT_PNR_OUT
                     ", ignoring retry",
                     meta(v).hdr.nr);
                goto done;
            }

            // handle an incoming retry packet
            warn(INF, "handling serv stateless retry");

            ignore_prot_fail_pkt(c, v);

            // server accepted version -
            // must use cid from retry for connection and re-init keys
            init_hshk_prot(c);

            // reinit tp
            c->vers_initial = c->vers;
            init_tp(c);

            // forget we transmitted any packets
            reset_conn(c, false);

            // process the retry data on stream-0
            dec_frames(c, v);
            process_stream0(c);

            // we can now reset stream-0 (inbound)
            struct q_stream * const s = get_stream(c, 0);
            s->in_off = 0;

            // we are not allowed to try 0RTT after retry
            c->try_0rtt = false;

            conn_to_state(c, CONN_STAT_RTRY);
            c->needs_tx = true;
            return;
        }

        ignore_prot_fail_pkt(c, v);

        // server accepted version -
        // if we get here, this should be a regular server-hello
        dec_frames(c, v);
        track_recv(c, meta(v).hdr.nr, meta(v).hdr.flags);
        break;

    case CONN_STAT_RTRY:
        ignore_prot_fail_pkt(c, v);
        track_recv(c, meta(v).hdr.nr, meta(v).hdr.flags);
        dec_frames(c, v);
        break;

    case CONN_STAT_SH:
    case CONN_STAT_HSHK_DONE:
        if (is_set(F_LONG_HDR, meta(v).hdr.flags) && meta(v).hdr.vers == 0) {
            // we shouldn't get another vers-neg packet here, ignore
            warn(NTE, "ignoring spurious ver neg response");
            goto done;
        }

        // if we got a SH or 0RTT packet, a q_accept() may be finished
        if (!is_set(F_LONG_HDR, meta(v).hdr.flags) ||
            meta(v).hdr.type == F_LH_0RTT) {
            if (maybe_api_return(q_accept, accept_queue))
                accept_queue = c;
        }
        // fall through

    case CONN_STAT_ESTB:
    case CONN_STAT_CLNG:
    case CONN_STAT_HSHK_FAIL:
    case CONN_STAT_DRNG:
        // ignore 0-RTT packets if we're not doing 0-RTT
        if (c->did_0rtt == false && meta(v).hdr.type == F_LH_0RTT) {
            warn(NTE, "ignoring 0-RTT pkt");
            goto done;
        }

        if (verify_prot(c, v) == false) {
            // check if this is a stateless reset
            if (memcmp(&v->buf[v->len - 16], c->stateless_reset_token, 16) ==
                0) {
                warn(NTE, "stateless reset on %s conn %s", conn_type(c),
                     cid2str(&c->scid));
                conn_to_state(c, CONN_STAT_DRNG);
            } else
                ignore_prot_fail_pkt(c, v);
        }

        track_recv(c, meta(v).hdr.nr, meta(v).hdr.flags);
        dec_frames(c, v);

        // if packet has anything other than ACK frames, arm the ACK timer
        if (c->state != CONN_STAT_DRNG && !is_ack_only(&meta(v))) {
            warn(DBG, "non-ACK frame received, starting ACK timer");
            ev_timer_again(loop, &c->ack_alarm);
        }
        break;

    case CONN_STAT_SEND_RTRY:
    case CONN_STAT_CLSD:
        break;

    default:
        die("TODO: state %u", c->state);
    }

done:
    if (is_rtxable(&meta(v)) == false || meta(v).stream == 0)
        // this packet is not rtx'able, or the stream data is duplicate
        q_free_iov(c, v);
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
        ASAN_UNPOISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        sq_remove_head(&i, next);

        const bool is_clnt = w_connected(ws);
        dec_pkt_hdr_initial(v, is_clnt);
        struct q_conn * c = 0;
        if (meta(v).is_valid == false) {
            warn(ERR, "received invalid %u-byte pkt, ignoring", v->len);
            q_free_iov(c, v);
            continue;
        }

        if (v->len > MAX_PKT_LEN)
            warn(WRN, "received %u-byte pkt (> %u max)", v->len, MAX_PKT_LEN);

        c = get_conn_by_cid(&meta(v).hdr.dcid, is_clnt);
        if (c == 0) {
            const struct sockaddr_in peer = {.sin_family = AF_INET,
                                             .sin_port = v->port,
                                             .sin_addr = {.s_addr = v->ip}};
            c = get_conn_by_ipnp(w_get_sport(ws), &peer, is_clnt);
            if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
                if (!is_clnt) {
                    if (c && meta(v).hdr.type == F_LH_0RTT)
                        warn(INF,
                             "got 0-RTT pkt for orig cid %s, new is %s, "
                             "accepting",
                             cid2str(&meta(v).hdr.dcid), cid2str(&c->scid));
                    else if (c && meta(v).hdr.type == F_LH_INIT) {
                        warn(INF,
                             "got duplicate CI for orig cid %s, new is %s, "
                             "ignoring",
                             cid2str(&meta(v).hdr.dcid), cid2str(&c->scid));
                        q_free_iov(c, v);
                        continue;
                    } else if (meta(v).hdr.type == F_LH_INIT) {
                        warn(NTE,
                             "new serv conn on port %u w/cid %s from %s:%u",
                             ntohs(w_get_sport(ws)), cid2str(&meta(v).hdr.dcid),
                             inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

                        // validate minimum packet size
                        if (v->len < MIN_INI_LEN)
                            warn(ERR, "initial %u-byte pkt too short (< %u)",
                                 v->len, MIN_INI_LEN);

                        c = new_conn(w, meta(v).hdr.vers, &meta(v).hdr.scid,
                                     &meta(v).hdr.dcid, &peer, 0,
                                     ntohs(w_get_sport(ws)), 0);
                        new_stream(c, 0, false);
                    }
                }
            }

        } else if (meta(v).hdr.scid.len) {
            if (memcmp(&meta(v).hdr.scid, &c->dcid, sizeof(c->dcid)) != 0)
                warn(INF, "got new dcid %s for %s conn (was %s)",
                     cid2str(&meta(v).hdr.scid), conn_type(c),
                     cid2str(&c->dcid));

            // always update the cid (TODO: check that this is allowed)
            c->dcid = meta(v).hdr.scid;
        }

        if (c == 0) {
            warn(INF, "cannot find connection for 0x%02x packet",
                 meta(v).hdr.flags);
            q_free_iov(c, v);
            continue;
        }

        if (meta(v).hdr.vers || !is_set(F_LONG_HDR, meta(v).hdr.flags))
            dec_pkt_hdr_remainder(v, c, &i);

        log_pkt("RX", v);

        // remember that we had a RX event on this connection
        if (!c->had_rx) {
            c->had_rx = true;
            sl_insert_head(&crx, c, next);
        }

        process_pkt(c, v);
        process_stream0(c);
    }

    // for all connections that had RX events
    while (!sl_empty(&crx)) {
        struct q_conn * const c = sl_first(&crx);
        sl_remove_head(&crx, next);

        // reset idle timeout
        ev_timer_again(l, &c->idle_alarm);

        // is a TX needed for this connection?
        if (c->needs_tx)
            tx(c, false, 0);

        log_sent_pkts(c);

        // clear the helper flags set above
        c->needs_tx = c->had_rx = false;


        if (c->state == CONN_STAT_SEND_RTRY)
            // if we sent a retry, forget the entire connection existed
            free_conn(c);
    }
}


void err_close(struct q_conn * const c,
               const uint16_t code,
               const char * const fmt,
               ...)
{
    va_list ap;
    va_start(ap, fmt);

    char reas[256];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    const int ret = vsnprintf(reas, sizeof(reas), fmt, ap);
#pragma clang diagnostic pop
    ensure(ret >= 0, "vsnprintf() failed");
    va_end(ap);

    if (c->err_code) {
        warn(WRN, "ignoring new err 0x%04x (%s); existing err is 0x%04x (%s) ",
             code, reas, c->err_code, c->err_reason);
        return;
    }

    warn(ERR, "%s", reas);
    c->err_code = code;
    c->err_reason = strdup(reas);
    conn_to_state(c, c->state <= CONN_STAT_HSHK_DONE ? CONN_STAT_HSHK_FAIL
                                                     : CONN_STAT_CLNG);
}


static void __attribute__((nonnull))
enter_closed(struct ev_loop * const l __attribute__((unused)),
             ev_timer * const w,
             int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    warn(DBG, "closing/draining alarm on %s conn %s", conn_type(c),
         cid2str(&c->scid));

    conn_to_state(c, CONN_STAT_CLSD);
    // terminate whatever API call is currently active
    api_return();
}


void enter_closing(struct q_conn * const c)
{
    if (!ev_is_active(&c->closing_alarm)) {
        // stop LD and ACK alarms
        ev_timer_stop(loop, &c->rec.ld_alarm);
        ev_timer_stop(loop, &c->ack_alarm);
        ev_timer_stop(loop, &c->idle_alarm);

        // start closing/draining alarm (3 * RTO)
        const ev_tstamp dur = 3 * (c->rec.srtt + 4 * c->rec.rttvar);
        warn(DBG, "closing/draining alarm in %f sec on %s conn %s", dur,
             conn_type(c), cid2str(&c->scid));
        ev_timer_init(&c->closing_alarm, enter_closed, dur, 0);
        c->closing_alarm.data = c;
        ev_timer_start(loop, &c->closing_alarm);
    }
}


void ack_alarm(struct ev_loop * const l __attribute__((unused)),
               ev_timer * const w,
               int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    warn(DBG, "ACK timeout on %s conn %s", conn_type(c), cid2str(&c->scid));
    c->needs_tx = true;
    tx(w->data, false, 0);
    ev_timer_stop(loop, &c->ack_alarm);
}


static void __attribute__((nonnull))
idle_alarm(struct ev_loop * const l __attribute__((unused)),
           ev_timer * const w,
           int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    warn(DBG, "idle timeout on %s conn %s", conn_type(c), cid2str(&c->scid));

    if (c->state >= CONN_STAT_ESTB) {
        // send connection close frame
        conn_to_state(c, CONN_STAT_CLNG);
        ev_async_send(loop, &c->tx_w);
    } else
        conn_to_state(c, CONN_STAT_DRNG);
}


struct q_conn * new_conn(struct w_engine * const w,
                         const uint32_t vers,
                         const struct cid * const dcid,
                         const struct cid * const scid,
                         const struct sockaddr_in * const peer,
                         const char * const peer_name,
                         const uint16_t port,
                         const uint64_t idle_to)
{
    struct q_conn * const c = calloc(1, sizeof(*c));
    ensure(c, "could not calloc");

    if (peer)
        c->peer = *peer;

    if (peer_name) {
        c->is_clnt = true;
        ensure(c->peer_name = strdup(peer_name), "could not dup peer_name");
    }

    if (dcid) {
        memcpy(&c->dcid, dcid, sizeof(*dcid));
    } else if (c->is_clnt) {
        c->dcid.len = SERV_SCID_LEN;
        arc4random_buf(c->dcid.id, c->dcid.len);
    }

    if (scid) {
        memcpy(&c->scid, scid, sizeof(*scid));
    } else if (c->is_clnt) {
        c->scid.len = CLNT_SCID_LEN;
        arc4random_buf(c->scid.id, c->scid.len);
    }

    c->vers = c->vers_initial = vers;
    arc4random_buf(c->stateless_reset_token, sizeof(c->stateless_reset_token));

    // initialize recovery state
    rec_init(c);

    splay_init(&c->streams);
    diet_init(&c->closed_streams);
    diet_init(&c->recv);

    // initialize idle timeout
    c->idle_alarm.data = c;
    c->idle_alarm.repeat = idle_to ? idle_to : kIdleTimeout;
    ev_init(&c->idle_alarm, idle_alarm);

    // initialize ACK timeout
    c->ack_alarm.data = c;
    c->ack_alarm.repeat = kDelayedAckTimeout;
    ev_init(&c->ack_alarm, ack_alarm);

    c->tp_peer.ack_del_exp = c->tp_local.ack_del_exp = 3;
    c->tp_local.idle_to = kIdleTimeout;
    c->tp_local.max_data = c->is_clnt ? 0x4000 : 0x8000;
    c->tp_local.max_strm_data = c->is_clnt ? 0x2000 : 0x4000;
    c->tp_local.max_strm_bidi = c->is_clnt ? 1 : 4;
    c->tp_local.max_strm_uni = 0; // TODO: support unidir streams

    // initialize socket and start a TX watcher
    ev_async_init(&c->tx_w, tx_w);
    c->tx_w.data = c;
    ev_async_start(loop, &c->tx_w);

    c->w = w;
    c->sock = w_get_sock(w, htons(port), 0);
    if (c->sock == 0) {
        c->rx_w.data = c->sock = w_bind(w, htons(port), 0);
        ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);
        ev_io_start(loop, &c->rx_w);
        c->holds_sock = true;
    }
    c->sport = w_get_sport(c->sock);

    // add connection to global data structures
    splay_insert(ipnp_splay, &conns_by_ipnp, c);
    if (c->scid.len)
        splay_insert(cid_splay, &conns_by_cid, c);

    warn(DBG, "%s conn %s on port %u created", conn_type(c), cid2str(&c->scid),
         ntohs(c->sport));
    return c;
}


void free_conn(struct q_conn * const c)
{
    if (c->holds_sock) {
        // only close the socket for the final server connection
        ev_io_stop(loop, &c->rx_w);
        w_close(c->sock);
    }
    ev_timer_stop(loop, &c->rec.ld_alarm);
    ev_timer_stop(loop, &c->closing_alarm);
    ev_timer_stop(loop, &c->idle_alarm);
    ev_timer_stop(loop, &c->ack_alarm);

    struct q_stream *s, *ns;
    for (s = splay_min(stream, &c->streams); s; s = ns) {
        ns = splay_next(stream, &c->streams, s);
        free_stream(s);
    }

    // free any w_iovs that are still hanging around
    struct pkt_meta *p, *np;
    for (p = splay_min(pm_nr_splay, &c->rec.sent_pkts); p; p = np) {
        np = splay_next(pm_nr_splay, &c->rec.sent_pkts, p);
        q_free_iov(c, w_iov(c->w, pm_idx(p)));
    }

    diet_free(&c->closed_streams);
    diet_free(&c->recv);
    free(c->peer_name);
    free_tls(c);
    if (c->err_reason)
        free(c->err_reason);

    // remove connection from global lists
    splay_remove(ipnp_splay, &conns_by_ipnp, c);
    splay_remove(cid_splay, &conns_by_cid, c);

    if (c->scid.len)
        warn(WRN, "%s conn %s on port %u closed", conn_type(c),
             cid2str(&c->scid), ntohs(c->sport));
    free(c);
}
