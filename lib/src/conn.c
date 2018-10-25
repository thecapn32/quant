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
#include <netinet/ip.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <ev.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"


#undef CONN_STATE
#define CONN_STATE(k, v) [v] = #k

const char * const conn_state_str[] = {CONN_STATES};


struct q_conn_sl c_ready;
struct conns_by_ipnp conns_by_ipnp = splay_initializer(&conns_by_ipnp);
struct conns_by_id conns_by_id = splay_initializer(&conns_by_id);


static inline int __attribute__((nonnull))
sockaddr_in_cmp(const struct sockaddr_in * const a,
                const struct sockaddr_in * const b)
{
    int diff =
        (a->sin_family > b->sin_family) - (a->sin_family < b->sin_family);
    if (diff)
        return diff;

    diff = (a->sin_port > b->sin_port) - (a->sin_port < b->sin_port);
    if (diff)
        return diff;

    return (a->sin_addr.s_addr > b->sin_addr.s_addr) -
           (a->sin_addr.s_addr < b->sin_addr.s_addr);
}


int conns_by_ipnp_cmp(const struct q_conn * const a,
                      const struct q_conn * const b)
{
    return sockaddr_in_cmp(&a->peer, &b->peer);
}


SPLAY_GENERATE(conns_by_ipnp, q_conn, node_ipnp, conns_by_ipnp_cmp)
SPLAY_GENERATE(conns_by_id, q_cid_map, node, conns_by_id_cmp)
SPLAY_GENERATE(cids_by_seq, cid, node_seq, cids_by_seq_cmp)
SPLAY_GENERATE(cids_by_id, cid, node_id, cid_cmp)


bool vers_supported(const uint32_t v)
{
    if (is_force_neg_vers(v) || is_rsvd_vers(v))
        return false;

    for (uint8_t i = 0; i < ok_vers_len; i++)
        if (v == ok_vers[i])
            return true;

    // we're out of matching candidates
    warn(INF, "no vers in common");
    return false;
}


struct ooo_0rtt_by_cid ooo_0rtt_by_cid = splay_initializer(&ooo_0rtt_by_cid);


SPLAY_GENERATE(ooo_0rtt_by_cid, ooo_0rtt, node, ooo_0rtt_by_cid_cmp)


static uint32_t __attribute__((nonnull))
pick_from_server_vers(const struct w_iov * const v)
{
    const uint16_t pos = meta(v).hdr.hdr_len;
    for (uint8_t i = 0; i < ok_vers_len; i++) {
        if (is_rsvd_vers(ok_vers[i]))
            // skip over reserved versions in our local list
            continue;

        for (uint8_t j = 0; j < v->len - pos; j += sizeof(uint32_t)) {
            uint32_t vers = 0;
            uint16_t x = j + pos;
            dec(&vers, v->buf, v->len, x, sizeof(vers), "0x%08x");

            if (is_rsvd_vers(vers))
                // skip over reserved versions in the server's list
                continue;

            warn(DBG, "serv prio %ld = 0x%08x; our prio %u = 0x%08x",
                 j / sizeof(uint32_t), vers, i, ok_vers[i]);
            if (ok_vers[i] == vers)
                return vers;
        }
    }

    // we're out of matching candidates
    warn(INF, "no vers in common with serv");
    return 0;
}


static struct q_conn * __attribute__((nonnull))
get_conn_by_ipnp(const uint16_t sport, const struct sockaddr_in * const peer)
{
    const struct q_conn which = {.peer = *peer, .sport = sport};
    return splay_find(conns_by_ipnp, &conns_by_ipnp, &which);
}


static struct q_conn * __attribute__((nonnull))
get_conn_by_cid(const struct cid * const scid)
{
    const struct q_cid_map which = {.cid = *scid};
    struct q_cid_map * const cm = splay_find(conns_by_id, &conns_by_id, &which);
    return cm ? cm->c : 0;
}


static void __attribute__((nonnull))
switch_scid(struct q_conn * const c, const struct cid * const id)
{
    struct cid * scid = splay_find(cids_by_id, &c->scids_by_id, id);
    ensure(scid, "have dcid");

    if (scid->seq <= c->scid->seq)
        return;

    warn(NTE, "migration to scid %s for %s conn (was %s)", cid2str(scid),
         conn_type(c), cid2str(c->scid));

    c->scid = scid;
}


static void __attribute__((nonnull)) use_next_dcid(struct q_conn * const c)
{
    const struct cid which = {.seq = c->dcid->seq + 1};
    struct cid * dcid = splay_find(cids_by_seq, &c->dcids_by_seq, &which);
    ensure(dcid, "have dcid");

    warn(NTE, "migration to dcid %s for %s conn (was %s)", cid2str(dcid),
         conn_type(c), cid2str(c->dcid));

    c->tx_retire_cid = c->dcid->retired = true;
    c->dcid = dcid;
}


static void log_sent_pkts(struct q_conn * const c)
{
    for (epoch_t e = ep_init; e < ep_data; e++) {
        char sent_pkts_buf[1024] = "";
        uint64_t prev = UINT64_MAX;
        struct pkt_meta * p = 0;
        struct pn_space * const pn = pn_for_epoch(c, e);
        splay_foreach (p, pm_by_nr, &pn->sent_pkts) {
            char tmp[1024] = "";
            const bool ack_only = is_ack_only(p);
            snprintf(tmp, sizeof(tmp), "%s%s" FMT_PNR_OUT "%s ",
                     is_rtxable(p) ? "*" : "", ack_only ? "(" : "",
                     prev == UINT64_MAX
                         ? p->hdr.nr
                         : shorten_ack_nr(p->hdr.nr, p->hdr.nr - prev),
                     ack_only ? ")" : "");
            strncat(sent_pkts_buf, tmp,
                    sizeof(sent_pkts_buf) - strlen(sent_pkts_buf) - 1);
            prev = p->hdr.nr;
        }
        if (sent_pkts_buf[0])
            warn(DBG, "epoch %u%s unacked: %s", e, e == 1 ? "/3" : "",
                 sent_pkts_buf);
    }
}


static void __attribute__((nonnull))
rtx_pkt(struct q_stream * const s, struct w_iov * const v)
{
    ensure(meta(v).is_rtx == false, "cannot RTX an RTX");
    // on RTX, remember orig pkt meta data
    const uint16_t data_start = meta(v).stream_data_start;
    struct w_iov * const r = q_alloc_iov(s->c->w, 0, data_start);
    pm_cpy(&meta(r), &meta(v), true); // copy pkt meta data
    memcpy(r->buf - data_start, v->buf - data_start, data_start);
    meta(r).is_rtx = true;
    sl_insert_head(&meta(v).rtx, &meta(r), rtx_next);
    sl_insert_head(&meta(r).rtx, &meta(v), rtx_next);

    // we reinsert meta(v) with its new pkt nr in on_pkt_sent()
    splay_remove(pm_by_nr, &meta(v).pn->sent_pkts, &meta(v));
    splay_insert(pm_by_nr, &meta(v).pn->sent_pkts, &meta(r));

    // warn(DBG, "RTX idx %u, cpy in idx %u", w_iov_idx(v), w_iov_idx(r));
}


static void __attribute__((nonnull)) do_tx(struct q_conn * const c)
{
    c->needs_tx = false;

    if (sq_empty(&c->txq))
        return;

    if (unlikely(sq_len(&c->txq) > 1 &&
                 pkt_type(*sq_first(&c->txq)->buf) != F_SH))
        coalesce(&c->txq);

    // transmit encrypted/protected packets
    w_tx(c->sock, &c->txq);
    while (w_tx_pending(&c->txq))
        w_nic_tx(c->w);

    // x was allocated straight from warpcore, no metadata needs to be freed
    w_free(&c->txq);
}


static void __attribute__((nonnull(1)))
tx_stream_data(struct q_stream * const s, const bool rtx, const uint32_t limit)
{
    uint32_t encoded = 0;
    struct w_iov * v = rtx ? s->out_una : s->out_nxt;
    sq_foreach_from (v, &s->out, next) {
        if (meta(v).is_acked) {
            // warn(DBG,
            //      "skipping ACKed pkt " FMT_PNR_OUT " on strm " FMT_SID
            //      " during %s",
            //      meta(v).hdr.nr, s->id, rtx ? "RTX" : "TX");
            continue;
        }

        if (rtx == (meta(v).tx_len == 0)) {
            // warn(DBG,
            //      "skipping %s pkt " FMT_PNR_OUT " on strm " FMT_SID
            //      " during %s",
            //      meta(v).tx_len ? "already-tx'ed" : "fresh", meta(v).hdr.nr,
            //      s->id, rtx ? "RTX" : "TX");
            continue;
        }

        if (rtx)
            rtx_pkt(s, v);

        if (s->c->state == conn_estb) {
            // add one MTU, so we can still encode this stream frame
            if (s->id >= 0 &&
                s->out_data + v->len + w_mtu(s->c->w) > s->out_data_max)
                s->blocked = true;
            if (s->c->out_data + v->len + w_mtu(s->c->w) >
                s->c->tp_out.max_data)
                s->c->blocked = true;
        }

        if (enc_pkt(s, rtx, true, v) == false)
            continue;
        encoded++;

        if (rtx == false)
            // update the stream's out_nxt pointer
            s->out_nxt = sq_next(v, next);

        if (s->blocked || s->c->blocked)
            break;

        if (limit && encoded == limit) {
            warn(NTE, "tx limit %u reached", limit);
            break;
        }
    }

    if (encoded == 0 && s->tx_fin) {
        // we need to send a FIN
        v = q_alloc_iov(s->c->w, 0, Q_OFFSET);
        v->len = 0;
        sq_insert_tail(&s->out, v, next);
        if (enc_pkt(s, rtx, true, v))
            encoded++;
    }

    log_sent_pkts(s->c);
}


static void __attribute__((nonnull)) tx_stream_ctrl(struct q_stream * const s)
{
    struct w_iov * const v = q_alloc_iov(s->c->w, 0, 0);
    enc_pkt(s, false, false, v);
    if (sq_len(&s->c->txq))
        do_tx(s->c);
}


void do_conn_fc(struct q_conn * const c)
{
    if (c->state == conn_clsg || c->state == conn_drng)
        return;

    // check if we need to do connection-level flow control
    if (c->in_data + 2 * MAX_PKT_LEN > c->tp_in.max_data) {
        c->tx_max_data = c->needs_tx = true;
        c->tp_in.new_max_data = c->tp_in.max_data + 0xA000;
    }
}


static void __attribute__((nonnull)) do_conn_mgmt(struct q_conn * const c)
{
    if (c->state == conn_clsg || c->state == conn_drng)
        return;

    // do we need to make more stream IDs available?
    struct q_stream * const s = splay_max(streams_by_id, &c->streams_by_id);
    if (s)
        do_stream_id_fc(s);

    if (c->tp_out.disable_migration == false) {
        if (c->is_clnt) {
            const struct cid * const dcid =
                splay_max(cids_by_seq, &c->dcids_by_seq);
            // if higher-numbered destination CIDs are available, switch to next
            if (dcid && dcid->seq > c->dcid->seq)
                use_next_dcid(c);
        } else
            // send new CID if the client doesn't have one remaining
            c->tx_ncid = (splay_count(&c->scids_by_seq) < 2);
    }
}


static void __attribute__((nonnull))
tx_crypto(struct q_conn * const c, const epoch_t e)
{
    for (epoch_t epoch = ep_init; epoch <= e; epoch++) {
        struct q_stream * const s = get_stream(c, crpt_strm_id(epoch));
        if (sq_empty(&s->out))
            continue;
        if (out_fully_acked(s)) {
            // no need to keep this crypto data around
            q_free(&s->in);
            q_free(&s->out);
            s->out_ack_cnt = 0;
        } else
            tx_stream_data(s, false, 0);
    }
}


void tx(struct q_conn * const c, const bool rtx, const uint32_t limit)
{
    switch (c->state) {
    case conn_drng:
        die("must not TX while draining");

    case conn_qlse:
        enter_closing(c);
        break;

    case conn_opng:
        if (rtx == false) {
            tx_crypto(c, c->tls.epoch_out);
            c->needs_tx = false;
            if (c->tls.epoch_out == ep_init)
                // we did not progress to the 0-RTT epoch
                goto done;
        }
        break;

    default:
        break;
    }

    if (rtx == false && c->blocked)
        goto done;

    do_conn_mgmt(c);

    struct q_stream * s = 0;
    splay_foreach (s, streams_by_id, &c->streams_by_id) {
        const bool stream_has_data_to_tx =
            sq_len(&s->out) > 0 && out_fully_acked(s) == false &&
            ((rtx && s->out_una) || (!rtx && s->out_nxt));

        // warn(ERR, "strm id=" FMT_SID " cnt=%u has_data=%u needs_ctrl=%u %p
        // %p",
        //      s->id, sq_len(&s->out), stream_has_data_to_tx,
        //      stream_needs_ctrl(s), out_fully_acked(s), s->out_una,
        //      s->out_nxt);
        // check if we should skip TX on this stream
        if ( // this is a crypto stream and we're not doing an RTX
            (s->id < 0 && rtx == false) ||
            // nothing to send and doesn't need control frames?
            (stream_has_data_to_tx == false && stream_needs_ctrl(s) == false) ||
            // is this a new TX but the stream is blocked?
            (rtx == false && s->blocked) ||
            // unless for 0-RTT, is this a regular stream during conn open?
            (c->try_0rtt == false && s->id >= 0 && c->state != conn_estb)) {
            // warn(ERR, "skip " FMT_SID, s->id);
            continue;
        }

        warn(DBG, "%s %sTX on %s conn %s strm " FMT_SID " w/%u pkt%s in queue",
             stream_has_data_to_tx ? "data" : "ctrl", rtx ? "R" : "",
             conn_type(c), cid2str(c->scid), s->id, sq_len(&s->out),
             plural(sq_len(&s->out)));

        if (stream_has_data_to_tx)
            tx_stream_data(s, rtx, limit);
        else
            tx_stream_ctrl(s);
    }

    if (sq_empty(&c->txq)) {
        // need to send other frame, do it in an ACK
        tx_ack(c, epoch_in(c));
        return;
    }

done:
    do_tx(c);
}


void tx_ack(struct q_conn * const c, const epoch_t e)
{
    struct q_stream * const s = get_stream(c, crpt_strm_id(e));
    struct pn_space * const pn = pn_for_epoch(c, e);

    if (!needs_ack(pn) && c->tx_rtry == false && c->state != conn_clsg)
        return;

    struct w_iov * const v = q_alloc_iov(c->w, 0, 0);
    enc_pkt(s, false, false, v);
    if (sq_len(&c->txq))
        do_tx(c);
}


void tx_w(struct ev_loop * const l __attribute__((unused)),
          ev_async * const w,
          int e __attribute__((unused)))
{
    tx(w->data, false, 0);
}


void update_act_scid(struct q_conn * const c, const struct cid * const id)
{
    warn(NTE, "hshk switch to scid %s for %s conn (was %s)", cid2str(id),
         conn_type(c), cid2str(c->scid));
    const struct q_cid_map which = {.cid = *c->scid};
    struct q_cid_map * cm = splay_find(conns_by_id, &conns_by_id, &which);
    splay_remove(conns_by_id, &conns_by_id, cm);
    cid_cpy(&cm->cid, id);
    splay_insert(conns_by_id, &conns_by_id, cm);
}


void add_scid(struct q_conn * const c, const struct cid * const id)
{
    struct q_cid_map * cm;
    struct cid * scid = splay_find(cids_by_seq, &c->scids_by_seq, id);
    ensure(scid == 0, "cid is new");

    // warn(ERR, "new scid %s", cid2str(id));
    cm = calloc(1, sizeof(*cm));
    ensure(cm, "could not calloc");
    cm->c = c;
    cid_cpy(&cm->cid, id);
    splay_insert(cids_by_seq, &c->scids_by_seq, &cm->cid);
    splay_insert(cids_by_id, &c->scids_by_id, &cm->cid);
    if (c->scid == 0)
        c->scid = &cm->cid;
    splay_insert(conns_by_id, &conns_by_id, cm);

    // splay_foreach (scid, cids_by_seq, &c->scids_by_seq)
    //     warn(ERR, "%s", cid2str(scid));
} // NOLINT


void add_dcid(struct q_conn * const c, const struct cid * const id)
{
    struct cid * dcid = splay_find(cids_by_seq, &c->dcids_by_seq, id);

    if (dcid == 0) {
        // warn(ERR, "new dcid %s", cid2str(id));
        dcid = calloc(1, sizeof(*dcid));
        ensure(dcid, "could not calloc");
        cid_cpy(dcid, id);
        splay_insert(cids_by_seq, &c->dcids_by_seq, dcid);
        if (c->dcid == 0)
            c->dcid = dcid;
    } else {
        warn(NTE, "hshk switch to dcid %s for %s conn (was %s)", cid2str(id),
             conn_type(c), cid2str(c->dcid));
        cid_cpy(dcid, id);
    }

    // splay_foreach (dcid, cids_by_seq, &c->dcids_by_seq)
    //     warn(ERR, "%s", cid2str(dcid));
} // NOLINT


static void __attribute__((nonnull))
update_ipnp(struct q_conn * const c, const struct sockaddr_in * const peer)
{
    splay_remove(conns_by_ipnp, &conns_by_ipnp, c);
    c->peer = *peer;
    splay_insert(conns_by_ipnp, &conns_by_ipnp, c);
}


static void __attribute__((nonnull)) rx_crypto(struct q_conn * const c)
{
    const epoch_t epoch = epoch_in(c);
    struct q_stream * const s = get_stream(c, crpt_strm_id(epoch));
    while (!sq_empty(&s->in)) {
        // take the data out of the crypto stream
        struct w_iov * const iv = sq_first(&s->in);
        sq_remove_head(&s->in, next);
        meta(iv).stream = 0;

        // and process it
        const int ret = tls_io(s, iv);
        if (ret == 0 || ret == PTLS_ERROR_STATELESS_RETRY) {
            tx_crypto(c, c->tls.epoch_out);
            if (ret == 0 && (c->state == conn_idle || c->state == conn_opng)) {
                conn_to_state(c, conn_estb);
                if (c->is_clnt)
                    maybe_api_return(q_connect, c, 0);
                else {
                    // TODO: find a better way to send NEW_TOKEN
                    make_rtry_tok(c);
                    sl_insert_head(&aq, c, node_aq);
                    maybe_api_return(q_accept, 0, 0);
                }
            }
        }
    }

    if (epoch_in(c) > epoch)
        // let's fire off some ACKs for the previous epochs
        for (epoch_t e = ep_init; e <= epoch; e++)
            tx_ack(c, e);
}


#define ignore_sh_pkt(v)                                                       \
    do {                                                                       \
        if (unlikely(!is_set(F_LONG_HDR, meta(v).hdr.flags))) {                \
            warn(NTE, "ignoring unexpected 0x%02x-type SH pkt",                \
                 pkt_type((v)->buf[0]));                                       \
            goto done;                                                         \
        }                                                                      \
    } while (0)


static void __attribute__((nonnull)) vneg_or_rtry_resp(struct q_conn * const c)
{
    // reset CC state
    init_rec(c);

    // reset FC state
    c->in_data = c->out_data = 0;

    struct q_stream * s;
    splay_foreach (s, streams_by_id, &c->streams_by_id)
        reset_stream(s, s->id < 0 && (c->try_0rtt == false ||
                                      (strm_epoch(s) != ep_0rtt &&
                                       strm_epoch(s) != ep_data)));

    // reset packet number spaces
    reset_pn(&c->pn_init.pn);
    reset_pn(&c->pn_hshk.pn);
    reset_pn(&c->pn_data.pn);

    // reset TLS state and create new CH
    init_tls(c);
    tls_io(get_stream(c, crpt_strm_id(ep_init)), 0);
}


static bool __attribute__((nonnull)) rx_pkt(struct q_conn * const c,
                                            struct w_iov * v,
                                            struct w_iov_sq * const x,
                                            const struct cid * const odcid
#ifdef NDEBUG
                                            __attribute__((unused))
#endif
                                            ,
                                            const uint8_t * const tok,
                                            const uint16_t tok_len)
{
    bool ok = false;
    struct pn_space * const pn = pn_for_pkt_type(c, meta(v).hdr.type);

    log_pkt("RX", v, odcid, tok, tok_len);

    switch (c->state) {
    case conn_idle:
        ignore_sh_pkt(v);

        c->vers = meta(v).hdr.vers;
        if (c->tx_rtry) {
            // tx_rtry is currently always set on port 4434
            if (meta(v).hdr.type == F_LH_INIT && tok_len) {
                if (verify_rtry_tok(c, tok, tok_len) == false) {
                    warn(ERR, "retry token verification failed");
                    enter_closing(c);
                    goto done;
                } else
                    c->tx_rtry = false;
            } else {
                warn(INF, "sending retry");
                // send a RETRY
                make_rtry_tok(c);
                c->needs_tx = true;
                goto done;
            }
        }

        warn(INF, "supporting clnt-requested vers 0x%08x", c->vers);
        if (dec_frames(c, &v) == UINT16_MAX)
            goto done;

        // if the CH doesn't include any crypto frames, bail
        if (bit_test(meta(v).frames, FRAM_TYPE_CRPT) == false) {
            warn(ERR, "initial pkt w/o crypto frames");
            enter_closing(c);
            goto done;
        }

        init_tp(c);

        // check if any reordered 0-RTT packets are cached for this CID
        const struct ooo_0rtt which = {.cid = meta(v).hdr.dcid};
        struct ooo_0rtt * const zo =
            splay_find(ooo_0rtt_by_cid, &ooo_0rtt_by_cid, &which);
        if (zo) {
            warn(INF, "have reordered 0-RTT pkt (t=%f sec) for %s conn %s",
                 ev_now(loop) - zo->t, conn_type(c), cid2str(c->scid));
            splay_remove(ooo_0rtt_by_cid, &ooo_0rtt_by_cid, zo);
            sq_insert_head(x, zo->v, next);
            free(zo);
        }
        conn_to_state(c, conn_opng);

        // this is a new connection; server picks a new random cid
        struct cid new_scid = {.len = SERV_SCID_LEN};
        arc4random_buf(new_scid.id, new_scid.len);
        update_act_scid(c, &new_scid);

        ok = true;
        break;

    case conn_opng:
        ignore_sh_pkt(v);

        if (meta(v).hdr.vers == 0) {
            // this is a vneg pkt
            if (c->vers != ok_vers[0]) {
                // we must have already reacted to a prior vneg pkt
                warn(INF, "ignoring spurious vers neg response");
                goto done;
            }

            // handle an incoming vers-neg packet
            const uint32_t try_vers = pick_from_server_vers(v);
            if (try_vers == 0) {
                // no version in common with serv
                enter_closing(c);
                goto done;
            }

            vneg_or_rtry_resp(c);
            c->vers = try_vers;
            warn(INF, "serv didn't like vers 0x%08x, retrying with 0x%08x",
                 c->vers_initial, c->vers);
            goto done;
        }

        if (unlikely(meta(v).hdr.vers != c->vers)) {
            warn(ERR, "serv responded with vers 0x%08x to our CI w/vers 0x%08x",
                 meta(v).hdr.vers, c->vers);
            err_close(c, ERR_PROTOCOL_VIOLATION, 0, "wrong vers in SH");
            goto done;
        }

        if (meta(v).hdr.type == F_LH_RTRY) {
            if (c->tok_len) {
                // we already had an earlier RETRY on this connection
                warn(ERR, "rx second RETRY");
                err_close(c, ERR_PROTOCOL_VIOLATION, 0, "rx 2nd retry");
                goto done;
            }

            // handle an incoming retry packet
            vneg_or_rtry_resp(c);

            c->tok_len = tok_len;
            memcpy(c->tok, tok, c->tok_len);

            warn(INF, "handling serv stateless retry w/tok %s",
                 hex2str(c->tok, c->tok_len));
            goto done;
        }

        // server accepted version -
        // if we get here, this should be a regular server-hello
        ok = (dec_frames(c, &v) != UINT16_MAX);
        break;

    case conn_estb:
    case conn_clsg:
    case conn_drng:
        if (is_set(F_LONG_HDR, meta(v).hdr.flags) && meta(v).hdr.vers == 0) {
            // we shouldn't get another vers-neg packet here, ignore
            warn(NTE, "ignoring spurious ver neg response");
            goto done;
        }

        // ignore 0-RTT packets if we're not doing 0-RTT
        if (c->did_0rtt == false && meta(v).hdr.type == F_LH_0RTT) {
            warn(NTE, "ignoring 0-RTT pkt");
            goto done;
        }

        if (dec_frames(c, &v) == UINT16_MAX)
            goto done;

        ok = true;
        break;

    case conn_clsd:
        warn(NTE, "ignoring pkt for closed %s conn", conn_type(c));
        break;

    default:
        die("TODO: state %s", conn_state_str[c->state]);
    }

    // if packet has anything other than ACK frames, maybe arm the ACK timer
    if (c->state != conn_drng && c->state != conn_clsd && !c->tx_rtry &&
        !is_ack_only(&meta(v)) && !ev_is_active(&pn->ack_alarm)) {
        // warn(DBG, "non-ACK frame received, starting epoch %u ACK timer",
        //      epoch_for_pkt_type(meta(v).hdr.type));
        ev_timer_again(loop, &pn->ack_alarm);
    }

    maybe_flip_keys(c, true);

done:
    // update ECN info
    switch (v->flags & IPTOS_ECN_MASK) {
    case IPTOS_ECN_ECT1:
        c->rec.ect1_cnt++;
        break;
    case IPTOS_ECN_ECT0:
        c->rec.ect0_cnt++;
        break;
    case IPTOS_ECN_CE:
        c->rec.ce_cnt++;
        break;
    }

    return ok;
}


#ifdef FUZZING
void
#else
static void __attribute__((nonnull))
#endif
rx_pkts(struct w_iov_sq * const x,
        struct q_conn_sl * const crx,
        const struct w_sock * const ws)
{
    while (!sq_empty(x)) {
        struct w_iov * const xv = sq_first(x);
        sq_remove_head(x, next);

        // warn(DBG, "rx idx %u len %u type 0x%02x", w_iov_idx(xv), xv->len,
        //      *xv->buf);

#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
        // when called from the fuzzer, v->ip is zero
        if (xv->ip)
            write_to_corpus(corpus_pkt_dir, xv->buf, xv->len);
#endif

        // allocate new w_iov for the (eventual) unencrypted data and meta-data
        struct w_iov * const v = q_alloc_iov(ws->w, 0, 0);
        v->port = xv->port;
        v->ip = xv->ip;
        v->flags = xv->flags;

        const bool is_clnt = w_connected(ws);
        struct q_conn * c = 0;
        struct cid odcid;
        uint8_t tok[MAX_PKT_LEN];
        uint16_t tok_len = 0;
        if (!dec_pkt_hdr_beginning(xv, v, is_clnt, &odcid, tok, &tok_len)) {
            // can't log packet, because it may be too short for log_pkt()
            warn(ERR, "received invalid %u-byte pkt (type 0x%02x), ignoring",
                 v->len, v->buf[0]);
            q_free_iov(v);
            continue;
        }

        const struct sockaddr_in peer = {.sin_family = AF_INET,
                                         .sin_port = v->port,
                                         .sin_addr = {.s_addr = v->ip}};

        c = get_conn_by_cid(&meta(v).hdr.dcid);
        if (c == 0) {
            c = get_conn_by_ipnp(w_get_sport(ws), &peer);
            if (is_set(F_LONG_HDR, meta(v).hdr.flags)) {
                if (!is_clnt) {
                    if (c && meta(v).hdr.type == F_LH_0RTT)
                        warn(INF,
                             "got 0-RTT pkt for orig cid %s, new is %s, "
                             "accepting",
                             cid2str(&meta(v).hdr.dcid), cid2str(c->scid));
                    else if (c == 0 && meta(v).hdr.type == F_LH_INIT) {
                        // validate minimum packet size
                        // TODO: actually reject
                        if (xv->user_data < MIN_INI_LEN)
                            warn(ERR, "initial %u-byte pkt too short (< %u)",
                                 xv->user_data, MIN_INI_LEN);

                        if (vers_supported(meta(v).hdr.vers) == false ||
                            is_force_neg_vers(meta(v).hdr.vers)) {
                            log_pkt("RX", v, &odcid, tok, tok_len);
                            warn(WRN,
                                 "clnt-requested vers 0x%08x not supported",
                                 meta(v).hdr.vers);
                            tx_vneg_resp(ws, v);
                            q_free_iov(v);
                            continue;
                        }

                        warn(NTE,
                             "new serv conn on port %u from %s:%u w/cid=%s",
                             ntohs(w_get_sport(ws)), inet_ntoa(peer.sin_addr),
                             ntohs(peer.sin_port), cid2str(&meta(v).hdr.dcid));
                        c = new_conn(w_engine(ws), meta(v).hdr.vers,
                                     &meta(v).hdr.scid, &meta(v).hdr.dcid,
                                     &peer, 0, ntohs(w_get_sport(ws)), 0);
                        init_tls(c);
                    }
                }
            }

        } else {
            if (meta(v).hdr.scid.len) {
                if (cid_cmp(&meta(v).hdr.scid, c->dcid) != 0) {
                    if (meta(v).hdr.vers && meta(v).hdr.type == F_LH_RTRY &&
                        cid_cmp(&odcid, c->dcid) != 0) {
                        log_pkt("RX", v, &odcid, tok, tok_len);
                        warn(ERR, "retry dcid mismatch %s != %s",
                             cid2str(&odcid), cid2str(c->dcid));
                        q_free_iov(v);
                        continue;
                    }
                    if (c->state == conn_opng)
                        add_dcid(c, &meta(v).hdr.scid);
                }
            }

            if (cid_cmp(&meta(v).hdr.dcid, c->scid) != 0)
                switch_scid(c, &meta(v).hdr.dcid);

            // check if this pkt came from a new source IP and/or port
            if (sockaddr_in_cmp(&c->peer, &peer) != 0) {
                warn(NTE, "pkt came from new peer %s:%u, probing",
                     inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
                update_ipnp(c, &peer);
                arc4random_buf(&c->path_chlg_out, sizeof(c->path_chlg_out));
                c->tx_path_chlg = true;
            }
        }

        if (c == 0) {
            warn(INF, "cannot find conn %s for 0x%02x-type pkt",
                 cid2str(&meta(v).hdr.dcid), meta(v).hdr.flags);
#ifndef FUZZING
            // if this is a 0-RTT pkt, track it (may be reordered)
            if (is_set(F_LONG_HDR, meta(v).hdr.flags) &&
                meta(v).hdr.type == F_LH_0RTT) {
                struct ooo_0rtt * const zo = calloc(1, sizeof(*zo));
                ensure(zo, "could not calloc");
                cid_cpy(&zo->cid, &meta(v).hdr.dcid);
                zo->v = v;
                zo->t = ev_now(loop);
                splay_insert(ooo_0rtt_by_cid, &ooo_0rtt_by_cid, zo);
                log_pkt("RX", v, &odcid, tok, tok_len); // NOLINT
                warn(INF, "caching 0-RTT pkt for unknown conn %s",
                     cid2str(&meta(v).hdr.dcid));
                continue;
            }
#endif
            log_pkt("RX", v, &odcid, tok, tok_len);
            warn(INF, "ignoring unexpected 0x%02x-type pkt for conn %s",
                 meta(v).hdr.flags, cid2str(&meta(v).hdr.dcid));
            q_free_iov(v);
            continue;
        }

        if ((meta(v).hdr.vers && meta(v).hdr.type != F_LH_RTRY) ||
            !is_set(F_LONG_HDR, meta(v).hdr.flags))
            if (dec_pkt_hdr_remainder(xv, v, c, x) == false) {
                log_pkt("RX", v, &odcid, tok, tok_len);
                warn(ERR, "received invalid %u-byte 0x%02x-type pkt, ignoring",
                     v->len, meta(v).hdr.flags);
                q_free_iov(v);
                continue;
            }

        // remember that we had a RX event on this connection
        if (!c->had_rx) {
            c->had_rx = true;
            sl_insert_head(crx, c, node_rx_int);
        }

        if (rx_pkt(c, v, x, &odcid, tok, tok_len))
            rx_crypto(c);

        if (meta(v).stream == 0)
            // we didn't place this pkt in any stream - bye!
            q_free_iov(v);
    }
}


void rx(struct ev_loop * const l,
        ev_io * const rx_w,
        int e __attribute__((unused)))
{
    // read from NIC
    struct w_sock * const ws = rx_w->data;
    w_nic_rx(w_engine(ws), -1);
    struct w_iov_sq x = w_iov_sq_initializer(x);
    struct q_conn_sl crx = sl_head_initializer(crx);
    w_rx(ws, &x);
    rx_pkts(&x, &crx, ws);

    // for all connections that had RX events
    while (!sl_empty(&crx)) {
        struct q_conn * const c = sl_first(&crx);
        sl_remove_head(&crx, node_rx_int);

        if (unlikely(c->state != conn_drng))
            // reset idle timeout
            ev_timer_again(l, &c->idle_alarm);

        // is a TX needed for this connection?
        if (c->needs_tx)
            tx(c, false, 0);

        // clear the helper flags set above
        c->needs_tx = c->had_rx = false;

        if (unlikely(c->tx_rtry))
            // if we sent a retry, forget the entire connection existed
            free_conn(c);
        else if (c->have_new_data) {
            if (!c->in_c_ready) {
                sl_insert_head(&c_ready, c, node_rx_int);
                c->in_c_ready = true;
            }
            maybe_api_return(q_rx_ready, 0, 0);
        }
    }
}


void err_close(struct q_conn * const c,
               const uint16_t code,
               const uint8_t frm,
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

#ifndef FUZZING
    if (c->err_code) {
        warn(WRN, "ignoring new err 0x%04x (%s); existing err is 0x%04x (%s) ",
             code, reas, c->err_code, c->err_reason);
        return;
    }
#endif

    warn(ERR, "%s", reas);
    c->err_code = code;
    c->err_reason = strdup(reas);
    c->err_frm = frm;
    enter_closing(c);
}


static void __attribute__((nonnull))
enter_closed(struct ev_loop * const l __attribute__((unused)),
             ev_timer * const w,
             int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    conn_to_state(c, conn_clsd);

    // terminate whatever API call is currently active
    maybe_api_return(c, 0);
    maybe_api_return(q_accept, 0, 0);
    maybe_api_return(q_rx_ready, 0, 0);
}


void enter_closing(struct q_conn * const c)
{
    if (c->state == conn_clsg)
        return;

    // stop LD and ACK alarms
    ev_timer_stop(loop, &c->rec.ld_alarm);
    ev_timer_stop(loop, &c->idle_alarm);

    // stop ACK alarm and (maybe) send any ACKs we still owe the peer
    for (epoch_t e = ep_init; e <= ep_data; e++) {
        struct pn_space * const pn = pn_for_epoch(c, e);
        if ( // don't ACK when we did this already
            c->state != conn_drng &&
            // we don't ACK in the 0-RTT packet number space
            e != ep_0rtt &&
            // don't ACK here, because there will be in ACK in the CLOSE pkt
            e != c->tls.epoch_out &&
            // don't ACK if the timer is not running
            ev_is_active(&pn->ack_alarm))
            ev_invoke(loop, &pn->ack_alarm, 0);
        ev_timer_stop(loop, &pn->ack_alarm);
    }

#ifndef FUZZING
    if ((c->state == conn_idle || c->state == conn_opng) && c->err_code == 0) {
#endif
        // no need to go closing->draining in these cases
        ev_invoke(loop, &c->closing_alarm, 0);
        return;
#ifndef FUZZING
    }
#endif

    // if we're going closing->draining, don't start the timer again
    if (!ev_is_active(&c->closing_alarm)) {
        // start closing/draining alarm (3 * RTO)
        const ev_tstamp dur =
            (3 * (is_zero(c->rec.srtt) ? kDefaultInitialRtt : c->rec.srtt) +
             4 * c->rec.rttvar);
        ev_timer_init(&c->closing_alarm, enter_closed, dur, 0);
#ifndef FUZZING
        ev_timer_start(loop, &c->closing_alarm);
        warn(DBG, "closing/draining alarm in %f sec on %s conn %s", dur,
             conn_type(c), cid2str(c->scid));
#endif
    }

    if (c->state != conn_drng) {
        c->needs_tx = true;
        conn_to_state(c, conn_clsg);
    }
}


static void __attribute__((nonnull))
idle_alarm(struct ev_loop * const l __attribute__((unused)),
           ev_timer * const w,
           int e __attribute__((unused)))
{
    struct q_conn * const c = w->data;
    warn(DBG, "idle timeout on %s conn %s", conn_type(c), cid2str(c->scid));

    conn_to_state(c, conn_drng);
    enter_closing(c);
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

    // init dcid
    splay_init(&c->dcids_by_seq);
    if (c->is_clnt) {
        struct cid ndcid = {.len = SERV_SCID_LEN};
        arc4random_buf(ndcid.id, ndcid.len);
        arc4random_buf(ndcid.srt, sizeof(ndcid.srt));
        cid_cpy(&c->odcid, &ndcid);
        add_dcid(c, &ndcid);
    } else if (dcid)
        add_dcid(c, dcid);

    c->vers = c->vers_initial = vers;
    splay_init(&c->streams_by_id);
    diet_init(&c->closed_streams);
    sq_init(&c->txq);

    // initialize packet number spaces
    init_pn(&c->pn_init.pn, c);
    init_pn(&c->pn_hshk.pn, c);
    init_pn(&c->pn_data.pn, c);

    // initialize idle timeout
    c->idle_alarm.data = c;
    c->idle_alarm.repeat = idle_to ? idle_to : kIdleTimeout;
    ev_init(&c->idle_alarm, idle_alarm);

    // initialize closing alarm
    c->closing_alarm.data = c;
    ev_init(&c->closing_alarm, enter_closed);

    c->tp_in.ack_del_exp = c->tp_out.ack_del_exp = 3;
    c->tp_in.max_ack_del = c->tp_out.max_ack_del =
        (uint8_t)(1000 * kDelayedAckTimeout);
    c->tp_in.idle_to = kIdleTimeout;
    c->tp_in.max_data = c->is_clnt ? 0x4000 : 0x8000;
    c->tp_in.max_strm_data_bidi_local = c->tp_in.max_strm_data_bidi_remote =
        c->is_clnt ? 0x2000 : 0x4000;
    c->tp_in.max_bidi_streams = c->is_clnt ? 1 : 2;
    c->tp_in.max_uni_streams = 0; // TODO: support unidir streams

    // initialize recovery state
    init_rec(c);

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

    // init scid and add connection to global data structures
    splay_insert(conns_by_ipnp, &conns_by_ipnp, c);
    splay_init(&c->scids_by_seq);
    splay_init(&c->scids_by_id);
    struct cid nscid = {0};
    if (c->is_clnt) {
        nscid.len = CLNT_SCID_LEN;
        arc4random_buf(nscid.id, nscid.len);
    } else {
        if (scid)
            cid_cpy(&nscid, scid);
        else
            nscid.len = 1;
    }
    arc4random_buf(nscid.srt, sizeof(nscid.srt));
    add_scid(c, &nscid);

    // create crypto streams
    for (epoch_t e = ep_init; e <= ep_data; e++)
        new_stream(c, crpt_strm_id(e));

    warn(DBG, "%s conn %s on port %u created", conn_type(c), cid2str(c->scid),
         ntohs(c->sport));

    conn_to_state(c, conn_idle);

    return c;
}


void free_scid(struct q_conn * const c, struct cid * const id)
{
    splay_remove(cids_by_seq, &c->scids_by_seq, id);
    splay_remove(cids_by_id, &c->scids_by_id, id);
    const struct q_cid_map which = {.cid = *id};
    struct q_cid_map * const cm = splay_find(conns_by_id, &conns_by_id, &which);
    splay_remove(conns_by_id, &conns_by_id, cm);
    free(cm);
}


void free_dcid(struct q_conn * const c, struct cid * const id)
{
    splay_remove(cids_by_seq, &c->dcids_by_seq, id);
    free(id);
}


void free_conn(struct q_conn * const c)
{
    // exit any active API call on the connection
    maybe_api_return(c, 0);

    if (c->holds_sock) {
        // only close the socket for the final server connection
        ev_io_stop(loop, &c->rx_w);
        w_close(c->sock);
    }
    ev_timer_stop(loop, &c->rec.ld_alarm);
    ev_timer_stop(loop, &c->closing_alarm);
    ev_timer_stop(loop, &c->idle_alarm);

    struct q_stream *s, *ns;
    for (s = splay_min(streams_by_id, &c->streams_by_id); s; s = ns) {
        ns = splay_next(streams_by_id, &c->streams_by_id, s);
        free_stream(s);
    }
    free_tls(c);

    // free packet number spaces
    free_pn(&c->pn_init.pn);
    free_pn(&c->pn_hshk.pn);
    free_pn(&c->pn_data.pn);

    ev_async_stop(loop, &c->tx_w);

    diet_free(&c->closed_streams);
    free(c->peer_name);
    if (c->err_reason)
        free(c->err_reason);

    // remove connection from global lists and free CID splays
    splay_remove(conns_by_ipnp, &conns_by_ipnp, c);

    while (!splay_empty(&c->scids_by_seq)) {
        struct cid * const id = splay_min(cids_by_seq, &c->scids_by_seq);
        free_scid(c, id);
    }

    while (!splay_empty(&c->dcids_by_seq)) {
        struct cid * const id = splay_min(cids_by_seq, &c->dcids_by_seq);
        free_dcid(c, id);
    }

    if (c->in_c_ready)
        sl_remove(&c_ready, c, q_conn, node_rx_int);

    free(c);
}
