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

#ifndef NO_QLOG

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <quant/quant.h>

#include "bitset.h"
#include "frame.h"
#include "loop.h"
#include "marshall.h"
#include "pkt.h"
#include "qlog.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"


static const char * __attribute__((const, nonnull))
qlog_pkt_type_str(const uint8_t flags, const void * const vers)
{
    if (is_lh(flags)) {
        if (((const uint8_t * const)vers)[0] == 0 &&
            ((const uint8_t * const)vers)[1] == 0 &&
            ((const uint8_t * const)vers)[2] == 0 &&
            ((const uint8_t * const)vers)[3] == 0)
            return "version_negotiation";
        switch (pkt_type(flags)) {
        case LH_INIT:
            return "initial";
        case LH_RTRY:
            return "retry";
        case LH_HSHK:
            return "handshake";
        case LH_0RTT:
            return "zerortt";
        }
    } else if (pkt_type(flags) == SH)
        return "onertt";
    return "unkown";
}


static bool qlog_common(const struct cid * const gid,
                        const struct per_engine_data * const ped)
{
    if (ped->qlog_ref_t == 0)
        return false;

    fprintf(ped->qlog, "%s[%" PRIu64 ",\"%s\"",
            likely(ped->qlog_prev_event) ? "," : "",
            NS_TO_US(loop_now() - ped->qlog_ref_t),
            hex2str(gid->id, gid->len, (char[hex_str_len(CID_LEN_MAX)]){""},
                    hex_str_len(CID_LEN_MAX)));

    return true;
}


void qlog_init(const struct q_conn * const c)
{
    if (ped(c->w)->qlog && ped(c->w)->qlog_ref_t == 0) {
        ped(c->w)->qlog_ref_t = loop_now();
        fprintf(
            ped(c->w)->qlog,
            "{\"qlog_version\":\"draft-01\",\"title\":\"%s %s "
            "qlog\",\"traces\":[{\"vantage_point\":{\"type\":\"%s\"},"
            "\"configuration\":{\"time_units\":\"us\"},\"common_fields\":{"
            "\"protocol_type\":\"QUIC_HTTP3\",\"reference_time\":%" PRIu64
            "},\"event_fields\":[\"relative_time\",\"group_id\",\"category\","
            "\"event\",\"trigger\",\"data\"],\"events\":[",
            quant_name, quant_version, is_clnt(c) ? "client" : "server",
            NS_TO_US(ped(c->w)->qlog_ref_t));
    }
}


void qlog_close(FILE * const qlog)
{
    if (qlog) {
        fputs("]}]}", qlog);
        fclose(qlog);
    }
}


void qlog_transport(const qlog_pkt_evt_t evt,
                    const char * const trg,
                    struct per_engine_data * const ped,
                    struct w_iov * const v,
                    const struct pkt_meta * const m,
                    const struct cid * const gid)
{
    if (qlog_common(gid, ped) == false)
        return;

    static const char * const evt_str[] = {[pkt_tx] = "packet_sent",
                                           [pkt_rx] = "packet_received",
                                           [pkt_dp] = "packet_dropped"};
    fprintf(ped->qlog,
            ",\"transport\",\"%s\",\"%s\",{\"packet_type\":\"%s\",\"header\":{"
            "\"packet_size\":%u",
            evt_str[evt], trg, qlog_pkt_type_str(m->hdr.flags, &m->hdr.vers),
            m->udp_len);
    if (is_lh(m->hdr.flags) == false || (m->hdr.vers && m->hdr.type != LH_RTRY))
        fprintf(ped->qlog, ",\"packet_number\":%" PRIu, m->hdr.nr);
    fputs("}", ped->qlog);

    if (evt == pkt_dp)
        goto done;

    static const struct frames qlog_frm =
        bitset_t_initializer(1 << FRM_ACK | 1 << FRM_STR);
    if (bit_overlap(FRM_MAX, &m->frms, &qlog_frm) == false)
        goto done;

    fputs(",\"frames\":[", ped->qlog);
    int prev_frame = 0;
    if (has_frm(m->frms, FRM_STR)) {
        prev_frame = fprintf(ped->qlog,
                             "%s{\"frame_type\":\"stream\",\"stream_id\":%" PRId
                             ",\"length\":%u,\"offset\":%" PRIu,
                             prev_frame ? "," : "", m->strm->id,
                             m->strm_data_len, m->strm_off);
        if (m->is_fin)
            fputs(",\"fin\":true", ped->qlog);
        fputs("}", ped->qlog);
    }

    if (has_frm(m->frms, FRM_ACK)) {
        adj_iov_to_start(v, m);
        const uint8_t * pos = v->buf + m->ack_frm_pos;
        const uint8_t * const end = v->buf + v->len;

        uint64_t lg_ack = 0;
        decv(&lg_ack, &pos, end);
        uint64_t ack_delay = 0;
        decv(&ack_delay, &pos, end);
        uint64_t ack_rng_cnt = 0;
        decv(&ack_rng_cnt, &pos, end);

        // prev_frame =
        fprintf(ped->qlog,
                "%s{\"frame_type\":\"ack\",\"ack_delay\":%" PRIu64
                ",\"acked_ranges\":[",
                prev_frame ? "," : "", ack_delay);

        // this is a similar loop as in dec_ack_frame() - keep changes in sync
        for (uint64_t n = ack_rng_cnt + 1; n > 0; n--) {
            uint64_t ack_rng = 0;
            decv(&ack_rng, &pos, end);
            fprintf(ped->qlog, "%s[%" PRIu64 ",%" PRIu64 "]",
                    (n <= ack_rng_cnt ? "," : ""), lg_ack - ack_rng, lg_ack);
            if (n > 1) {
                uint64_t gap = 0;
                decv(&gap, &pos, end);
                lg_ack -= ack_rng + gap + 2;
            }
        }

        adj_iov_to_data(v, m);
        fputs("]}", ped->qlog);
    }
    fputs("]", ped->qlog);

done:
    fputs("}]", ped->qlog);

    ped->qlog_prev_event = true;
}


void qlog_recovery(const qlog_rec_evt_t evt,
                   const char * const trg,
                   const struct q_conn * const c,
                   const struct pkt_meta * const m,
                   const struct cid * const gid)
{
    struct per_engine_data * const ped = ped(c->w);

    if (qlog_common(gid, ped) == false)
        return;

    static const char * const evt_str[] = {
        [rec_mu] = "metrics_updated", [rec_pl] = "packet_lost"};
    fprintf(ped->qlog, ",\"recovery\",\"%s\",\"%s\",{", evt_str[evt], trg);

    if (evt == rec_pl) {
        fprintf(ped->qlog, "\"packet_number\":%" PRIu, m->hdr.nr);
        goto done;
    }

    int prev_metric = 0;
    if (c->rec.cur.in_flight != c->rec.prev.in_flight)
        prev_metric = fprintf(ped->qlog, "%s\"bytes_in_flight\":%" PRIu,
                              prev_metric ? "," : "", c->rec.cur.in_flight);
    if (c->rec.cur.cwnd != c->rec.prev.cwnd)
        prev_metric = fprintf(ped->qlog, "%s\"cwnd\":%" PRIu,
                              prev_metric ? "," : "", c->rec.cur.cwnd);
#if 0
    if (c->rec.cur.ssthresh != UINT_T_MAX &&
        c->rec.cur.ssthresh != c->rec.prev.ssthresh)
        prev_metric = fprintf(ped->qlog, "%s\"ssthresh\":%" PRIu,
                              prev_metric ? "," : "", c->rec.cur.ssthresh);
#endif
    if (c->rec.cur.srtt != c->rec.prev.srtt)
        prev_metric = fprintf(ped->qlog, "%s\"smoothed_rtt\":%" PRIu,
                              prev_metric ? "," : "", c->rec.cur.srtt);
    if (c->rec.cur.min_rtt < UINT_T_MAX &&
        c->rec.cur.min_rtt != c->rec.prev.min_rtt)
        prev_metric = fprintf(ped->qlog, "%s\"min_rtt\":%" PRIu,
                              prev_metric ? "," : "", c->rec.cur.min_rtt);
    if (c->rec.cur.latest_rtt != c->rec.prev.latest_rtt)
        // prev_metric =
        fprintf(ped->qlog, "%s\"latest_rtt\":%" PRIu, prev_metric ? "," : "",
                c->rec.cur.latest_rtt);
#if 0
    if (c->rec.cur.rttvar != c->rec.prev.rttvar)
        // prev_metric =
        fprintf(ped->qlog, "%s\"rtt_variance\":%" PRIu, prev_metric ? "," : "",
                c->rec.cur.rttvar);
#endif

done:
    fputs("}]", ped->qlog);

    ped->qlog_prev_event = true;
}

#else

static void * _unused __attribute__((unused));

#endif
