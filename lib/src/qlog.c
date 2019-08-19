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
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

// IWYU pragma: no_include "../deps/libev/ev.h"

#include "bitset.h"
#include "event.h" // IWYU pragma: keep
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "qlog.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"


static bool prev_event = false;

static ev_tstamp qlog_ref_t = -HUGE_VAL;


static const char * __attribute__((const, nonnull))
qlog_pkt_type_str(const uint8_t flags, const void * const vers)
{
    if (is_lh(flags)) {
        if (((const uint8_t * const)vers)[0] == 0 &&
            ((const uint8_t * const)vers)[1] == 0 &&
            ((const uint8_t * const)vers)[2] == 0 &&
            ((const uint8_t * const)vers)[3] == 0)
            return "VERSION_NEGOTIATION";
        switch (pkt_type(flags)) {
        case LH_INIT:
            return "INITIAL";
        case LH_RTRY:
            return "RETRY";
        case LH_HSHK:
            return "HANDSHAKE";
        case LH_0RTT:
            return "ZERORTT";
        }
    } else if (pkt_type(flags) == SH)
        return "ONERTT";
    return "UNKOWN";
}


static uint64_t __attribute__((const)) to_usec(const ev_tstamp t)
{
    return (uint64_t)(t * US_PER_S);
}


static bool qlog_common()
{
    if (qlog_ref_t < 0)
        return false;

    fprintf(qlog, "%s[%" PRIu64, likely(prev_event) ? "," : "",
            to_usec(ev_now() - qlog_ref_t));

    return true;
}


void qlog_init()
{
    if (qlog && qlog_ref_t < 0) {
        qlog_ref_t = ev_now();
        fprintf(
            qlog,
            "{"
            "\"qlog_version\":\"draft-00\","
            "\"title\":\"%s %s qlog\","
            "\"traces\":["
            "{\"configuration\":{\"time_units\":\"us\"},\"common_fields\":{"
            "\"protocol_type\":\"QUIC_HTTP3\",\"reference_time\":%" PRIu64 "},"
            "\"event_fields\":[\"relative_time\",\"CATEGORY\",\"EVENT_TYPE\","
            "\"TRIGGER\",\"DATA\"],\"events\":[",
            quant_name, quant_version, to_usec(qlog_ref_t));
    }
}


void qlog_close()
{
    if (qlog) {
        fputs("]}]}", qlog);
        fclose(qlog);
    }
}


void qlog_transport(const qlog_pkt_evt_t evt,
                    const char * const trg,
                    struct w_iov * const v,
                    const struct pkt_meta * const m)
{
    if (qlog_common() == false)
        return;

    static const char * const evt_str[] = {[pkt_tx] = "PACKET_SENT",
                                           [pkt_rx] = "PACKET_RECEIVED",
                                           [pkt_dp] = "PACKET_DROPPED"};
    fprintf(qlog,
            ",\"TRANSPORT\",\"%s\",\"%s\",{\"packet_type\":\"%"
            "s\",\"header\":{\"packet_size\":%u",
            evt_str[evt], trg, qlog_pkt_type_str(m->hdr.flags, &m->hdr.vers),
            m->udp_len);
    if (is_lh(m->hdr.flags) == false || (m->hdr.vers && m->hdr.type != LH_RTRY))
        fprintf(qlog, ",\"packet_number\":%" PRIu, m->hdr.nr);
    fputs("}", qlog);

    if (evt == pkt_dp)
        goto done;

    static const struct frames qlog_frm =
        bitset_t_initializer(1 << FRM_ACK | 1 << FRM_STR);
    if (bit_overlap(FRM_MAX, &m->frms, &qlog_frm) == false)
        goto done;

    fputs(",\"frames\":[", qlog);
    int prev_frame = 0;
    if (has_frm(m->frms, FRM_STR)) {
        prev_frame = fprintf(qlog,
                             "%s{\"frame_type\": \"STREAM\",\"id\": %" PRId
                             ",\"length\": %u,\"offset\": %" PRIu,
                             prev_frame ? "," : "", m->strm->id,
                             m->strm_data_len, m->strm_off);
        if (m->is_fin)
            fputs(",\"fin\":true", qlog);
        fputs("}", qlog);
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
        fprintf(qlog,
                "%s{\"frame_type\": \"ACK\",\"ack_delay\": %" PRIu64
                ",\"acked_ranges\":[",
                prev_frame ? "," : "", ack_delay);

        // this is a similar loop as in dec_ack_frame() - keep changes in sync
        for (uint64_t n = ack_rng_cnt + 1; n > 0; n--) {
            uint64_t ack_rng = 0;
            decv(&ack_rng, &pos, end);
            fprintf(qlog, "%s[%" PRIu64 ",%" PRIu64 "]",
                    (n <= ack_rng_cnt ? "," : ""), lg_ack - ack_rng, lg_ack);
            if (n > 1) {
                uint64_t gap = 0;
                decv(&gap, &pos, end);
                lg_ack -= ack_rng + gap + 2;
            }
        }

        adj_iov_to_data(v, m);
        fputs("]}", qlog);
    }
    fputs("]", qlog);

done:
    fputs("}]", qlog);

    prev_event = true;
}


void qlog_recovery(const qlog_rec_evt_t evt,
                   const char * const trg,
                   const struct q_conn * const c)
{
    if (qlog_common() == false)
        return;

    static const char * const evt_str[] = {[rec_mu] = "METRIC_UPDATE"};
    fprintf(qlog, ",\"RECOVERY\",\"%s\",\"%s\",{", evt_str[evt], trg);
    int prev_metric = 0;
    if (c->rec.cur.in_flight != c->rec.prev.in_flight)
        prev_metric = fprintf(qlog, "%s\"bytes_in_flight\":%" PRIu,
                              prev_metric ? "," : "", c->rec.cur.in_flight);
    if (c->rec.cur.cwnd != c->rec.prev.cwnd)
        prev_metric = fprintf(qlog, "%s\"cwnd\":%" PRIu, prev_metric ? "," : "",
                              c->rec.cur.cwnd);
    if (c->rec.cur.ssthresh != UINT_T_MAX &&
        c->rec.cur.ssthresh != c->rec.prev.ssthresh)
        prev_metric = fprintf(qlog, "%s\"ssthresh\":%" PRIu,
                              prev_metric ? "," : "", c->rec.cur.ssthresh);
    if (TM_T_ABS(c->rec.cur.srtt - c->rec.prev.srtt) < TM_T(1.) / US_PER_S)
        prev_metric =
            fprintf(qlog, "%s\"smoothed_rtt\":%" PRIu64, prev_metric ? "," : "",
                    to_usec((double)c->rec.cur.srtt));
    if (c->rec.cur.min_rtt < TM_T_HUGE &&
        TM_T_ABS(c->rec.cur.min_rtt - c->rec.prev.min_rtt) <
            TM_T(1.) / US_PER_S)
        prev_metric =
            fprintf(qlog, "%s\"min_rtt\":%" PRIu64, prev_metric ? "," : "",
                    to_usec((double)c->rec.cur.min_rtt));
    if (TM_T_ABS(c->rec.cur.latest_rtt - c->rec.prev.latest_rtt) <
        TM_T(1.) / US_PER_S)
        prev_metric =
            fprintf(qlog, "%s\"latest_rtt\":%" PRIu64, prev_metric ? "," : "",
                    to_usec((double)c->rec.cur.latest_rtt));
    if (TM_T_ABS(c->rec.cur.rttvar - c->rec.prev.rttvar) <
        TM_T(1.) / US_PER_S)
        // prev_metric =
        fprintf(qlog, "%s\"rtt_variance\":%" PRIu64, prev_metric ? "," : "",
                to_usec((double)c->rec.cur.rttvar));
    fputs("}]", qlog);

    prev_event = true;
}

#else

static void * _unused __attribute__((unused));

#endif
