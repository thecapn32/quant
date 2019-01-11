// Copyright (c) 2014-2018, NetApp, Inc.
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

#include <net/if.h>

#include <benchmark/benchmark.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <picotls/openssl.h> // IWYU pragma: keep

#include "conn.h" // IWYU pragma: keep
#include "pkt.h"
#include "quic.h"
#include "tls.h" // IWYU pragma: keep

#ifdef __cplusplus
}
#endif


static struct q_conn * c;
static struct w_engine * w;


static void BM_quic_encryption(benchmark::State & state)
{
    const auto len = uint16_t(state.range(0));
    const auto pne = uint16_t(state.range(1));
    struct w_iov * v = alloc_iov(w, len, 0);
    struct w_iov * x = alloc_iov(w, MAX_PKT_LEN, 0);

    ptls_openssl_random_bytes(v->buf, len);
    meta(v).hdr.type = LH_INIT;
    meta(v).hdr.flags = HEAD_FORM | meta(v).hdr.type;
    meta(v).hdr.hdr_len = 16;

    for (auto _ : state)
        benchmark::DoNotOptimize(enc_aead(c, v, x, pne * 16));
    state.SetBytesProcessed(int64_t(state.iterations() * len)); // NOLINT

    free_iov(x);
    free_iov(v);
}


BENCHMARK(BM_quic_encryption)
    ->RangeMultiplier(2)
    ->Ranges({{16, MAX_PKT_LEN}, {0, 1}})
    // ->MinTime(3)
    // ->UseRealTime()
    ;


// BENCHMARK_MAIN()

int main(int argc, char ** argv)
{
    char i[IFNAMSIZ] = "lo"
#ifndef __linux__
                       "0"
#endif
        ;

    benchmark::Initialize(&argc, argv);
#ifndef NDEBUG
    util_dlevel = INF;
#endif
    w = q_init(i, nullptr);
    __extension__ struct cid cid = {
        .len = 4,
#if defined(__GNUC__) && !defined(__clang__)
        {.id = "1234"}
#else
        .id = "1234"
#endif
    };
    c = new_conn(w, 0xff00000e, &cid, &cid, nullptr, "", 55555, nullptr);
    init_tls(c);
    benchmark::RunSpecifiedBenchmarks();

    q_cleanup(w);
}
