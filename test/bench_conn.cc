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


#include <arpa/inet.h>
#include <cstdint>
#include <fcntl.h>
#include <libgen.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <benchmark/benchmark.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>


static struct w_engine * w;
static struct q_conn *cc, *sc;


static uint32_t io(const uint32_t len)
{
    // reserve a new stream
    struct q_stream * s = q_rsv_stream(cc, true);

    // allocate buffers to transmit a packet
    struct w_iov_sq o = w_iov_sq_initializer(o);
    q_alloc(w, &o, len);

    // send the data
    q_write(s, &o, true);
    q_close_stream(s);

    // read the data
    struct w_iov_sq i = w_iov_sq_initializer(i);
    s = q_read(sc, &i, true);
    q_close_stream(s);

    q_free(&i);
    q_free(&o);

    return len;
}


static void BM_conn(benchmark::State & state)
{
    const auto len = uint32_t(state.range(0));
    for (auto _ : state)
        benchmark::DoNotOptimize(io(len));
    state.SetBytesProcessed(int64_t(state.iterations() * len)); // NOLINT
}


BENCHMARK(BM_conn)->RangeMultiplier(2)->Ranges({{4096, 65535 * 8}})
    // ->MinTime(3)
    // ->UseRealTime()
    ;


// BENCHMARK_MAIN()

int main(int argc __attribute__((unused)), char ** argv)
{
#ifndef NDEBUG
    util_dlevel = ERR; // default to maximum compiled-in verbosity
#endif

    // init
    const int cwd = open(".", O_CLOEXEC);
    ensure(cwd != -1, "cannot open");
    ensure(chdir(dirname(argv[0])) == 0, "cannot chdir");
    w = q_init("lo"
#ifndef __linux__
               "0"
#endif
               ,
               "dummy.crt", "dummy.key", nullptr, nullptr, false, true);
    ensure(fchdir(cwd) == 0, "cannot fchdir");

    // bind server socket
    q_bind(w, 55555);

    // connect to server
    const struct sockaddr_in sip = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = inet_addr("127.0.0.1"),
                                    .sin_port = htons(55555)};
    cc = q_connect(w, &sip, "localhost", nullptr, nullptr, true, 0);
    ensure(cc, "is zero");

    // accept connection
    sc = q_accept(0);
    ensure(sc, "is zero");

    benchmark::RunSpecifiedBenchmarks();

    // close connections
    q_close(cc);
    q_close(sc);
    q_cleanup(w);
}
