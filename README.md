# QUANT – QUIC Userspace Accelerated Network Transfers

These are the beginnings of a BSD-licensed C11 implementation of
[QUIC](https://www.chromium.org/quic), the Google-originated proposal for a new
HTTP/2 transport over UDP. QUANT uses the
[warpcore](https://github.com/NTAP/warpcore) zero-copy  userspace UDP/IPv4 stack
on top of the [netmap](http://info.iet.unipi.it/~luigi/netmap/) packet I/O
framework.

The quant repository is [on GitHub](https://github.com/NTAP/quant), as is
the [documentation](https://ntap.github.io/quant/).

We use [picotls](https://github.com/h2o/picotls) for its [TLS
1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-tls13/) implementation.
Picotls will be built automatically.


## Prerequisites

We use the [cmake](https://cmake.org/) build system.

We use [libev](http://software.schmorp.de/pkg/libev.html) as a basis for the
event loop that underlies this implementation. The intent is that it will in the
end resemble something like what [libebb](http://tinyclouds.org/libebb/)
offers for HTTP/1.1 and TLS.

So you need to install some dependencies. On the Mac, the easiest way is via
[Homebrew](http://brew.sh/), so install that first. Then, do

    brew install cmake libev http-parser doxygen

On Debian-based Linux systems, do

    apt install libev-dev libssl-dev libhttp-parser-dev libbsd-dev

On Darwin, you *must* also install the Xcode command line tools first:

    xcode-select --install


## Building
Warpcore uses [cmake](https://cmake.org/) as a build system. To do an
out-of-source build of warpcore (best practice with `cmake`), do the following
to build with `make` as a generator:

    mkdir Debug
    cd Debug
    cmake ..
    make

The default build (per above) is without optimizations and with extensive debug
logging enabled. In order to build an optimized build, do this:

    mkdir Release
    cd Release
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make


## Testing

The `libquant` library will be in `lib`. There are `client` and `server`
examples in `bin`.


## Copyright

Copyright (c) 2016-2018, NetApp, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


## Acknowledgement

This software has received funding from the European Union's Horizon 2020
research and innovation program 2014-2018 under grant agreement 644866
(["SSICLOPS"](https://ssiclops.eu/)). The European Commission is not responsible
for any use that may be made of this software.


[//]: # (@example client.c)
[//]: # (@example server.c)
