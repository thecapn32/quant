# QUANT – QUIC Userspace Accelerated Network Transfers

QUANT is a BSD-licensed C11 implementation of the emerging IETF
[QUIC](https://quicwg.github.io/) standard for a new
HTTP/2 transport over UDP. QUANT uses the
[warpcore](https://github.com/NTAP/warpcore) zero-copy  userspace UDP/IPv4 stack
on top of the [netmap](http://info.iet.unipi.it/~luigi/netmap/) packet I/O
framework. It can also operate over the regular Socket API.

The quant repository is [on GitHub](https://github.com/NTAP/quant), as is
the [documentation](https://ntap.github.io/quant/).

We use [picotls](https://github.com/h2o/picotls) for its [TLS
1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-tls13/) implementation.
Picotls will be built automatically.


## Prerequisites

We use the [cmake](https://cmake.org/) build system.

We use [libev](http://software.schmorp.de/pkg/libev.html) as a basis for the
event loop that underlies this implementation.

So you need to install some dependencies. On the Mac, the easiest way is via
[Homebrew](http://brew.sh/), so install that first. Then, do

    brew install cmake libev http-parser doxygen

On Debian-based Linux systems, do

    apt install libev-dev libssl-dev libhttp-parser-dev libbsd-dev

On Darwin, you *must* also install the Xcode command line tools first:

    xcode-select --install


## Building
To do an
out-of-source build of warpcore (best practice with `cmake`), do the following
to build with `make` as a generator:

    git submodule update --init --recursive
    mkdir Debug
    cd Debug
    cmake ..
    make

The default build (per above) is without optimizations and with extensive debug
logging enabled. In order to build an optimized build, do this:

    git submodule update --init --recursive
    mkdir Release
    cd Release
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make


## Docker container

Instead of building quant for yourself, you can also obtain a [pre-built Docker container]
(https://cloud.docker.com/u/ntap/repository/docker/ntap/quant/). For example,

    docker pull ntap/quant:latest

should download the latest build on the `master` branch. The docker container by default exposes a QUIC server on port 4433 that can serve `/index.html` and possibly other resources.

## Testing

The `libquant` library will be in `lib`. There are `client` and `server`
examples in `bin`. They explain their usage when called with a `-h` argument.

The current interop status of quant against [other
stacks](https://github.com/quicwg/base-drafts/wiki/Implementations) is captured
in [this
spreadsheet](https://docs.google.com/spreadsheets/d/1D0tW89vOoaScs3IY9RGC0UesWGAwE6xyLk0l4JtvTVg/edit?usp=sharing).

At the moment, development happens in branches other than `master`, which are
numbered according to the [IETF Internet Drafts](https://quicwg.github.io/) they
implement. The `master` branch is updated whenever such a per-draft branch is
stable.


## Contributing

I'm happy to merge contributions that fix
[bugs](https://github.com/NTAP/quant/issues?q=is%3Aopen+is%3Aissue+label%3Abug)
or add
[features](https://github.com/NTAP/quant/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement).
Please send pull requests.

(Contributions to the underlying [warpcore](https://github.com/NTAP/warpcore)
stack are also very welcome.)


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
