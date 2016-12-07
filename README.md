# QUANT -- QUIC Userspace Accelerated Network Transfers

This will eventually be an independent C implementation of
[QUIC](https://www.chromium.org/quic), the Google-originated proposal for a new
HTTP/2 transport over UDP.


## Prerequisites

We use the [`cmake`](https://cmake.org/) build system,
[`vagrant`](https://www.vagrantup.com/) for testing against Google's
[`proto-quic`](https://github.com/google/proto-quic) implementation, as well as
some other assorted tools. (Note that the [IETF flavor of
QUIC](https://datatracker.ietf.org/wg/quic/charter/), which this implementation
will track, is not expected to interoperate anymore with Google-QUIC.)

We use [`libev`](http://software.schmorp.de/pkg/libev.html) as a basis for the
event loop that underlies this implementation. The intent is that it will in the
end resemble something like what [`libebb`](http://tinyclouds.org/libebb/)
offers for HTTP/1.1 and TLS.

We use [`TommyDS`](http://www.tommyds.it/) for a number of internal datatypes.

We *plan* to use
[`NSS`](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) for its
[TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-tls13/)
implementation. Another alternative might be [ARM
mbed](https://www.mbed.com/en/), once it supports TLS 1.3.

So you need to install some dependencies. On the Mac, the easiest way is via
[Homebrew](http://brew.sh/), so install that first. Then, do

```
brew install cmake daemon libev nss tcpdump wireshark doxygen
brew cask install vagrant
```


## Building
Warpcore uses [cmake](https://cmake.org/) as a build system. To do an
out-of-source build of warpcore (best practice with `cmake`), do the following
to build with `make` as a generator:

```
mkdir Debug
cd Debug
cmake ..
make
```

The default build (per above) is without optimizations and with extensive debug
logging enabled. In order to build an optimized build, do this:

```
mkdir Release
cd Release
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```


## Testing

The `libquant` library will be in `lib`. There are `client` and `server`
examples in `bin`.


## Copyright

Copyright (c) 2016, NetApp, Inc.
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


[//]: # (@example client.c)
[//]: # (@example server.c)
