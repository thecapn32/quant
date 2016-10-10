# QUICKIE -- QUIC Kickstarter for Implementation Experience

This will eventually be an independent C implementation of [QUIC](https://www.chromium.org/quic), the Google-originated proposal for a new HTTP/2 transport over UDP.

## Prerequisites

We use the [`cmake`](https://cmake.org/) build system, [`vagrant`](https://www.vagrantup.com/) for testing against Google's [`proto-quic`](https://github.com/google/proto-quic) implementation, as well as some other assorted tools.

We use ['libev'](http://software.schmorp.de/pkg/libev.html) as a basis for the event loop that underlies this implementation. The intent is that it will in the end resemble something like what ['libebb'](http://tinyclouds.org/libebb/) offers for HTTP/1.1 and TLS.

We use ['TommyDS'](http://www.tommyds.it/) for a number of internal datatypes.

We *plan* to use [NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) for its [TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-tls13/) implementation.

So you need to install some dependencies. On the Mac, the easiest way is via [Homebrew](http://brew.sh/), so install that first. Then, do
```
brew install cmake daemonize libev nss
brew cask install vagrant
```
