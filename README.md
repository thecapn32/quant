# QUICKIE -- QUIC Kickstarter for Implementation Experience

This will eventually be an independent C implementation of [QUIC](https://www.chromium.org/quic), the Google-originated proposal for a new HTTP/2 transport over UDP.

## Prerequisites

We use the [`cmake`](https://cmake.org/) build system, [`vagrant`](https://www.vagrantup.com/) for testing against Google's [`proto-quic`](https://github.com/google/proto-quic) implementation, as well as some other assorted tools.

So you need to install some dependencies. On the Mac, the easiest way is via [Homebrew](http://brew.sh/), so install that first. Then, do
```
brew install cmake daemonize
brew cask install vagrant
```
