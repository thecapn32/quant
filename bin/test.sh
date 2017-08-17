#! /usr/bin/env bash

rm -f /cores/*.core

set -e

c=${1:-quant}
s=${2:-quant}

ninja "$c"
[ "$c" != "$s" ] && ninja "$s"

case $c in
        quant)
                c=bin/client
                ;;
        quicly)
                c="external/usr/local/bin/cli 127.0.0.1 4433"
                ;;
        minq)
                c="env MINQ_LOG=\* GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/client/main.go"
                ;;
        ngtcp2)
                c="external/ngtcp2-prefix/src/ngtcp2/examples/client \
                        127.0.0.1 4433"
                ;;
        mozquic)
                c="env MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/nss-prefix/src/dist/$(cat external/nss-prefix/src/dist/latest)/lib \
                        external/mozquic-prefix/src/mozquic/client -peer 127.0.0.1"
                ;;
esac

case $s in
        quant)
                s=bin/server
                ;;
        quicly)
                s="external/usr/local/bin/cli -k lib/src/key.pem -c \
                        lib/src/cert.pem 127.0.0.1 4433"
                ;;
        minq)
                s="env MINQ_LOG=\* GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/server/main.go"
                ;;
        ngtcp2)
                s="external/ngtcp2-prefix/src/ngtcp2/examples/server \
                        127.0.0.1 4433 lib/src/key.pem lib/src/cert.pem"
                ;;
        mozquic)
                s="env MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/nss-prefix/src/dist/$(cat external/nss-prefix/src/dist/latest)/lib \
                        external/mozquic-prefix/src/mozquic/server -send-close"
                ;;
esac

tmux -CC \
        new-session "sleep 0.1; $c" \; \
        split-window -h "$s" \; \
        set remain-on-exit on

ls -lta /cores
