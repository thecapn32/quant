#! /usr/bin/env bash

rm -f /cores/*.core

c=${1:-quant}
s=${2:-quant}

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
        *)
                echo "Unknown client $c"
                exit 1
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
        *)
                echo "Unknown server $s"
                exit 1
esac

ninja && tmux -CC \
        new-session "sleep 0.1; $c" \; \
        split-window -h "$s" \; \
        set remain-on-exit on

ls -lta /cores
