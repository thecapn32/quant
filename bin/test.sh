#! /usr/bin/env bash

rm -f /cores/*.core

c=${1:-quant}
s=${2:-quant}


case $c in
        quant)
                ninja client || exit 1
                c=bin/client
                ;;
        quicly)
                ninja quicly || exit 1
                c="external/usr/local/bin/cli 127.0.0.1 4433"
                ;;
        minq)
                ninja minq || exit 1
                c="env MINQ_LOG=\* GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/client/main.go"
                ;;
        ngtcp2)
                ninja ngtcp2 || exit 1
                c="external/ngtcp2-prefix/src/ngtcp2/examples/client \
                        127.0.0.1 4433"
                ;;
        mozquic)
                ninja mozquic || exit 1
                c="env MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/nss-prefix/src/dist/Darwin16.6.0_cc_64_DBG.OBJ/lib \
                        external/mozquic-prefix/src/mozquic/client"
                ;;
        *)
                echo "Unknown client $c"
                exit 1
esac

case $s in
        quant)
                ninja server || exit 1
                s=bin/server
                ;;
        quicly)
                ninja quicly || exit 1
                s="external/usr/local/bin/cli -k lib/src/key.pem -c \
                        lib/src/cert.pem 127.0.0.1 4433"
                ;;
        minq)
                ninja minq || exit 1
                s="env MINQ_LOG=\* GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/server/main.go"
                ;;
        ngtcp2)
                ninja ngtcp2 || exit 1
                s="external/ngtcp2-prefix/src/ngtcp2/examples/server \
                        127.0.0.1 4433 lib/src/key.pem lib/src/cert.pem"
                ;;
        mozquic)
                ninja mozquic || exit 1
                s="env MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/nss-prefix/src/dist/Darwin16.6.0_cc_64_DBG.OBJ/lib \
                        external/mozquic-prefix/src/mozquic/server"
                ;;
        *)
                echo "Unknown server $s"
                exit 1
esac

tmux -CC \
        new-session "sleep 0.1; $c" \; \
        split-window -h "$s" \; \
        set remain-on-exit on

ls -lta /cores
