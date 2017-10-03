#! /usr/bin/env bash

rm -f /cores/*.core

set -e

# by default, test quant
c=${1:-quant}
s=${2:-quant}

# port to run servers on
port=44333

# (re-)build the client (and possibly server) to test
ninja "$c"
[ "$c" != "$s" ] && ninja "$s"

# commands to run the different clients against 127.0.0.1:$port
case $c in
        quant)
                c="bin/client https://127.0.0.1:$port/"
                ;;
        quicly)
                c="external/usr/local/bin/cli 127.0.0.1 $port"
                ;;
        minq)
                c="env MINQ_LOG=\* GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/client/main.go"
                ;;
        ngtcp2)
                c="external/ngtcp2-prefix/src/ngtcp2/examples/client \
                        127.0.0.1 $port"
                ;;
        mozquic)
                c="env MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/nss-prefix/src/dist/$(cat external/nss-prefix/src/dist/latest)/lib \
                        external/mozquic-prefix/src/mozquic/client -peer 127.0.0.1"
                ;;
esac

# commands to run the different servers on  127.0.0.1:$port
case $s in
        quant)
                s="bin/server -p $port -d .."
                ;;
        quicly)
                s="external/usr/local/bin/cli -v -k lib/src/key.pem -c \
                        lib/src/cert.pem 127.0.0.1 $port"
                ;;
        minq)
                s="env MINQ_LOG=\* GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/server/main.go"
                ;;
        ngtcp2)
                s="external/ngtcp2-prefix/src/ngtcp2/examples/server \
                        127.0.0.1 $port lib/src/key.pem lib/src/cert.pem"
                ;;
        mozquic)
                s="env MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/nss-prefix/src/dist/$(cat external/nss-prefix/src/dist/latest)/lib \
                        external/mozquic-prefix/src/mozquic/server -send-close"
                ;;
esac

# if we are on MacOS X, configure the firewall to add delay and loss
if [ -x /usr/sbin/dnctl ]; then
        # create pipes to limit bandwidth and add loss
        sudo dnctl pipe 1 config bw 64Kbit/s #delay 50 queue 10Kbytes #plr 0.25
        sudo dnctl pipe 2 config bw 64Kbit/s #delay 50 queue 10Kbytes #plr 0.25
        sudo pfctl -f - <<EOF
                dummynet out proto udp from any to 127.0.0.1 port $port pipe 1
                dummynet out proto udp from 127.0.0.1 port $port to any pipe 2
EOF
        # sudo pfctl -e || true
fi

tmux -CC \
        new-session "sleep 0.1; $c" \; \
        split-window -h "$s" \; \
        set remain-on-exit on

# if we are on MacOS X, unconfigure the firewall
if [ -x /usr/sbin/dnctl ]; then
        # sudo pfctl -d
        sudo dnctl -f flush
fi
