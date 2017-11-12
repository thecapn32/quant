#! /usr/bin/env bash

rm -f /cores/*.core

set -e

# by default, test quant
c=${1:-quant}
s=${2:-quant}

# port to run servers on
addr=127.0.0.1
port=4433 # mozquic server can only run on 4433 at the moment
path=/ #index.html
dir=/Users/lars/Sites/lars/output
cert=lib/src/quant.eggert.org/fullchain.pem
key=lib/src/quant.eggert.org/privkey.pem

# (re-)build the client (and possibly server) to test
ninja "$c"
[ "$c" != "$s" ] && ninja "$s"

export ASAN_OPTIONS=strict_string_checks=1:strict_init_order=1:detect_stack_use_after_return=1:detect_leaks=1:check_initialization_order=1:sleep_before_dying=30:alloc_dealloc_mismatch=1:detect_invalid_pointer_pairs=1
export UBSAN_OPTIONS=suppressions=../misc/ubsan.supp:print_stacktrace=1

# commands to run the different clients against $addr:$port
case $c in
        quant)
                c="bin/client -v5 https://$addr:$port$path"
                ;;
        quicly)
                c="external/usr/local/bin/cli -l /tmp/quicly-c.log -v \
                        -p $path $addr $port"
                ;;
        minq)
                c="env MINQ_LOG=\* GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/client/main.go \
                        -addr $addr:$port -http $path  2>&1 | \
                                grep -v -E 'Frame type (byte )?0'"
                ;;
        ngtcp2)
                c="echo GET / | external/ngtcp2-prefix/src/ngtcp2/examples/client \
                        -i $addr $port"
                ;;
        mozquic)
                c="env MOZQUIC_LOG=all:9 \
                        MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/mozquic-prefix/src/dist/$(cat external/mozquic-prefix/src/dist/latest)/lib \
                        external/mozquic-prefix/src/mozquic/client \
                                -peer $addr:$port -get $path -send-close"
                ;;
        picoquic)
                c="external/picoquic-prefix/src/picoquic/picoquicdemo \
                        $addr $port -r"
                ;;
esac

# commands to run the different servers on  $addr:$port
case $s in
        quant)
                s="sudo bin/server -v5 -p $port -d $dir"
                ;;
        quicly)
                s="external/usr/local/bin/cli -a hq-05 -l /tmp/quicly-s.log -v \
                        -k $key -c $cert $addr $port"
                ;;
        minq)
                s="env MINQ_LOG=\* GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/server/main.go \
                        -addr $addr:$port -http -key $key \
                        -cert $cert -server-name $addr 2>&1 \
                        | grep -v -E 'Frame type (byte )?0'"
                ;;
        ngtcp2)
                s="external/ngtcp2-prefix/src/ngtcp2/examples/server \
                        -d $dir $addr $port $key $cert"
                ;;
        mozquic)
                s="env MOZQUIC_LOG=all:9 \
                        MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/mozquic-prefix/src/dist/$(cat external/mozquic-prefix/src/dist/latest)/lib \
                        external/mozquic-prefix/src/mozquic/server -send-close"
                ;;
        picoquic)
                s="external/picoquic-prefix/src/picoquic/picoquicdemo \
                        -p $port -k $key -c $cert"
                ;;
esac

# if we are on MacOS X, configure the firewall to add delay and loss
# if [ -x /usr/sbin/dnctl ]; then
#         # create pipes to limit bandwidth and add loss
#         sudo dnctl pipe 1 config plr 0.25 #bw 64Kbit/s delay 250 queue 10Kbytes #plr 0.5
#         sudo dnctl pipe 2 config plr 0 #bw 64Kbit/s delay 250 queue 10Kbytes #plr 0.25
#         sudo pfctl -f - <<EOF
#                 dummynet out proto udp from any to $addr port $port pipe 1
#                 dummynet out proto udp from $addr port $port to any pipe 2
# EOF
#         sudo pfctl -e || true
# fi

tmux -CC \
        new-session "sleep 0.1; $c" \; \
        split-window -h "$s" \; \
        set remain-on-exit on

# if we are on MacOS X, unconfigure the firewall
if [ -x /usr/sbin/dnctl ]; then
        sudo pfctl -d
        sudo dnctl -f flush
fi
