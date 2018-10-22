#! /usr/bin/env bash

rm -f /cores/*.core

set -e

# by default, test quant
c=${1:-quant}
s=${2:-quant}

# port to run servers on
addr=127.0.0.1
port=4433 # mozquic server can only run on 4433 at the moment
path=/20000
dir=/Users/lars/Sites/lars/output/papers
cert=/etc/letsencrypt/live/slate.eggert.org/fullchain.pem
key=/etc/letsencrypt/live/slate.eggert.org/privkey.pem

# (re-)build the client (and possibly server) to test
if [ "$c" == wquant ] || [ "$s" == wquant ]; then
        delay=3
        addr=$(vagrant ssh -c 'ip -o -4 address show enp0s8')
        addr=$(echo $addr | awk '{print $4;}' | cut -d/ -f 1)
        iface=$(route get $addr | grep interface | cut -f2 -d:)
        vagrant ssh -c "\
                mkdir -p /vagrant/Linux; \
                cd /vagrant/Linux; \
                cmake -GNinja .. && ninja; \
                sudo dhclient enp0s8"
else
        delay=.2
        iface=lo0
        ninja "$c"
        [ "$c" != "$s" ] && ninja "$s"
fi

set +e

export ASAN_OPTIONS=strict_string_checks=1:strict_init_order=1:detect_stack_use_after_return=1:detect_leaks=1:check_initialization_order=1:sleep_before_dying=30:alloc_dealloc_mismatch=1:detect_invalid_pointer_pairs=1
# export LSAN_OPTIONS=log_threads=1
export UBSAN_OPTIONS=print_stacktrace=1

# commands to run the different clients against $addr:$port
case $c in
        quant)
                cc="bin/client -v5 -i $iface -u 8000 \
                        https://$addr:$port$path" # https://$addr:$port$path"
                ;;
        wquant)
                cc="vagrant ssh -c \"\
                        /vagrant/Linux/bin/client -v5 -i enp0s8 \
                                https://$addr:44433$path\""
                ;;
        quicly)
                cc="external/quicly-prefix/src/quicly-build/cli \
                        -l /tmp/quicly-c.log -s /tmp/quicly-session -n -v \
                        -p $path $addr $port"
                ;;
        minq)
                cc="env MINQ_LOG=aead,connection,ack,handshake,tls,server,udp \
                        GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/client/main.go \
                        -addr $addr:$port -http $path"
                ;;
        ngtcp2)
                touch /tmp/ngtcp2-session /tmp/ngtcp2-tp
                cc="echo GET $path | \
                        external/ngtcp2-prefix/src/ngtcp2/examples/client -s \
                        -i $addr $port --session-file=/tmp/ngtcp2-session \
                        --tp-file=/tmp/ngtcp2-tp"
                ;;
        mozquic)
                cc="env MOZQUIC_LOG=all:9 \
                        MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/mozquic-prefix/src/dist/$(cat external/mozquic-prefix/src/dist/latest)/lib \
                        external/mozquic-prefix/src/mozquic/client \
                                -peer $addr:$port -get $path \
                                -ignorePKI -send-close"
                ;;
        picoquic)
                cc="external/picoquic-prefix/src/picoquic/picoquicdemo \
                        -1 -n localhost -u 1 $addr $port"
                ;;

        quicker)
                cc="external/bin/node external/quicker-prefix/src/quicker/out/mainclient.js $addr $port"
                ;;

        quic-tracker)
                cc="sudo env GOPATH=$(pwd)/external/go \
                        CGO_CFLAGS=-I/usr/local/opt/openssl@1.1/include \
                        CGO_LDFLAGS=-L/usr/local/opt/openssl@1.1/lib \
                    go run $(pwd)/external/go/src/github.com/QUIC-Tracker/quic-tracker/bin/test_suite/scenario_runner.go \
                        -interface lo0 -host $addr:$port -scenario flow_control"
                ;;
esac

# commands to run the different servers on  $addr:$port
case $s in
        quant)
                sc="bin/server -v5 -c $cert -k $key -i $iface -p $port -d $dir"
                ;;
        wquant)
                sc="vagrant ssh -c \"\
                        /vagrant/Linux/bin/server -i enp0s8 -v5 -p $port \
                                -c ~/slate.eggert.org/fullchain.pem \
                                -k ~/slate.eggert.org/privkey.pem \
                                -d /usr/share/doc/valgrind/html\""
                ;;
        quicly)
                sc="external/quicly-prefix/src/quicly-build/cli \
                        -l /tmp/quicly-s.log -v \
                        -k $key -c $cert $addr $port"
                ;;
        minq)
                sc="env MINQ_LOG=aead,connection,ack,handshake,tls,server,udp \
                        GOPATH=$(pwd)/external/go go run \
                        external/go/src/github.com/ekr/minq/bin/server/main.go \
                        -addr $addr:$port -http -key $key -stateless-reset \
                        -cert $cert -server-name $addr"
                ;;
        ngtcp2)
                sc="external/ngtcp2-prefix/src/ngtcp2/examples/server -s \
                        -d $dir $addr $port $key $cert"
                ;;
        mozquic)
                sc="env MOZQUIC_LOG=all:9 \
                        MOZQUIC_NSS_CONFIG=external/mozquic-prefix/src/mozquic/sample/nss-config \
                        DYLD_LIBRARY_PATH=external/mozquic-prefix/src/dist/$(cat external/mozquic-prefix/src/dist/latest)/lib \
                        external/mozquic-prefix/src/mozquic/server \
                        -ignorePKI -send-close -0rtt"
                ;;
        picoquic)
                sc="external/picoquic-prefix/src/picoquic/picoquicdemo \
                        -p $port -k $key -c $cert -1"
                ;;
        ats)
                sed -i"" -e "s/.*proxy.config.http.server_ports.*/CONFIG proxy.config.http.server_ports STRING $port:quic/g" external/etc/trafficserver/records.config
                echo "dest_ip=* ssl_cert_name=$cert ssl_key_name=$key" > external/etc/trafficserver/ssl_multicert.config
                echo "map / http://127.0.0.1:8000/" > external/etc/trafficserver/remap.config
                sc="external/bin/traffic_server"
                ;;

        quicker)
                sc="external/bin/node external/quicker-prefix/src/quicker/out/main.js $addr $port $key $cert"
                ;;
esac

# # if we are on MacOS X, configure the firewall to add delay and loss
# if [ -x /usr/sbin/dnctl ]; then
#         # create pipes to limit bandwidth and add loss
#         sudo dnctl pipe 1 config bw 128Kbit/s delay 50 queue 10Kbytes #plr 0.25
#         sudo dnctl pipe 2 config bw 128Kbit/s delay 50 queue 10Kbytes #plr 0.25
#         sudo pfctl -f - <<EOF
#                 dummynet out proto udp from any to $addr port $port pipe 1
#                 dummynet out proto udp from $addr port $port to any pipe 2
# EOF
#         sudo pfctl -e || true
# fi

tmux -CC \
        new-session "sleep $delay; $cc; sleep 1" \; \
        split-window -h "$sc; sleep 1" \; \
        set remain-on-exit on

# ats doesn't exit cleanly
pkill -9 traffic_server

# # if we are on MacOS X, unconfigure the firewall
# if [ -x /usr/sbin/dnctl ]; then
#         sudo dnctl -f flush
#         sudo pfctl -f /etc/pf.conf -d
# fi
