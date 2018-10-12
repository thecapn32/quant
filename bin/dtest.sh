#! /usr/bin/env bash

rm -f /cores/*.core

set -e

red=$(tput setaf 1)
green=$(tput setaf 2)
bold=$(tput bold)
norm=$(tput sgr0)


declare -A status col=(
        [ok]="${bold}${green}"
        [fail]="${bold}${red}"
)


function run_test() {
        local base
        base=$(basename -s .qv "$1")
        local dc="docker-compose -p $base"
        local size=10000

        $dc up --no-start 2> /dev/null
        local cmd="$dc run --detach --no-deps -T --service-ports"
        $cmd --name "$base-server" server \
                server -i eth0 -t 1 -v5 -d /www \
                        -c /tls/quant.crt -k /tls/quant.key > /dev/null
        $cmd --name "$base-valve" valve \
                env PYTHONUNBUFFERED=1 qvalve -ra "$base-server" -r "/$t" \
                        > /dev/null
        $cmd --name "$base-client" client \
                client -v5 -i eth0 "https://$base-valve/$size" \
                        > /dev/null

        local ret=ok
        if [ "$(docker container wait "$base-client")" != 0 ] || \
           [ "$(docker container wait "$base-server")" != 0 ]; then
                ret=fail
        elif [ "$(sed -n -E "s/(.*)read (.*) bytes (.*)/\\2/gp" \
                  "$base-client.log")" -ne $size ]; then
                ret=fail
        fi

        for s in server valve client; do
                local log="$base-$s.log"
                if [ "$ret" = "ok" ]; then
                        rm -f "$log"
                else
                        docker logs "$base-$s" > "$log" 2>&1
                fi
        done

        echo "$t ... ${col[$ret]}${ret}${norm}"

        $dc down --timeout 1 2> /dev/null
        echo $ret > "/tmp/$$-$base.ret"
}


# if arguments are given, assume they are tests (otherwise run all)
tests="qvalve-tests/*"
[ ! -z "$*" ] && tests=$*

for t in $tests; do
        run_test "$t" &
done
wait

for t in $tests; do
        base=$(basename -s .qv "$t")
        ret=$(cat "/tmp/$$-$base.ret")
        rm "/tmp/$$-$base.ret"
        status[$ret]=$((status[$ret] + 1))
        status[all]=$((status[all] + 1))

        if [ "$ret" = "fail" ]; then
                tmux -CC \
                    new-session "cat $base-client.log" \; \
                    split-window -h "cat $base-valve.log" \; \
                    split-window -h "cat $base-server.log" \; \
                    set remain-on-exit on
        fi
done

for s in ok fail; do
        [ -n "${status[$s]}" ] && \
                echo "${col[$s]}$s${norm} ${status[$s]}/${status[all]}"
done

