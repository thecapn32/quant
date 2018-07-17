#! /usr/bin/env bash

rm -f /cores/*.core

set -e

red=$(tput setaf 1)
green=$(tput setaf 2)
# blue=$(tput setaf 4)
bold=$(tput bold)
norm=$(tput sgr0)

# clean up from previous run
docker-compose down --timeout 1 --remove-orphans 2> /dev/null

# if arguments are given, assume they are tests (otherwise run all)
tests="qvalve-tests/*"
[ ! -z "$*" ] && tests=$*

declare -A status col
col[ok]="${bold}${green}"
col[fail]="${bold}${red}"

for t in $tests; do
        echo -n "$t"

        declare -A log cmd ret
        for s in server valve client; do
                cmd[$s]="docker-compose run --detach --no-deps -T \
                        --service-ports --name $s $s"
                log[$s]="docker logs --follow $s"
        done

        ${cmd[server]} > /dev/null 2> /dev/null
        ${cmd[valve]} env PYTHONUNBUFFERED=1 \
                qvalve -ra server -r "/$t" > /dev/null
        ${cmd[client]} client -v4 -i eth0 https://valve/10000 > /dev/null

        for s in client server; do
                ret[$s]=$(docker container wait $s)
        done

        if [ "${ret[client]}" == 0 ] && [ "${ret[server]}" == 0 ]; then
                stat=ok
        else
                stat=fail
                tmux -CC \
                        new-session "${log[client]}" \; \
                        split-window -h "${log[valve]}" \; \
                        split-window -h "${log[server]}" \; \
                        set remain-on-exit on
        fi
        echo " - ${col[$stat]}${stat}${norm}"
        status[$stat]=$((status[$stat] + 1))
        status[all]=$((status[all] + 1))

        docker-compose rm --force --stop > /dev/null 2> /dev/null
done

for s in ok fail; do
        [ -n "${status[$s]}" ] && \
                echo ${col[$s]}$s${norm} ${status[$s]}/${status[all]}
done


docker-compose kill
docker-compose down --timeout 1 --remove-orphans 2> /dev/null
