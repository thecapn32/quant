#! /usr/bin/env bash

rm -f /cores/*.core

set -e

red=$(tput setaf 1)
green=$(tput setaf 2)
bold=$(tput bold)
norm=$(tput sgr0)

# clean up from previous run
docker-compose down --timeout 1 --remove-orphans 2> /dev/null

# if arguments are given, assume they are tests (otherwise run all)
tests="qvalve-tests/*"
[ ! -z "$*" ] && tests=$*

declare -A col=(
        [ok]="${bold}${green}"
        [fail]="${bold}${red}"
)

declare -A status
for t in $tests; do
        echo -n "$t ..."

        cmd="docker-compose run --detach --no-deps -T --service-ports"
        $cmd --name server server > /dev/null 2> /dev/null
        $cmd --name valve valve \
                env PYTHONUNBUFFERED=1 qvalve -ra server -r "/$t" > /dev/null
        $cmd --name client client \
                client -v4 -i eth0 https://valve/10000 > /dev/null

        if [ "$(docker container wait client)" == 0 ] && \
           [ "$(docker container wait server)" == 0 ]; then
                stat=ok
        else
                stat=fail
                # save the logs
                base=$(basename -s .qv "$t")
                for s in server valve client; do
                        docker logs $s > "${base}-${s}.log" 2>&1
                done
        fi

        echo " ${col[$stat]}${stat}${norm}"
        status[$stat]=$((status[$stat] + 1))
        status[all]=$((status[all] + 1))

        docker-compose rm --force --stop > /dev/null 2> /dev/null
done

for s in ok fail; do
        [ -n "${status[$s]}" ] && \
                echo "${col[$s]}$s${norm} ${status[$s]}/${status[all]}"
done

docker-compose kill
docker-compose down --timeout 1 --remove-orphans 2> /dev/null
