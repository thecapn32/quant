#! /usr/bin/env bash

rm -f /cores/*.core

set -e

for t in qvalve-tests/*; do
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
                echo " - success"
        else
                echo " - failed"
                tmux -CC \
                        new-session "${log[client]}" \; \
                        split-window -h "${log[valve]}" \; \
                        split-window -h "${log[server]}" \; \
                        set remain-on-exit on
        fi

        docker-compose rm --force --stop > /dev/null 2> /dev/null
done

docker-compose kill
docker-compose down --timeout 1 --remove-orphans 2> /dev/null
