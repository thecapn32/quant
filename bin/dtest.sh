#! /usr/bin/env bash

rm -f /cores/*.core

set -e

docker-compose up --no-color --force-recreate --remove-orphans -d

tmux -CC \
        new-session "docker-compose logs -f client | cut -f2 -d\\|" \; \
        split-window -h "docker-compose logs -f valve | cut -f2 -d\\|" \; \
        split-window -h "docker-compose logs -f server | cut -f2 -d\\|" \; \
        set remain-on-exit on

docker-compose kill
