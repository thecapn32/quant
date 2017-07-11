#! /usr/bin/env bash

rm -f /cores/server.core /cores/client.core

v=${1:-5}

ninja && tmux -CC \
        new-session "sleep 0.1; bin/client -v$v" \; \
        split-window -h "bin/server -v$v" \; \
        set remain-on-exit on
