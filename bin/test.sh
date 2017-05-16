#! /usr/bin/env bash

ninja && tmux new-session -d bin/server -t10 \; \
        split-window -h "sleep 0.1; bin/client -t5" \; \
        set remain-on-exit on \; \
        attach
