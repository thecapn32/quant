#! /usr/bin/env bash

ninja && tmux new-session -d "sleep 0.1; bin/client -t3" \; \
        split-window -h bin/server -t5 \; \
        set remain-on-exit on \; \
        attach
