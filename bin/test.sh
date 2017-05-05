#! /usr/bin/env bash

ninja && tmux new-session -d bin/server -t0 \; \
        split-window -h "sleep 0.1; bin/client " \; \
        set remain-on-exit on \; \
        attach
