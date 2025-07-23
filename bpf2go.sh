#!/bin/sh

bpf2go \
    -tags linux \
    -cflags "-O2 -g -Wall -Werror" \
    -type event \
    -output-dir bpf/ \
    -go-package bpf \
    Bpf ./bpf/bpf.c \
    -- -I./libbpf/src -I./vmlinux.h/include/x86_64
