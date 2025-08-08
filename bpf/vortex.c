//go:build ignore

/* Merge all; bpf2go only supports one input file. */
#include "common.c"
#include "maps.c"
#include "openssl.c"
#include "socket.c"

char __license[] SEC("license") = "Dual MIT/GPL";
