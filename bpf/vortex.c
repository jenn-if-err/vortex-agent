//go:build ignore

/* Merge, bpf2go only supports one input file. */
#include "base.c"
#include "openssl.c"
#include "socket.c"

char __license[] SEC("license") = "Dual MIT/GPL";
