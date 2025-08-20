//go:build ignore

/* Merge, bpf2go only supports one input file. */
#include "base.c"
#include "openssl.c"
#include "sk.c"
#include "socket.c"
#include "tc.c"
#include "xdp.c"

char __license[] SEC("license") = "Dual MIT/GPL";
