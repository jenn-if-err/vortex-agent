//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_XDP_C
#define __BPF_VORTEX_XDP_C

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) { return XDP_PASS; }

#endif /* __BPF_VORTEX_XDP_C */
