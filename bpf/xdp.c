//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_XDP_C
#define __BPF_VORTEX_XDP_C

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(4, 8, 0))
        return XDP_PASS;

    return XDP_PASS;
}

#endif /* __BPF_VORTEX_XDP_C */
