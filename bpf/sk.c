//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_SK_C
#define __BPF_VORTEX_SK_C

enum {
    CG_SOCK_BLOCK = 0,
    CG_SOCK_ALLOW = 1,
};

SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *ctx) { return CG_SOCK_ALLOW; }

SEC("cgroup/sock_release")
int cgroup_sock_release(struct bpf_sock *ctx) { return CG_SOCK_ALLOW; }

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx) { return CG_SOCK_ALLOW; }

#endif /* __BPF_VORTEX_SK_C */
