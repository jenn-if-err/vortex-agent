//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_SK_C
#define __BPF_VORTEX_SK_C

enum {
    CG_SOCK_BLOCK = 0,
    CG_SOCK_ALLOW = 1,
};

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx) {
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(4, 17, 0))
        return CG_SOCK_ALLOW;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct bpf_sock *sk = BPF_CORE_READ(ctx, sk);
    bpf_map_update_elem(&sk_to_pid_tgid, &sk, &pid_tgid, BPF_ANY);
    return CG_SOCK_ALLOW;
}

SEC("cgroup/sock_release")
int cgroup_sock_release(struct bpf_sock *ctx) {
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(4, 10, 0))
        return CG_SOCK_ALLOW;

    bpf_map_delete_elem(&sk_to_pid_tgid, &ctx);
    return CG_SOCK_ALLOW;
}

#endif /* __BPF_VORTEX_SK_C */
