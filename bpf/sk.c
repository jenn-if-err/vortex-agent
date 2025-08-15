//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_SK_C
#define __BPF_VORTEX_SK_C

/*
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");
*/

SEC("sockops")
int bpf_sockops_handler(struct bpf_sock_ops *ctx) {
    /*
    __u32 lip4;
    __u32 rip4;
    __u32 lport;
    __u32 rport;
    */

    __u32 op = ctx->op;

    switch (op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: /* we are client */
        break;

        /*
        lip4 = ctx->local_ip4;
        rip4 = ctx->remote_ip4;
        lport = ctx->local_port;
        rport = bpf_ntohl(ctx->remote_port);
        bpf_printk("sockops: ACTIVE conn established: %pI4:%u -> %pI4:%u", &lip4, lport, &rip4, rport);
        */

    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: /* we are server */
        break;

        /*
        lip4 = ctx->local_ip4;
        rip4 = ctx->remote_ip4;
        lport = ctx->local_port;
        rport = bpf_ntohl(ctx->remote_port);

        bpf_printk("sockops: PASSIVE conn established: %pI4:%u -> %pI4:%u", &lip4, lport, &rip4, rport);
        */

        /*
        struct sock_key key = {
            .sip4 = sk_ops->local_ip4,
            .dip4 = sk_ops->remote_ip4,
            .sport = sk_ops->local_port,
            .dport = bpf_ntohl(sk_ops->remote_port),
        };

        bpf_printk("sockops: established connection %pI4:%u -> %pI4:%u", &key.sip4, key.sport, &key.dip4, key.dport);

        int ret = bpf_sock_hash_update(ctx, &sock_map, &rport, BPF_ANY);
        if (ret != 0) {
            bpf_printk("sockops: failed to update sock_hash: %d", ret);
        }
        */
    }

    /* BPF processing for messages on this socket. We do this by setting */
    /* bpf_sock_ops_cb_flags_set(sk_ops, BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG); */

    return BPF_OK;
}

/*
SEC("sk_msg")
int bpf_sk_msg_handler(struct sk_msg_md *msg) {
    return SK_PASS;
}
*/

#endif /* __BPF_VORTEX_SK_C */
