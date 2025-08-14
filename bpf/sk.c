//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_SK_C
#define __BPF_VORTEX_SK_C

struct sock_key {
    __u32 sip4;
    __u32 dip4;
    __u32 sport;
    __u32 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1024);
    __type(key, struct sock_key);
    __type(value, __u32);
} sock_map SEC(".maps");

SEC("sockops")
int bpf_sockops_handler(struct bpf_sock_ops *sk_ops) {
    if (sk_ops->family != AF_INET || sk_ops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
        return BPF_OK;

    struct sock_key key = {
        .sip4 = sk_ops->local_ip4,
        .dip4 = sk_ops->remote_ip4,
        .sport = sk_ops->local_port,
        .dport = bpf_ntohl(sk_ops->remote_port),
    };

    bpf_printk("bpf_sockops_handler: established connection %pI4:%u -> %pI4:%u", &key.sip4, key.sport, &key.dip4,
               key.dport);

    int ret = bpf_sock_hash_update(sk_ops, &sock_map, &key, BPF_NOEXIST);
    if (ret != 0)
        bpf_printk("bpf_sockops_handler: failed to update sock_map: %d", ret);

    return BPF_OK;
}

SEC("sk_msg")
int bpf_sk_msg_handler(struct sk_msg_md *msg) {
    bpf_printk("bpf_sk_msg_handler: message of size %d intercepted on a monitored socket", msg->size);
    return SK_PASS;
}

#endif /* __BPF_VORTEX_SK_C */
