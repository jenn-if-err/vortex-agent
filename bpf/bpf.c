//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"

#define AF_INET  2
#define AF_INET6 10

struct event {
    __u32 pid;
    __u32 tgid;
    __s64 bytes;    // bytes sent/received or error code
    __u16 family;   // AF_INET, AF_INET6, etc.
    __s16 type;     // SOCK_STREAM, SOCK_DGRAM, etc.
    __u16 protocol; // IPPROTO_TCP, IPPROTO_UDP, etc.
    __u32 is_send;  // 1 if send event, 0 if receive event
    __be32 saddr;
    __u16 sport;
    __be32 daddr;
    __be16 dport;
    u8 comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
    __type(value, struct event);
} events SEC(".maps");

static __always_inline
int set_event_fields(__u32 is_send, struct event *event, struct socket *sock, long ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->tgid = pid_tgid >> 32;
    event->bytes = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->is_send = is_send;
    event->family = 0;
    event->type = 0;
    event->protocol = 0;

    int ret_val = 0;

    if (sock) {
        BPF_CORE_READ_INTO(&event->type, sock, type);
        if (!(event->type == SOCK_STREAM || event->type == SOCK_DGRAM)) {
            ret_val = -1;
        }

        if (sock->sk) {
            BPF_CORE_READ_INTO(&event->family, sock->sk, __sk_common.skc_family);
            BPF_CORE_READ_INTO(&event->protocol, sock->sk, sk_protocol);

            if (!(event->family == AF_INET || event->family == AF_INET6)) {
                ret_val = -1;
            }

            BPF_CORE_READ_INTO(&event->saddr, sock->sk, __sk_common.skc_rcv_saddr);
            BPF_CORE_READ_INTO(&event->sport, sock->sk, __sk_common.skc_num);
            BPF_CORE_READ_INTO(&event->daddr, sock->sk, __sk_common.skc_daddr);
            __be16 dport = 0;
            BPF_CORE_READ_INTO(&dport, sock->sk, __sk_common.skc_dport);
            event->dport = bpf_htons(dport);
        }
    }

    return ret_val;
}

SEC("fentry/sock_sendmsg")
int BPF_PROG2(sock_sendmsg_fentry, struct socket*, sock, struct msghdr*, msg) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    int discard = set_event_fields(1, e, sock, 1);
    if (discard < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fexit/sock_recvmsg")
int BPF_PROG2(sock_recvmsg_fexit, struct socket*, sock, struct msghdr*, msg, int, flags, int, ret) {
    if (ret <= 0) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    int discard = set_event_fields(0, e, sock, ret);
    if (discard < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
