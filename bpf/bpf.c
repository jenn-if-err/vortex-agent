//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#define AF_INET 2

// Event structure to send to user space for both send and receive
struct event {
    __u32 pid;
    __u32 tgid;
    __s64 bytes;    // bytes sent/received or error code
    __u16 family;   // AF_INET, AF_INET6, etc.
    __s16 type;     // SOCK_STREAM, SOCK_DGRAM, etc.
    __u16 protocol; // IPPROTO_TCP, IPPROTO_UDP, etc.
    __u32 is_send;  // 1 if send event, 0 if receive event
    u8 comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
    __type(value, struct event);
} events SEC(".maps");

static __always_inline void
fill_common_event_fields(struct event *event, struct socket *sock, long ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid & 0xFFFFFFFF; // PID (thread ID)
    event->tgid = pid_tgid >> 32;       // TGID (process ID)
    event->bytes = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->family = 0;
    event->type = 0;
    event->protocol = 0;

    if (sock) {
        BPF_CORE_READ_INTO(&event->type, sock, type);
        if (sock->sk) {
            BPF_CORE_READ_INTO(&event->family, sock->sk, __sk_common.skc_family);
            BPF_CORE_READ_INTO(&event->protocol, sock->sk, sk_protocol);
        }
    }
}

SEC("fexit/sock_sendmsg")
int BPF_PROG2(sock_sendmsg_fexit, struct socket*, sock, struct msghdr*, msg, int, ret) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    fill_common_event_fields(e, sock, ret);
    e->is_send = 1; // mark as a send event

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fexit/sock_recvmsg")
int BPF_PROG2(sock_recvmsg_fexit, struct socket*, sock, struct msghdr*, msg, int, flags, int, ret) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    fill_common_event_fields(e, sock, ret);
    e->is_send = 0; // mark as a receive event

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
