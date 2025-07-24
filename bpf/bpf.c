//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"

#define AF_INET  2
#define AF_INET6 10

#define TYPE_FENTRY_SOCK_SENDMSG 1
#define TYPE_FEXIT_SOCK_SENDMSG  2
#define TYPE_FEXIT_TCP_SENDMSG   3
#define TYPE_FEXIT_UDP_SENDMSG   4
#define TYPE_TP_SYS_ENTER_SENDTO 5

struct event {
    u8 comm[TASK_COMM_LEN]; // for debugging
    __u32 type;
    __u32 pid;
    __u32 tgid;
    __s64 bytes;
    __be32 saddr;
    __u16 sport;
    __be32 daddr;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
    __type(value, struct event);
} events SEC(".maps");

static __always_inline void set_proc_info(struct event *event) {
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid     = pid_tgid & 0xFFFFFFFF;
    event->tgid    = pid_tgid >> 32;
}

static __always_inline int set_sock_sendrecv_sk_info(struct event *event, struct socket *sock, long ret) {
    event->bytes = ret;
    int ret_val = 0;

    __s16 sk_type = 0;
    BPF_CORE_READ_INTO(&sk_type, sock, type);
    if (!(sk_type == SOCK_STREAM || sk_type == SOCK_DGRAM)) {
        ret_val = -1;
    }

    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sock->sk, __sk_common.skc_family);

    if (!(family == AF_INET || family == AF_INET6)) {
        ret_val = -1;
    }

    BPF_CORE_READ_INTO(&event->saddr, sock->sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event->sport, sock->sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&event->daddr, sock->sk, __sk_common.skc_daddr);
    __be16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sock->sk, __sk_common.skc_dport);
    event->dport = bpf_htons(dport);

    return ret_val;
}

/*
 * fentry/fexit hooks can be found in:
 * /sys/kernel/tracing/available_filter_functions
 *
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/linux/net.h#L261
 */
SEC("fentry/sock_sendmsg")
int BPF_PROG2(sock_sendmsg_fentry, struct socket *, sock, struct msghdr *, msg) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->type = TYPE_FENTRY_SOCK_SENDMSG;
    set_proc_info(e);

    int discard = set_sock_sendrecv_sk_info(e, sock, 1);
    if (discard < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/linux/net.h#L262
 */
SEC("fexit/sock_recvmsg")
int BPF_PROG2(sock_recvmsg_fexit, struct socket *, sock, struct msghdr *, msg, int, flags, int, ret) {
    if (ret <= 0) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->type = TYPE_FEXIT_SOCK_SENDMSG;
    set_proc_info(e);

    int discard = set_sock_sendrecv_sk_info(e, sock, ret);
    if (discard < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline void set_sendmsg_sk_info(struct event *event, struct sock *sk) {
    BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event->sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
    __be16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    event->dport = bpf_htons(dport);
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/tcp.h#L332
 */
SEC("fexit/tcp_sendmsg")
int BPF_PROG2(tcp_sendmsg_fexit, struct sock *, sk, struct msghdr *, msg, size_t, size, int, ret) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->type  = TYPE_FEXIT_TCP_SENDMSG;
    e->bytes = size;
    set_proc_info(e);
    set_sendmsg_sk_info(e, sk);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/udp.h#L271
 */
SEC("fexit/udp_sendmsg")
int BPF_PROG2(udp_sendmsg_fexit, struct sock *, sk, struct msghdr *, msg, size_t, len, int, ret) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->type  = TYPE_FEXIT_UDP_SENDMSG;
    e->bytes = len;
    set_proc_info(e);
    set_sendmsg_sk_info(e, sk);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * NOTE: Not registered/used in user-agent code, ref only.
 *
 * From '/sys/kernel/tracing/events/syscalls/sys_enter_sendto/format':
 *
 *  int fd
 *  void *buff
 *  size_t len
 *  unsigned int flags
 *  struct sockaddr *addr
 *  int addr_len
 */
SEC("tp/syscalls/sys_enter_sendto")
int handle_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    size_t len = BPF_CORE_READ(ctx, args[2]);
    if (len == 0) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->type  = TYPE_TP_SYS_ENTER_SENDTO;
    e->bytes = len;
    set_proc_info(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * uprobe for SSL_write (called before encryption)
 */
SEC("uprobe/SSL_write")
int BPF_UPROBE(uprobe_SSL_write, void *s, const void *buf, int num) {
    if (num <= 0) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->type  = 0;
    e->bytes = num > TASK_COMM_LEN ? TASK_COMM_LEN : num;
    set_proc_info(e);

    __u32 len = num > TASK_COMM_LEN ? TASK_COMM_LEN : num;
    if (bpf_probe_read_user(&e->comm, len, buf) != 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
