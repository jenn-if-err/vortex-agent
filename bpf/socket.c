//go:build ignore

#include "common.c"
#include "maps.c"

#ifndef __BPF_VORTEX_SOCKET_C
#define __BPF_VORTEX_SOCKET_C

/*
static __always_inline int set_sock_sendrecv_sk_info(struct event *event, struct socket *sock, long ret) {
    event->bytes = ret;
    int ret_val = 0;

    __s16 sk_type = 0;
    BPF_CORE_READ_INTO(&sk_type, sock, type);
    if (!(sk_type == SOCK_STREAM || sk_type == SOCK_DGRAM))
        ret_val = -1;

    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sock->sk, __sk_common.skc_family);

    if (!(family == AF_INET || family == AF_INET6))
        ret_val = -1;

    BPF_CORE_READ_INTO(&event->saddr, sock->sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event->sport, sock->sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&event->daddr, sock->sk, __sk_common.skc_daddr);
    __be16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sock->sk, __sk_common.skc_dport);
    event->dport = bpf_htons(dport);

    return ret_val;
}
*/

/*
 * fentry/fexit hooks can be found in:
 * /sys/kernel/tracing/available_filter_functions
 *
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/linux/net.h#L261
 */
/*
SEC("fentry/sock_sendmsg")
int BPF_PROG2(sock_sendmsg_fentry, struct socket *, sock, struct msghdr *, msg) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->type = TYPE_FENTRY_SOCK_SENDMSG;
    set_proc_info(e);

    if (should_trace(e->tgid) == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    int discard = set_sock_sendrecv_sk_info(e, sock, 1);
    if (discard < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
*/

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/linux/net.h#L262
 */
/*
SEC("fexit/sock_recvmsg")
int BPF_PROG2(sock_recvmsg_fexit, struct socket *, sock, struct msghdr *, msg, int, flags, int, ret) {
    if (ret <= 0)
        return 0;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->type = TYPE_FEXIT_SOCK_RECVMSG;
    set_proc_info(e);

    if (should_trace(e->tgid) == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    int discard = set_sock_sendrecv_sk_info(e, sock, ret);
    if (discard < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
*/

/*
 * Set the socket information in the event structure for sendmsg/recvmsg.
 * This is used for both TCP and UDP send/recv messages.
 */
static __always_inline void set_send_recv_msg_sk_info(struct event *event, struct sock *sk) {
    BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event->sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
    __be16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    event->dport = bpf_htons(dport);
}

static __always_inline void assoc_SSL_write_socket_info(__u64 pid_tgid, struct sock *sk) {
    struct ssl_callstack_ctx *ctx;
    ctx = bpf_map_lookup_elem(&ssl_write_callstack, &pid_tgid);
    if (!ctx)
        return;

    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return;

    evt->type = TYPE_REPORT_WRITE_SOCKET_INFO;
    set_proc_info(evt);
    set_send_recv_msg_sk_info(evt, sk);
    bpf_ringbuf_submit(evt, 0);
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/tcp.h#L332
 */
SEC("fexit/tcp_sendmsg")
int BPF_PROG2(tcp_sendmsg_fexit, struct sock *, sk, struct msghdr *, msg, size_t, size, int, ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Sends another ringbuf event. */
    assoc_SSL_write_socket_info(pid_tgid, sk);

    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return 0;

    set_proc_info(evt);

    if (should_trace(evt->tgid) == VORTEX_NO_TRACE) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    evt->type = TYPE_FEXIT_TCP_SENDMSG;
    evt->total_len = size;
    set_send_recv_msg_sk_info(evt, sk);
    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

static __always_inline void assoc_SSL_read_socket_info(__u64 pid_tgid, struct sock *sk) {
    struct ssl_callstack_ctx *ctx;
    ctx = bpf_map_lookup_elem(&ssl_read_callstack, &pid_tgid);
    if (!ctx)
        return;

    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return;

    evt->type = TYPE_REPORT_READ_SOCKET_INFO;
    set_proc_info(evt);
    set_send_recv_msg_sk_info(evt, sk);
    bpf_ringbuf_submit(evt, 0);
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/tcp.h#L425
 */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret) {
    if (ret <= 0)
        return BPF_OK;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Sends another ringbuf event. */
    assoc_SSL_read_socket_info(pid_tgid, sk);

    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return BPF_OK;

    set_proc_info(evt);

    if (should_trace(evt->tgid) == VORTEX_NO_TRACE) {
        bpf_ringbuf_discard(evt, 0);
        return BPF_OK;
    }

    evt->type = TYPE_FEXIT_TCP_RECVMSG;
    evt->total_len = ret;
    set_send_recv_msg_sk_info(evt, sk);
    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/udp.h#L271
 */
SEC("fexit/udp_sendmsg")
int BPF_PROG2(udp_sendmsg_fexit, struct sock *, sk, struct msghdr *, msg, size_t, len, int, ret) {
    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return BPF_OK;

    set_proc_info(evt);

    if (should_trace(evt->tgid) == VORTEX_NO_TRACE) {
        bpf_ringbuf_discard(evt, 0);
        return BPF_OK;
    }

    evt->type = TYPE_FEXIT_UDP_SENDMSG;
    evt->total_len = len;
    set_send_recv_msg_sk_info(evt, sk);
    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/net/ipv4/udp_impl.h#L20
 */
SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recvmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret) {
    if (ret <= 0)
        return BPF_OK;

    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return BPF_OK;

    evt->type = TYPE_FEXIT_UDP_RECVMSG;
    evt->total_len = ret;
    set_proc_info(evt);

    if (should_trace(evt->tgid) == VORTEX_NO_TRACE) {
        bpf_ringbuf_discard(evt, 0);
        return BPF_OK;
    }

    set_send_recv_msg_sk_info(evt, sk);
    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

/*
 * /sys/kernel/tracing/events/syscalls/sys_enter_sendto/format
 *
 *  int fd
 *  void *buff
 *  size_t len
 *  unsigned int flags
 *  struct sockaddr *addr
 *  int addr_len
 */
/*
SEC("tp/syscalls/sys_enter_sendto")
int handle_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    size_t len = BPF_CORE_READ(ctx, args[2]);
    if (len == 0)
        return 0;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->type = TYPE_TP_SYS_ENTER_SENDTO;
    e->bytes = len;
    set_proc_info(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
*/

#endif /* __BPF_VORTEX_SOCKET_C */
