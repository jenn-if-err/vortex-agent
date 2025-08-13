//go:build ignore

#include "base.c"

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
    int trace_all = COMM_NO_TRACE_ALL;
    if (should_trace_comm(&trace_all) == VORTEX_NO_TRACE)
        return BPF_OK;

    if (trace_all == COMM_TRACE_ALL)
        return BPF_OK;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_printk("sysfentry/sock_sendmsg: pid_tgid=%llu", pid_tgid);

    return BPF_OK;
}
*/

/* https://elixir.bootlin.com/linux/v6.1.146/source/include/linux/net.h#L262 */
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

static __always_inline void set_SSL_callstack_socket_info(struct ssl_callstack_k *key, struct sock *sk) {
    struct ssl_callstack_v *cs_val;
    cs_val = bpf_map_lookup_elem(&ssl_callstack, key);
    if (!cs_val)
        return;

    BPF_CORE_READ_INTO(&cs_val->saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&cs_val->sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&cs_val->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&cs_val->dport, sk, __sk_common.skc_dport);
}

/* https://elixir.bootlin.com/linux/v6.1.146/source/include/net/tcp.h#L332 */
SEC("fexit/tcp_sendmsg")
int BPF_PROG2(tcp_sendmsg_fexit, struct sock *, sk, struct msghdr *, msg, size_t, size, int, ret) {
    int trace_all = COMM_NO_TRACE_ALL;
    if (should_trace_comm(&trace_all) == VORTEX_NO_TRACE)
        return BPF_OK;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k cs_key = {.pid_tgid = pid_tgid, .rw_flag = F_WRITE};
    set_SSL_callstack_socket_info(&cs_key, sk);

    return BPF_OK;
}

/* https://elixir.bootlin.com/linux/v6.1.146/source/include/net/tcp.h#L425 */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret) {
    if (ret <= 0)
        return BPF_OK;

    int trace_all = COMM_NO_TRACE_ALL;
    if (should_trace_comm(&trace_all) == VORTEX_NO_TRACE)
        return BPF_OK;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k cs_key = {.pid_tgid = pid_tgid, .rw_flag = F_READ};
    set_SSL_callstack_socket_info(&cs_key, sk);

    return BPF_OK;
}

/* https://elixir.bootlin.com/linux/v6.1.146/source/include/net/udp.h#L271 */
SEC("fexit/udp_sendmsg")
int BPF_PROG2(udp_sendmsg_fexit, struct sock *, sk, struct msghdr *, msg, size_t, len, int, ret) {
    return BPF_OK; /* NOTE: disable for now */

    int trace_all = COMM_NO_TRACE_ALL;
    if (should_trace_comm(&trace_all) == VORTEX_NO_TRACE)
        return BPF_OK;

    return BPF_OK;
}

/* https://elixir.bootlin.com/linux/v6.1.146/source/net/ipv4/udp_impl.h#L20 */
SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recvmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret) {
    return BPF_OK; /* NOTE: disable for now */

    if (ret <= 0)
        return BPF_OK;

    int trace_all = COMM_NO_TRACE_ALL;
    if (should_trace_comm(&trace_all) == VORTEX_NO_TRACE)
        return BPF_OK;

    return BPF_OK;
}

/*
 * /sys/kernel/tracing/events/syscalls/sys_enter_connect/format
 *
 * int fd
 * struct sockaddr __user *uaddr
 * int addrlen
 */
SEC("tp/syscalls/sys_enter_connect")
int sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    int trace_all = COMM_NO_TRACE_ALL;
    if (should_trace_comm(&trace_all) == VORTEX_NO_TRACE)
        return BPF_OK;

    if (trace_all == COMM_TRACE_ALL)
        return BPF_OK;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = ctx->args[0];
    void *usr_addr = (void *)ctx->args[1];
    int usr_addrlen = (int)ctx->args[2];
    if (usr_addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in sa_in;
        if (bpf_probe_read_user(&sa_in, sizeof(sa_in), usr_addr) < 0)
            return BPF_OK;

        if (sa_in.sin_family != AF_INET)
            return BPF_OK;

        struct fd_connect_v val = {
            .fd = fd,
            .saddr = 0,
            .sport = 0,
            .daddr = sa_in.sin_addr.s_addr,
            .dport = sa_in.sin_port,
        };

        bpf_map_update_elem(&fd_connect, &pid_tgid, &val, BPF_ANY);

        bpf_printk("sys_enter_connect: pid_tgid=%llu, fd=%d, dst=%x:%u", pid_tgid, fd, sa_in.sin_addr.s_addr,
                   bpf_ntohs(sa_in.sin_port));

        return BPF_OK;
    }

    if (usr_addrlen >= sizeof(struct sockaddr_in6)) {
        /* TODO: IPv6 */
    }

    return BPF_OK;
}

const char *tcp_state_to_string(int state) {
    switch (state) {
    case TCP_ESTABLISHED:
        return "ESTABLISHED";
    case TCP_SYN_SENT:
        return "SYN_SENT";
    case TCP_SYN_RECV:
        return "SYN_RECV";
    case TCP_FIN_WAIT1:
        return "FIN_WAIT1";
    case TCP_FIN_WAIT2:
        return "FIN_WAIT2";
    case TCP_TIME_WAIT:
        return "TIME_WAIT";
    case TCP_CLOSE:
        return "CLOSE";
    case TCP_CLOSE_WAIT:
        return "CLOSE_WAIT";
    case TCP_LAST_ACK:
        return "LAST_ACK";
    case TCP_LISTEN:
        return "LISTEN";
    case TCP_CLOSING:
        return "CLOSING";
    case TCP_NEW_SYN_RECV:
        return "TCP_NEW_SYN_RECV";
    default:
        return "UNKNOWN";
    }
}

/*
 * /sys/kernel/tracing/events/sock/inet_sock_set_state/format
 *
 * { 1, "TCP_ESTABLISHED" }
 * { 2, "TCP_SYN_SENT" }
 * { 3, "TCP_SYN_RECV" }
 * { 4, "TCP_FIN_WAIT1" }
 * { 5, "TCP_FIN_WAIT2" }
 * { 6, "TCP_TIME_WAIT" }
 * { 7, "TCP_CLOSE" }
 * { 8, "TCP_CLOSE_WAIT" }
 * { 9, "TCP_LAST_ACK" }
 * { 10, "TCP_LISTEN" }
 * { 11, "TCP_CLOSING" }
 * { 12, "TCP_NEW_SYN_RECV" }
 */
SEC("tp/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    int trace_all = COMM_NO_TRACE_ALL;
    if (should_trace_comm(&trace_all) == VORTEX_NO_TRACE)
        return BPF_OK;

    if (trace_all == COMM_TRACE_ALL)
        return BPF_OK;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)BPF_CORE_READ(ctx, skaddr);
    int oldstate = (int)BPF_CORE_READ(ctx, oldstate);
    int newstate = (int)BPF_CORE_READ(ctx, newstate);
    __be32 saddr = 0, daddr = 0;
    __u16 sport = 0;
    __be16 dport = 0;
    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

    struct fd_connect_v *fdc_v;
    fdc_v = bpf_map_lookup_elem(&fd_connect, &pid_tgid);
    if (fdc_v)
        if (oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT)
            fdc_v->sk = (uintptr_t)sk;

    if (oldstate == TCP_ESTABLISHED)
        bpf_map_delete_elem(&fd_connect, &pid_tgid);

    bpf_printk("inet_sock_set_state: pid_tgid=%llu, old=%s, new=%s, src=%x:%u, dst=%x:%u", pid_tgid,
               tcp_state_to_string(oldstate), tcp_state_to_string(newstate), saddr, sport, daddr, bpf_ntohs(dport));

    return BPF_OK;
}

#endif /* __BPF_VORTEX_SOCKET_C */
