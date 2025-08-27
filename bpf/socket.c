//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_SOCKET_C
#define __BPF_VORTEX_SOCKET_C

static __always_inline void set_send_recv_msg_sk_info(struct event *event, struct sock *sk) {
    BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event->sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
    event->dport = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __always_inline void set_ssl_callstack_socket_info(struct ssl_callstack_k *key, struct sock *sk) {
    struct ssl_callstack_v *val;
    val = bpf_map_lookup_elem(&ssl_callstack, key);
    if (!val)
        return;

    BPF_CORE_READ_INTO(&val->saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&val->sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&val->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&val->dport, sk, __sk_common.skc_dport);
}

/*
 * fentry/fexit hooks can be found in:
 * /sys/kernel/tracing/available_filter_functions
 *
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/tcp.h#L332
 */
SEC("fexit/tcp_sendmsg")
int BPF_PROG2(tcp_sendmsg_fexit, struct sock *, sk, struct msghdr *, msg, size_t, size, int, ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_WRITE};
    set_ssl_callstack_socket_info(&key, sk);

    return BPF_OK;
}

/*
 * fentry/fexit hooks can be found in:
 * /sys/kernel/tracing/available_filter_functions
 *
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/tcp.h#L425
 */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret) {
    if (ret <= 0)
        return BPF_OK;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_READ};
    set_ssl_callstack_socket_info(&key, sk);

    return BPF_OK;
}

/*
 * fentry/fexit hooks can be found in:
 * /sys/kernel/tracing/available_filter_functions
 *
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/udp.h#L271
 */
/*
SEC("fexit/udp_sendmsg")
int BPF_PROG2(udp_sendmsg_fexit, struct sock *, sk, struct msghdr *, msg, size_t, len, int, ret) {
    int trace_all = COMM_NO_TRACE_ALL;
    if (should_trace_comm(&trace_all) == VORTEX_NO_TRACE)
        return BPF_OK;

    return BPF_OK;
}
*/

/*
 * fentry/fexit hooks can be found in:
 * /sys/kernel/tracing/available_filter_functions
 *
 * https://elixir.bootlin.com/linux/v6.1.146/source/net/ipv4/udp_impl.h#L20
 */
/*
SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recvmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret) {
    if (ret <= 0)
        return BPF_OK;

    int trace_all = COMM_NO_TRACE_ALL;
    if (should_trace_comm(&trace_all) == VORTEX_NO_TRACE)
        return BPF_OK;

    return BPF_OK;
}
*/

/*
 * /sys/kernel/tracing/events/syscalls/sys_enter_connect/format
 *
 *   int fd;
 *   struct sockaddr __user *uaddr;
 *   int addrlen;
 */
SEC("tp/syscalls/sys_enter_connect")
int sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    int fd = (int)BPF_CORE_READ(ctx, args[0]);
    void *usr_addr = (void *)BPF_CORE_READ(ctx, args[1]);
    int usr_addrlen = (int)BPF_CORE_READ(ctx, args[2]);
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

        __u64 pid_tgid = bpf_get_current_pid_tgid();
        bpf_map_update_elem(&fd_connect, &pid_tgid, &val, BPF_ANY);

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
 *   const void *skaddr;
 *   int oldstate;
 *   int newstate;
 *   __u16 sport;
 *   __u16 dport;
 *   __u16 family;
 *   __u16 protocol;
 *   __u8 saddr[4];
 *   __u8 daddr[4];
 *   __u8 saddr_v6[16];
 *   __u8 daddr_v6[16];
 */
SEC("tp/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    __u16 family = (int)BPF_CORE_READ(ctx, family);
    if (family != AF_INET)
        return BPF_OK;

    struct sock *sk = (struct sock *)BPF_CORE_READ(ctx, skaddr);
    int oldstate = (int)BPF_CORE_READ(ctx, oldstate);
    int newstate = (int)BPF_CORE_READ(ctx, newstate);

    struct fd_connect_v *val;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    val = bpf_map_lookup_elem(&fd_connect, &pid_tgid);
    if (val)
        if (val->fd > 2 && oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT)
            val->sk = (uintptr_t)sk;

    if (oldstate == TCP_ESTABLISHED && newstate != TCP_ESTABLISHED)
        bpf_map_delete_elem(&fd_connect, &pid_tgid);

    return BPF_OK;
}

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct bpf_sock *sk = BPF_CORE_READ(ctx, sk);
    bpf_map_update_elem(&sk_to_pid_tgid, &sk, &pid_tgid, BPF_ANY);
    return CG_SOCK_ALLOW;
}

SEC("cgroup/sock_release")
int cgroup_sock_release(struct bpf_sock *ctx) {
    bpf_map_delete_elem(&sk_to_pid_tgid, &ctx);
    return CG_SOCK_ALLOW;
}

#endif /* __BPF_VORTEX_SOCKET_C */
