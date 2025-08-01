//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"

#define AF_INET  2
#define AF_INET6 10

#define TYPE_FENTRY_SOCK_SENDMSG 1
#define TYPE_FEXIT_SOCK_RECVMSG  2
#define TYPE_FEXIT_TCP_SENDMSG   3
#define TYPE_FEXIT_TCP_RECVMSG   4
#define TYPE_FEXIT_UDP_SENDMSG   5
#define TYPE_FEXIT_UDP_RECVMSG   6
#define TYPE_TP_SYS_ENTER_SENDTO 7
#define TYPE_UPROBE_SSL_WRITE    8
#define TYPE_URETPROBE_SSL_WRITE 9
#define TYPE_UPROBE_SSL_READ     10
#define TYPE_URETPROBE_SSL_READ  11

#define BUF_LEN 256

#define TGID_ENABLE_ALL 0xFFFFFFFF
#define CHUNKED_END_IDX 0xFFFFFFFF

struct event {
    __u8 comm[TASK_COMM_LEN]; // bin; for debugging
    __u8 buf[BUF_LEN];
    __s64 bytes;
    __u32 chunk_idx;
    __u32 type;
    __u32 tgid;
    __u32 pid;
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
    __type(value, struct event);
} events SEC(".maps");

/*
 * Map to control which TGIDs are traced. A key of TGID_ENABLE_ALL means all
 * TGIDs are traced. Otherwise, only trace whatever's in the map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} tgids_to_trace SEC(".maps");

/*
 * Map to store the user buffer pointer for SSL_read. The key is the PID/TGID,
 * and the value is a pointer to the user buffer.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, char *);
} ssl_read_map SEC(".maps");

/*
 * Map to track SSL handshakes. The key is the PID/TGID, and the value is a
 * simple byte (not used, just to indicate that the handshake is in progress).
 * This map is used to determine if we should trace SSL_write/SSL_read.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} ssl_handshakes SEC(".maps");

static __always_inline void set_proc_info(struct event *event) {
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->tgid = pid_tgid >> 32;
}

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

static __always_inline int should_trace(__u32 tgid) {
    __u32 all = TGID_ENABLE_ALL;
    if (bpf_map_lookup_elem(&tgids_to_trace, &all) == NULL)
        if (bpf_map_lookup_elem(&tgids_to_trace, &tgid) == NULL)
            return 0;

    return 1;
}

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
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->type = TYPE_FEXIT_TCP_SENDMSG;
    e->bytes = size;
    set_proc_info(e);

    if (should_trace(e->tgid) == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    set_sendmsg_sk_info(e, sk);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/tcp.h#L425
 */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret) {
    if (ret <= 0)
        return 0;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->type = TYPE_FEXIT_TCP_RECVMSG;
    e->bytes = ret;
    set_proc_info(e);

    if (should_trace(e->tgid) == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    set_sendmsg_sk_info(e, sk);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/include/net/udp.h#L271
 */
SEC("fexit/udp_sendmsg")
int BPF_PROG2(udp_sendmsg_fexit, struct sock *, sk, struct msghdr *, msg, size_t, len, int, ret) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->type = TYPE_FEXIT_UDP_SENDMSG;
    e->bytes = len;
    set_proc_info(e);

    if (should_trace(e->tgid) == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    set_sendmsg_sk_info(e, sk);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

/*
 * https://elixir.bootlin.com/linux/v6.1.146/source/net/ipv4/udp_impl.h#L20
 */
SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recvmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int ret) {
    if (ret <= 0)
        return 0;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->type = TYPE_FEXIT_UDP_RECVMSG;
    e->bytes = ret;
    set_proc_info(e);

    if (should_trace(e->tgid) == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    set_sendmsg_sk_info(e, sk);
    bpf_ringbuf_submit(e, 0);

    return 0;
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

/*
 * int SSL_do_handshake(SSL *ssl);
 */
SEC("uretprobe/SSL_do_handshake")
int uretprobe_SSL_do_handshake(struct pt_regs *ctx) {
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    __u8 enable = 1; /* no meaning */
    __u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_handshakes, &tgid, &enable, BPF_ANY);
    return 0;
}

struct loop_data {
    __u32 type;
    char **buf;
    int *len;
};

/*
 * Send data to user space in chunks of BUF_LEN bytes.
 */
static int do_SSL_loop(__u32 index, struct loop_data *data) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 1; /* end loop */

    __u32 len = (__u32)*data->len > BUF_LEN ? BUF_LEN : (__u32)*data->len;
    set_proc_info(e);
    e->type = data->type;
    e->bytes = len;
    e->chunk_idx = index;

    e->buf[0] = '\0';
    char *buf = *data->buf;
    if (bpf_probe_read_user(&e->buf, len, buf) == 0)
        bpf_ringbuf_submit(e, 0);
    else
        bpf_ringbuf_discard(e, 0); /* discard but still adjust values? */

    *data->buf = *data->buf + len; /* forward buffer pointer */

    int sub = *data->len <= BUF_LEN ? *data->len : BUF_LEN;
    *data->len = *data->len - sub;
    if (*data->len <= 0)
        return 1; /* end loop */

    return 0; /* continue loop */
}

/*
 * Methods for accessing container-based file systems for u[ret]probes.
 *
 * 1) Check /proc/pid/root/. Symbolic link to pid's root directory.
 *
 * 2) Check /proc/pid/mountinfo. There will be a lowerdir, upperdir, and
 *    workdir mounts. Replace upperdir's ---/diff/ to ---/merged/.
 */

/*
 * uprobe for SSL_write (called before encryption).
 * int SSL_write(SSL *s, const void *buf, int num);
 */
SEC("uprobe/SSL_write")
int uprobe_SSL_write(struct pt_regs *ctx) {
    __u64 tgid = bpf_get_current_pid_tgid();
    __u8 *enable = bpf_map_lookup_elem(&ssl_handshakes, &tgid);
    if (!enable)
        return 0;

    char *buf = (char *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    struct loop_data data = {
        .type = TYPE_UPROBE_SSL_WRITE,
        .buf = &buf,
        .len = &num,
    };

    /* Is BUF_LEN * 1000 enough? */
    bpf_loop(1000, do_SSL_loop, &data, 0);

    /* Signal previous chunked stream's end. */
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->type = TYPE_UPROBE_SSL_WRITE;
    set_proc_info(e);
    e->bytes = -1;
    e->chunk_idx = CHUNKED_END_IDX;
    e->buf[0] = '\0';
    bpf_ringbuf_submit(e, 0);

    return 0;
}

/*
 * uprobe for SSL_read (called after decryption).
 * int SSL_read(SSL *s, void *buf, int num);
 *
 * Store the pointer of the user buffer in a map,
 * so that we can retrieve it in the uretprobe.
 */
SEC("uprobe/SSL_read")
int uprobe_SSL_read(struct pt_regs *ctx) {
    __u64 tgid = bpf_get_current_pid_tgid();
    __u8 *enable = bpf_map_lookup_elem(&ssl_handshakes, &tgid);
    if (!enable)
        return 0;

    char *buf = (char *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_read_map, &tgid, &buf, BPF_ANY);
    return 0;
}

/*
 * uretprobe for SSL_read (called after decryption); can access return value.
 * int SSL_read(SSL *s, void *buf, int num);
 *
 * Retrieve the user buffer pointer from our map, read the data, and send to
 * our ring buffer (user space).
 */
SEC("uretprobe/SSL_read")
int uretprobe_SSL_read(struct pt_regs *ctx) {
    __u64 tgid = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_read_map, &tgid);
        return 0;
    }

    char **pbuf = bpf_map_lookup_elem(&ssl_read_map, &tgid);
    if (!pbuf)
        return 0;

    char *buf = (char *)*pbuf;

    struct loop_data data = {
        .type = TYPE_URETPROBE_SSL_READ,
        .buf = &buf,
        .len = &ret,
    };

    /* Is BUF_LEN * 1000 enough? */
    bpf_loop(1000, do_SSL_loop, &data, 0);
    bpf_map_delete_elem(&ssl_read_map, &tgid);

    /* Signal previous chunked stream's end. */
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->type = TYPE_URETPROBE_SSL_READ;
    set_proc_info(e);
    e->bytes = -1;
    e->chunk_idx = CHUNKED_END_IDX;
    e->buf[0] = '\0';
    bpf_ringbuf_submit(e, 0);

    return 0;
}

/*
 * Tracepoint for process exit; clean up our ssl_handshakes map.
 *
 * /sys/kernel/tracing/events/sched/sched_process_exit/format
 *
 *  char comm[16]
 *  pid_t pid
 *  int prio
 */
SEC("tp/sched/sched_process_exit")
int tp_sched_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ssl_handshakes, &tgid);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
