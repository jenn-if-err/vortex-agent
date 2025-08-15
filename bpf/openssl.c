//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_OPENSSL_C
#define __BPF_VORTEX_OPENSSL_C

static __always_inline void set_fdc_sock(__u64 pid_tgid, __be32 *saddr, __be32 *daddr, __u16 *sport, __be16 *dport) {
    struct fd_connect_v *val;
    val = bpf_map_lookup_elem(&fd_connect, &pid_tgid);
    if (!val)
        return;

    struct sock *sk = (struct sock *)val->sk;
    if (!sk)
        return;

    BPF_CORE_READ_INTO(saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(dport, sk, __sk_common.skc_dport);
}

struct loop_data {
    __u32 type;
    char **buf_ptr;
    int *len;
    int *orig_len;
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

/* bpf_loop callback: send data to userspace in chunks of EVENT_BUF_LEN bytes. */
static int do_loop_send_SSL_payload(u64 index, struct loop_data *data) {
    struct event *event;
    event = rb_events_reserve_with_stats();
    if (!event)
        return BPF_END_LOOP;

    __u32 len = (__u32)*data->len > EVENT_BUF_LEN ? EVENT_BUF_LEN : (__u32)*data->len;
    set_proc_info(event);
    event->type = data->type;
    event->total_len = *data->orig_len;
    event->chunk_len = len;
    event->chunk_idx = index;
    event->saddr = data->saddr;
    event->sport = data->sport;
    event->daddr = data->daddr;
    event->dport = bpf_ntohs(data->dport);
    __builtin_memset(event->buf, 0, EVENT_BUF_LEN);

    char *buf = *data->buf_ptr;
    if (bpf_probe_read_user(&event->buf, len, buf) == 0)
        rb_events_submit_with_stats(event, 0);
    else
        bpf_ringbuf_discard(event, 0); /* discard but still adjust values? */

    *data->buf_ptr = *data->buf_ptr + len; /* forward buffer pointer */

    int sub = *data->len <= EVENT_BUF_LEN ? *data->len : EVENT_BUF_LEN;
    *data->len = *data->len - sub;
    if (*data->len <= 0)
        return BPF_END_LOOP;

    return BPF_CONTINUE_LOOP;
}

/* Shared with uprobe/SSL_write and uprobe/SSL_write_ex. */
static __always_inline int do_uprobe_SSL_write(struct pt_regs *ctx) {
    struct ssl_callstack_v val;
    val.buf = (uintptr_t)PT_REGS_PARM2(ctx);
    val.len = (int)PT_REGS_PARM3(ctx);
    val.saddr = 0;
    val.daddr = 0;
    val.sport = 0;
    val.dport = 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_WRITE};
    bpf_map_update_elem(&ssl_callstack, &key, &val, BPF_ANY);

    /* bpf_printk("do_uprobe_SSL_write: pid_tgid=%llu, num=%d", pid_tgid, cs_val.len); */

    return BPF_OK;
}

/* Shared with uretprobe/SSL_write and uretprobe/SSL_write_ex. */
static __always_inline int do_uretprobe_SSL_write(struct pt_regs *ctx, int written) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_WRITE};

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_callstack, &key);
        return BPF_OK;
    }

    struct ssl_callstack_v *val;
    val = bpf_map_lookup_elem(&ssl_callstack, &key);
    if (!val)
        return BPF_OK;

    __be32 saddr = val->saddr;
    __be32 daddr = val->daddr;
    __u16 sport = val->sport;
    __be16 dport = val->dport;

    if (daddr == 0 || dport == 0)
        set_fdc_sock(pid_tgid, &saddr, &daddr, &sport, &dport);

    char *buf = (char *)val->buf;
    int num = val->len;
    int orig_num = num;

    struct loop_data data = {
        .type = TYPE_URETPROBE_SSL_WRITE,
        .buf_ptr = &buf,
        .len = &num,
        .orig_len = &orig_num,
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
    };

    /* Is EVENT_BUF_LEN * 1000 enough? */
    bpf_loop(1000, do_loop_send_SSL_payload, &data, 0);

    /* Signal previous chunked stream's end. */
    struct event *event;
    event = rb_events_reserve_with_stats();
    if (!event) {
        bpf_map_delete_elem(&ssl_callstack, &key);
        return BPF_OK;
    }

    // event->type = TYPE_UPROBE_SSL_WRITE; TEMP FIX
    event->type = TYPE_URETPROBE_SSL_WRITE;
    set_proc_info(event);
    event->total_len = orig_num;
    event->chunk_len = -1;
    event->chunk_idx = CHUNKED_END_IDX;
    event->saddr = saddr;
    event->sport = sport;
    event->daddr = daddr;
    event->dport = bpf_ntohs(dport);
    __builtin_memset(event->buf, 0, EVENT_BUF_LEN);
    rb_events_submit_with_stats(event, 0);

    bpf_map_delete_elem(&ssl_callstack, &key);
    return BPF_OK;
}

/*
 * Synopsis:
 * int SSL_write(SSL *s, const void *buf, int num);
 */
SEC("uprobe/SSL_write")
int uprobe_SSL_write(struct pt_regs *ctx) { return do_uprobe_SSL_write(ctx); }

/*
 * Synopsis:
 * int SSL_write(SSL *s, const void *buf, int num);
 */
SEC("uretprobe/SSL_write")
int uretprobe_SSL_write(struct pt_regs *ctx) { return do_uretprobe_SSL_write(ctx, (int)PT_REGS_RC(ctx)); }

/*
 * Synopsis:
 * int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
 */
SEC("uprobe/SSL_write_ex")
int uprobe_SSL_write_ex(struct pt_regs *ctx) { return do_uprobe_SSL_write(ctx); }

/*
 * Synopsis:
 * int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
 */
SEC("uretprobe/SSL_write_ex")
int uretprobe_SSL_write_ex(struct pt_regs *ctx) { return do_uretprobe_SSL_write(ctx, (int)PT_REGS_PARM3(ctx)); }

/* Shared with uprobe/SSL_read and uprobe/SSL_read_ex. */
static __always_inline int do_uprobe_SSL_read(struct pt_regs *ctx) {
    struct ssl_callstack_v val;
    val.buf = (uintptr_t)PT_REGS_PARM2(ctx);
    val.len = (int)PT_REGS_PARM3(ctx);
    val.saddr = 0;
    val.daddr = 0;
    val.sport = 0;
    val.dport = 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_READ};
    bpf_map_update_elem(&ssl_callstack, &key, &val, BPF_ANY);

    /* bpf_printk("do_uprobe_SSL_read: pid_tgid=%llu", pid_tgid); */

    return BPF_OK;
}

/* Shared with uretprobe/SSL_read and uretprobe/SSL_read_ex. */
static __always_inline int do_uretprobe_SSL_read(struct pt_regs *ctx, int read) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_READ};

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_callstack, &key);
        return BPF_OK;
    }

    if (read <= 0) {
        bpf_map_delete_elem(&ssl_callstack, &key);
        return BPF_OK;
    }

    struct ssl_callstack_v *val;
    val = bpf_map_lookup_elem(&ssl_callstack, &key);
    if (!val)
        return BPF_OK;

    __be32 saddr = val->saddr;
    __be32 daddr = val->daddr;
    __u16 sport = val->sport;
    __be16 dport = val->dport;

    if (daddr == 0 || dport == 0)
        set_fdc_sock(pid_tgid, &saddr, &daddr, &sport, &dport);

    char *buf = (char *)val->buf;
    int orig_len = read;

    struct loop_data data = {
        .type = TYPE_URETPROBE_SSL_READ,
        .buf_ptr = &buf,
        .len = &read,
        .orig_len = &orig_len,
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
    };

    /* Is EVENT_BUF_LEN * 1000 enough? */
    bpf_loop(1000, do_loop_send_SSL_payload, &data, 0);

    /* Signal previous chunked stream's end. */
    struct event *event;
    event = rb_events_reserve_with_stats();
    if (!event)
        return BPF_OK;

    event->type = TYPE_UPROBE_SSL_WRITE;
    set_proc_info(event);
    event->total_len = orig_len;
    event->chunk_len = -1;
    event->chunk_idx = CHUNKED_END_IDX;
    event->saddr = saddr;
    event->sport = sport;
    event->daddr = daddr;
    event->dport = bpf_ntohs(dport);
    __builtin_memset(event->buf, 0, EVENT_BUF_LEN);
    rb_events_submit_with_stats(event, 0);

    bpf_map_delete_elem(&ssl_callstack, &key);
    return BPF_OK;
}

/*
 * Synopsis:
 * int SSL_read(SSL *s, void *buf, int num);
 */
SEC("uprobe/SSL_read")
int uprobe_SSL_read(struct pt_regs *ctx) { return do_uprobe_SSL_read(ctx); }

/*
 * Synopsis:
 * int SSL_read(SSL *s, void *buf, int num);
 */
SEC("uretprobe/SSL_read")
int uretprobe_SSL_read(struct pt_regs *ctx) { return do_uretprobe_SSL_read(ctx, (int)PT_REGS_RC(ctx)); }

/*
 * Synopsis:
 * int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *read);
 */
SEC("uprobe/SSL_read_ex")
int uprobe_SSL_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 read = (__u64)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&ssl_read_ex_p4, &pid_tgid, &read, BPF_ANY);
    return do_uprobe_SSL_read(ctx);
}

/*
 * Synopsis:
 * int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *read);
 */
SEC("uretprobe/SSL_read_ex")
int uretprobe_SSL_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *read = bpf_map_lookup_elem(&ssl_read_ex_p4, &pid_tgid);
    if (!read)
        return BPF_OK;

    size_t len = 0;
    bpf_probe_read_user(&len, sizeof(len), (void *)*read);
    bpf_map_delete_elem(&ssl_read_ex_p4, &pid_tgid);
    return do_uretprobe_SSL_read(ctx, (int)len);
}

#endif /* __BPF_VORTEX_OPENSSL_C */
