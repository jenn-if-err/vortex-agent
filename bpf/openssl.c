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
    __u32 *cursor;
    char **buf_ptr;
    int *len;
    int orig_len;
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

/* bpf_loop callback: send data to userspace in chunks of EVENT_BUF_LEN bytes. */
static int do_loop_send_ssl_payload(u64 index, struct loop_data *data) {
    struct event *event;
    event = rb_events_reserve_with_stats();
    if (!event)
        return BPF_END_LOOP;

    __u32 len = (__u32)*data->len > EVENT_BUF_LEN ? EVENT_BUF_LEN : (__u32)*data->len;
    set_proc_info(event);
    event->type = data->type;
    event->total_len = data->orig_len;
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
        bpf_ringbuf_discard(event, 0);

    *data->buf_ptr = *data->buf_ptr + len;
    int sub = *data->len <= EVENT_BUF_LEN ? *data->len : EVENT_BUF_LEN;
    *data->len = *data->len - sub;
    if (*data->len <= 0)
        return BPF_END_LOOP;

    return BPF_CONTINUE_LOOP;
}

/* Shared with uprobe/SSL_write and uprobe/SSL_write_ex. */
static __always_inline int do_uprobe_ssl_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (should_sni_trace(pid_tgid) == VORTEX_NO_TRACE)
        return BPF_OK;

    struct ssl_callstack_v val;
    val.buf = (uintptr_t)PT_REGS_PARM2(ctx);
    val.len = (int)PT_REGS_PARM3(ctx);
    val.saddr = 0;
    val.daddr = 0;
    val.sport = 0;
    val.dport = 0;

    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_WRITE};
    bpf_map_update_elem(&ssl_callstack, &key, &val, BPF_ANY);

    return BPF_OK;
}

/*
 * bpf_loop callback: parse HTTP/2 frames and attempt to extract the data frame.
 * Reference: https://httpwg.org/specs/rfc7540.html
 */
static int loop_h2_parse(u64 index, struct loop_data *data) {
    if (*data->cursor + H2_FRAME_HEADER_SIZE > data->orig_len)
        return BPF_END_LOOP;

    /* Read the 9-byte frame header. */
    __u8 hdr[H2_FRAME_HEADER_SIZE];
    if (bpf_probe_read_user(&hdr, sizeof(hdr), *data->buf_ptr + *data->cursor) != 0)
        return BPF_END_LOOP;

    __u32 frame_len = ((__u32)hdr[0] << 16) | ((__u32)hdr[1] << 8) | (__u32)hdr[2];
    __u8 frame_type = hdr[3], flags = hdr[4];

    /*
    if (frame_type <= 0x9) {
        __u32 stream_id = ((__u32)hdr[5] << 24) | ((__u32)hdr[6] << 16) | ((__u32)hdr[7] << 8) | ((__u32)hdr[8]);
        stream_id = stream_id & 0x7FFFFFFF;
        bpf_printk("[%d] H2 frame: type=0x%x frame_len=%u, stream_id=%u, flags=0x%x", index, frame_type, frame_len,
                   stream_id, flags);
    }
    */

    if (frame_type <= 0x9 && frame_type == H2_FRAME_TYPE_DATA && frame_len > 0) {
        __u32 payload_offset = *data->cursor + H2_FRAME_HEADER_SIZE;
        __u32 data_len = frame_len;

        if (flags & H2_FLAG_PADDED) {
            __u8 pad_len = 0;
            if (bpf_probe_read_user(&pad_len, 1, *data->buf_ptr + payload_offset) != 0)
                return BPF_END_LOOP;

            payload_offset += 1;
            if (data_len < pad_len + 1)
                return BPF_END_LOOP;

            data_len -= (pad_len + 1);
        }

        if (payload_offset + data_len > data->orig_len)
            return BPF_END_LOOP;

        char *buf = *data->buf_ptr + payload_offset;
        int len = (int)data_len;

        struct loop_data d = {
            .type = data->type,
            .buf_ptr = &buf,
            .len = &len,
            .orig_len = data->orig_len,
            .saddr = data->saddr,
            .daddr = data->daddr,
            .sport = data->sport,
            .dport = data->dport,
        };

        bpf_loop(4096, do_loop_send_ssl_payload, &d, 0);
    }

    *data->cursor += H2_FRAME_HEADER_SIZE + frame_len;
    return BPF_CONTINUE_LOOP;
}

/* Shared with uretprobe/SSL_write and uretprobe/SSL_write_ex. */
static __always_inline int do_uretprobe_ssl_write(struct pt_regs *ctx, int written) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_WRITE};

    if (written <= 0)
        goto cleanup_and_exit;

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
    int num = written;

    struct h2_k h2_key = {
        .pid_tgid = pid_tgid,
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
    };

    /* Preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" */
    char preface[3];
    bpf_probe_read_user(preface, sizeof(preface), buf);
    if (preface[0] == 'P' && preface[1] == 'R' && preface[2] == 'I') {
        __u8 val = 1;
        bpf_map_update_elem(&is_h2, &h2_key, &val, BPF_ANY);
        goto cleanup_and_exit;
    }

    struct loop_data data = {
        .type = TYPE_URETPROBE_SSL_WRITE,
        .buf_ptr = &buf,
        .len = &num,
        .orig_len = written,
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
    };

    __u8 *unused = bpf_map_lookup_elem(&is_h2, &h2_key);
    if (!unused) {
        bpf_loop(4096, do_loop_send_ssl_payload, &data, 0);
        goto cleanup_and_exit;
    }

    __u32 cursor = 0;
    data.cursor = &cursor;
    bpf_loop(4096, loop_h2_parse, &data, 0);

cleanup_and_exit:
    bpf_map_delete_elem(&ssl_callstack, &key);
    return BPF_OK;
}

/*
 * Synopsis:
 * int SSL_write(SSL *s, const void *buf, int num);
 */
SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx) { return do_uprobe_ssl_write(ctx); }

/*
 * Synopsis:
 * int SSL_write(SSL *s, const void *buf, int num);
 */
SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx) { return do_uretprobe_ssl_write(ctx, (int)PT_REGS_RC(ctx)); }

/*
 * Synopsis:
 * int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
 */
SEC("uprobe/SSL_write_ex")
int uprobe_ssl_write_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 written = (__u64)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&ssl_write_ex_p4, &pid_tgid, &written, BPF_ANY);
    return do_uprobe_ssl_write(ctx);
}

/*
 * Synopsis:
 * int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
 */
SEC("uretprobe/SSL_write_ex")
int uretprobe_ssl_write_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *written = bpf_map_lookup_elem(&ssl_write_ex_p4, &pid_tgid);
    if (!written)
        return BPF_OK;

    size_t len = 0;
    bpf_probe_read_user(&len, sizeof(len), (void *)*written);
    bpf_map_delete_elem(&ssl_write_ex_p4, &pid_tgid);
    return do_uretprobe_ssl_write(ctx, (int)len);
}

/* Shared with uprobe/SSL_read and uprobe/SSL_read_ex. */
static __always_inline int do_uprobe_ssl_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (should_sni_trace(pid_tgid) == VORTEX_NO_TRACE)
        return BPF_OK;

    struct ssl_callstack_v val;
    val.buf = (uintptr_t)PT_REGS_PARM2(ctx);
    val.len = (int)PT_REGS_PARM3(ctx);
    val.saddr = 0;
    val.daddr = 0;
    val.sport = 0;
    val.dport = 0;

    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_READ};
    bpf_map_update_elem(&ssl_callstack, &key, &val, BPF_ANY);

    return BPF_OK;
}

/* Shared with uretprobe/SSL_read and uretprobe/SSL_read_ex. */
static __always_inline int do_uretprobe_ssl_read(struct pt_regs *ctx, int read) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_READ};

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup_and_exit;

    if (read <= 0)
        goto cleanup_and_exit;

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

    struct loop_data data = {
        .type = TYPE_URETPROBE_SSL_READ,
        .buf_ptr = &buf,
        .len = &read,
        .orig_len = read,
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
    };

    if (bpf_loop(4096, do_loop_send_ssl_payload, &data, 0) < 1)
        goto cleanup_and_exit;

    /* Signal previous chunked stream's end. */
    struct event *event;
    event = rb_events_reserve_with_stats();
    if (!event)
        goto cleanup_and_exit;

    event->type = TYPE_URETPROBE_SSL_READ;
    set_proc_info(event);
    event->total_len = read;
    event->chunk_len = -1;
    event->chunk_idx = CHUNKED_END_IDX;
    event->saddr = saddr;
    event->sport = sport;
    event->daddr = daddr;
    event->dport = bpf_ntohs(dport);
    __builtin_memset(event->buf, 0, EVENT_BUF_LEN);
    rb_events_submit_with_stats(event, 0);

cleanup_and_exit:
    bpf_map_delete_elem(&ssl_callstack, &key);
    return BPF_OK;
}

/*
 * Synopsis:
 * int SSL_read(SSL *s, void *buf, int num);
 */
SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx) { return do_uprobe_ssl_read(ctx); }

/*
 * Synopsis:
 * int SSL_read(SSL *s, void *buf, int num);
 */
SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx) { return do_uretprobe_ssl_read(ctx, (int)PT_REGS_RC(ctx)); }

/*
 * Synopsis:
 * int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *read);
 */
SEC("uprobe/SSL_read_ex")
int uprobe_ssl_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 read = (__u64)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&ssl_read_ex_p4, &pid_tgid, &read, BPF_ANY);
    return do_uprobe_ssl_read(ctx);
}

/*
 * Synopsis:
 * int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *read);
 */
SEC("uretprobe/SSL_read_ex")
int uretprobe_ssl_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *read = bpf_map_lookup_elem(&ssl_read_ex_p4, &pid_tgid);
    if (!read)
        return BPF_OK;

    size_t len = 0;
    bpf_probe_read_user(&len, sizeof(len), (void *)*read);
    bpf_map_delete_elem(&ssl_read_ex_p4, &pid_tgid);
    return do_uretprobe_ssl_read(ctx, (int)len);
}

#endif /* __BPF_VORTEX_OPENSSL_C */
