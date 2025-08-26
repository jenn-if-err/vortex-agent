//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_OPENSSL_C
#define __BPF_VORTEX_OPENSSL_C

#define H2_FRAME_HEADER_SIZE 9
#define H2_FRAME_TYPE_DATA 0x0
#define H2_FLAG_PADDED 0x8

// Max data to capture from a single DATA frame
#define DATA_MAX_SIZE 1024

// Max frames to parse in a single SSL_write call to satisfy the verifier
#define MAX_FRAMES_PER_WRITE 3

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
        bpf_ringbuf_discard(event, 0);

    *data->buf_ptr = *data->buf_ptr + len;
    int sub = *data->len <= EVENT_BUF_LEN ? *data->len : EVENT_BUF_LEN;
    *data->len = *data->len - sub;
    if (*data->len <= 0)
        return BPF_END_LOOP;

    return BPF_CONTINUE_LOOP;
}

/* Shared with uprobe/SSL_write and uprobe/SSL_write_ex. */
static __always_inline int do_uprobe_SSL_write(struct pt_regs *ctx) {
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

struct h2_loop_data_t {
    __u32 *cursor;
    char *buf;
    int written;
};

/* Reference: https://httpwg.org/specs/rfc7540.html */
static int loop_h2_parse(u64 index, struct h2_loop_data_t *data) {
    if (*data->cursor + H2_FRAME_HEADER_SIZE > data->written)
        return BPF_END_LOOP;

    // Read the 9-byte frame header
    u8 h2_hdr[H2_FRAME_HEADER_SIZE];
    if (bpf_probe_read_user(&h2_hdr, sizeof(h2_hdr), data->buf + *data->cursor) != 0)
        return BPF_END_LOOP;

    __u32 frame_len = ((u32)h2_hdr[0] << 16) | ((u32)h2_hdr[1] << 8) | (u32)h2_hdr[2];
    __u8 frame_type = h2_hdr[3];
    __u8 flags = h2_hdr[4];
    if (frame_type <= 0x9) {
        u32 stream_id_raw = ((u32)h2_hdr[5] << 24) | ((u32)h2_hdr[6] << 16) | ((u32)h2_hdr[7] << 8) | ((u32)h2_hdr[8]);
        u32 stream_id = stream_id_raw & 0x7FFFFFFF;
        bpf_printk("[%d] H2 frame: type=0x%x frame_len=%u, stream_id=%u, flags=0x%x", index, frame_type, frame_len,
                   stream_id, flags);
    }

    if (frame_type <= 0x9 && frame_type == H2_FRAME_TYPE_DATA && frame_len > 0) {
        u32 payload_offset = *data->cursor + H2_FRAME_HEADER_SIZE;
        u32 data_len = frame_len;

        // Check if the PADDED flag is set
        if (flags & H2_FLAG_PADDED) {
            u8 pad_len = 0;
            if (bpf_probe_read_user(&pad_len, 1, data->buf + payload_offset) != 0)
                return BPF_END_LOOP;

            payload_offset += 1;        // The payload starts after the pad length byte
            if (data_len < pad_len + 1) // Sanity check
                return BPF_END_LOOP;

            data_len -= (pad_len + 1);
        }

        // Ensure we don't read past the end of the SSL_write buffer
        if (payload_offset + data_len > data->written)
            return BPF_END_LOOP;

        // Read the actual data
        u32 read_size = (data_len < DATA_MAX_SIZE) ? data_len : DATA_MAX_SIZE;
        bpf_printk("[%d] H2 DATA payload: data_len=%u, read_size=%u", index, data_len, read_size);
    }

    *data->cursor += H2_FRAME_HEADER_SIZE + frame_len;

    return BPF_CONTINUE_LOOP;
}

/* Shared with uretprobe/SSL_write and uretprobe/SSL_write_ex. */
static __always_inline int do_uretprobe_SSL_write(struct pt_regs *ctx, int written) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_callstack_k key = {.pid_tgid = pid_tgid, .rw_flag = F_WRITE};

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
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
    int num = val->len;
    int orig_num = num;

    /* Preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" */
    char preface[3];
    bpf_probe_read_user(preface, sizeof(preface), buf);
    if (preface[0] == 'P' && preface[1] == 'R' && preface[2] == 'I')
        goto cleanup_and_exit;

    __u32 cursor = 0;

    struct h2_loop_data_t h2_loop_data = {
        .cursor = &cursor,
        .buf = buf,
        .written = written,
    };

    bpf_loop(16, loop_h2_parse, &h2_loop_data, 0);

    bpf_printk("SSL_write: total written=%d, parsed bytes=%u", written, cursor);

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

    if (bpf_loop(4096, do_loop_send_SSL_payload, &data, 0) < 1)
        goto cleanup_and_exit;

    /* Signal previous chunked stream's end. */
    struct event *event;
    event = rb_events_reserve_with_stats();
    if (!event)
        goto cleanup_and_exit;

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

cleanup_and_exit:
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
static __always_inline int do_uretprobe_SSL_read(struct pt_regs *ctx, int read) {
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

    if (bpf_loop(4096, do_loop_send_SSL_payload, &data, 0) < 1)
        goto cleanup_and_exit;

    /* Signal previous chunked stream's end. */
    struct event *event;
    event = rb_events_reserve_with_stats();
    if (!event)
        goto cleanup_and_exit;

    event->type = TYPE_URETPROBE_SSL_READ;
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

cleanup_and_exit:
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
