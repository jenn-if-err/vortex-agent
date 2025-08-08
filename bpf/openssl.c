//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_OPENSSL_C
#define __BPF_VORTEX_OPENSSL_C

struct loop_data {
    u32 type;
    char **buf_ptr;
    int *len;
    int *orig_len;
};

/* bpf_loop callback: send data to userspace in chunks of EVENT_BUF_LEN bytes. */
static int do_SSL_loop(u64 index, struct loop_data *data) {
    struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return BPF_END_LOOP;

    u32 len = (u32)*data->len > EVENT_BUF_LEN ? EVENT_BUF_LEN : (u32)*data->len;
    set_proc_info(event);
    event->type = data->type;
    event->total_len = *data->orig_len;
    event->chunk_len = len;
    event->chunk_idx = index;
    __builtin_memset(event->buf, 0, EVENT_BUF_LEN);

    char *buf = *data->buf_ptr;
    if (bpf_probe_read_user(&event->buf, len, buf) == 0)
        bpf_ringbuf_submit(event, 0);
    else
        bpf_ringbuf_discard(event, 0); /* discard but still adjust values? */

    *data->buf_ptr = *data->buf_ptr + len; /* forward buffer pointer */

    int sub = *data->len <= EVENT_BUF_LEN ? *data->len : EVENT_BUF_LEN;
    *data->len = *data->len - sub;
    if (*data->len <= 0)
        return BPF_END_LOOP;

    return BPF_CONTINUE_LOOP;
}

static int do_uprobe_SSL_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_callstack_ctx w_ctx;
    w_ctx.buf = (uintptr_t)PT_REGS_PARM2(ctx);
    w_ctx.len = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_write_callstack, &pid_tgid, &w_ctx, BPF_ANY);

    char *buf = (char *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    int orig_num = num;

    struct loop_data data = {
        .type = TYPE_UPROBE_SSL_WRITE,
        .buf_ptr = &buf,
        .len = &num,
        .orig_len = &orig_num,
    };

    /* Is EVENT_BUF_LEN * 1000 enough? */
    bpf_loop(1000, do_SSL_loop, &data, 0);

    /* Signal previous chunked stream's end. */
    struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return BPF_OK;

    event->type = TYPE_UPROBE_SSL_WRITE;
    set_proc_info(event);
    event->total_len = orig_num;
    event->chunk_len = -1;
    event->chunk_idx = CHUNKED_END_IDX;
    __builtin_memset(event->buf, 0, EVENT_BUF_LEN);
    bpf_ringbuf_submit(event, 0);

    return BPF_OK;
}

static int do_uretprobe_SSL_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ssl_write_callstack, &pid_tgid);
    return BPF_OK;
}

/*
 * Methods for accessing container-based file systems for u[ret]probes.
 *
 * 1) Check /proc/pid/root/. Symbolic link to pid's root directory.
 *    Recommended method.
 *
 * 2) Check /proc/pid/mountinfo. There will be a lowerdir, upperdir, and
 *    workdir mounts. Replace upperdir's ---/diff/ to ---/merged/.
 */

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
int uretprobe_SSL_write(struct pt_regs *ctx) { return do_uretprobe_SSL_write(ctx); }

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
int uretprobe_SSL_write_ex(struct pt_regs *ctx) { return do_uretprobe_SSL_write(ctx); }

static int do_uprobe_SSL_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_callstack_ctx r_ctx;
    r_ctx.buf = (uintptr_t)PT_REGS_PARM2(ctx);
    r_ctx.len = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_read_callstack, &pid_tgid, &r_ctx, BPF_ANY);

    char *buf = (char *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_read_buf, &pid_tgid, &buf, BPF_ANY);

    return BPF_OK;
}

static int do_uretprobe_SSL_read(struct pt_regs *ctx, int read) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&ssl_read_callstack, &pid_tgid);

    if (read <= 0) {
        bpf_map_delete_elem(&ssl_read_buf, &pid_tgid);
        return BPF_OK;
    }

    char **buf_ptr = bpf_map_lookup_elem(&ssl_read_buf, &pid_tgid);
    if (!buf_ptr)
        return BPF_OK;

    char *buf = (char *)*buf_ptr;
    int orig_len = read;

    struct loop_data data = {
        .type = TYPE_URETPROBE_SSL_READ,
        .buf_ptr = &buf,
        .len = &read,
        .orig_len = &orig_len,
    };

    /* Is EVENT_BUF_LEN * 1000 enough? */
    bpf_loop(1000, do_SSL_loop, &data, 0);

    bpf_map_delete_elem(&ssl_read_buf, &pid_tgid);

    /* Signal previous chunked stream's end. */
    struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return BPF_OK;

    event->type = TYPE_UPROBE_SSL_WRITE;
    set_proc_info(event);
    event->total_len = orig_len;
    event->chunk_len = -1;
    event->chunk_idx = CHUNKED_END_IDX;
    __builtin_memset(event->buf, 0, EVENT_BUF_LEN);
    bpf_ringbuf_submit(event, 0);

    return BPF_OK;
}

/*
 * Synopsis:
 * int SSL_read(SSL *s, void *buf, int num);
 *
 * Store the pointer of the user buffer in a map,
 * so that we can retrieve it in its uretprobe pair.
 */
SEC("uprobe/SSL_read")
int uprobe_SSL_read(struct pt_regs *ctx) { return do_uprobe_SSL_read(ctx); }

/*
 * Synopsis:
 * int SSL_read(SSL *s, void *buf, int num);
 *
 * Retrieve the user buffer pointer from our map, read the data, and send to
 * our ring buffer (userspace).
 */
SEC("uretprobe/SSL_read")
int uretprobe_SSL_read(struct pt_regs *ctx) { return do_uretprobe_SSL_read(ctx, (int)PT_REGS_RC(ctx)); }

/*
 * Synopsis:
 * int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *read);
 *
 * Store the pointer of the user buffer in a map so that we can
 * retrieve it in its uretprobe pair.
 */
SEC("uprobe/SSL_read_ex")
int uprobe_SSL_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 read = (u64)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&ssl_read_ex_p4, &pid_tgid, &read, BPF_ANY);
    return do_uprobe_SSL_read(ctx);
}

/*
 * Synopsis:
 * int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *read);
 *
 * Retrieve the user buffer pointer from our map, read the data,
 * and send to our ring buffer (userspace).
 */
SEC("uretprobe/SSL_read_ex")
int uretprobe_SSL_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *read = bpf_map_lookup_elem(&ssl_read_ex_p4, &pid_tgid);
    if (!read)
        return BPF_OK;

    size_t len = 0;
    bpf_probe_read_user(&len, sizeof(len), (void *)*read);
    bpf_map_delete_elem(&ssl_read_ex_p4, &pid_tgid);
    return do_uretprobe_SSL_read(ctx, (int)len);
}

#endif /* __BPF_VORTEX_OPENSSL_C */
