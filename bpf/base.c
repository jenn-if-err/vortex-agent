//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"

#include "vortex.h"

#ifndef __BPF_VORTEX_COMMON_C
#define __BPF_VORTEX_COMMON_C

/*
 * Event structure to be sent to user space.
 */
struct event {
    __u8 comm[TASK_COMM_LEN]; /* for debugging only */
    __u8 buf[EVENT_BUF_LEN];
    __s64 total_len;
    __s64 chunk_len;
    __u32 chunk_idx;
    __u32 type;
    __u32 tgid;
    __u32 pid;
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

/*
 * Map to store events for user space consumption.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB buffer */
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
} ssl_read_buf SEC(".maps");

/*
 * Map to store the read pointer for SSL_read_ex. The key is the PID/TGID,
 * and the value is a pointer to the "bytes written" value.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} ssl_read_ex_p4 SEC(".maps");

/*
 * The following struct defs are for associating SSL_writes and SSL_reads to
 * socket information. This makes it limited to apps that are "BIO-native",
 * or those that use their TLS/SSL libraries to handle the networking
 * alongside crypto.
 *
 * Unfortunately, this won't support "BIO-custom apps", or those that
 * only use the TLS/SSL libraries for crypto, and handle networking by
 * themselves.
 *
 * Anyway, this is easier to implement than using offsets, which is very
 * error-prone and requires a lot of maintenance. We might need to do offsets
 * in the future, for those BIO-custom apps.
 */

/* Callstack context information. */
struct ssl_callstack_ctx {
    uintptr_t buf; /* instead of (char *), which bpf2go doesn't support */
    int len;
};

/* Active on SSL_write entry, removed on SSL_write exit. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct ssl_callstack_ctx);
} ssl_write_callstack SEC(".maps");

/* Active on SSL_read entry, removed on SSL_read exit. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct ssl_callstack_ctx);
} ssl_read_callstack SEC(".maps");

/*
 * Set process information in the event structure.
 */
static __always_inline void set_proc_info(struct event *event) {
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->tgid = pid_tgid >> 32;
}

/*
 * Are we tracing this TGID?
 */
static __always_inline int should_trace(__u32 tgid) {
    __u32 all = TGID_ENABLE_ALL;
    if (bpf_map_lookup_elem(&tgids_to_trace, &all) == NULL)
        if (bpf_map_lookup_elem(&tgids_to_trace, &tgid) == NULL)
            return VORTEX_NO_TRACE;

    return VORTEX_TRACE;
}

#endif /* __BPF_VORTEX_COMMON_C */
