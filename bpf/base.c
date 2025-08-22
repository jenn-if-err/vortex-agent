//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"

#include "vortex.h"

#ifndef __BPF_VORTEX_COMMON_C
#define __BPF_VORTEX_COMMON_C

extern int LINUX_KERNEL_VERSION __kconfig;

/* Event structure to be sent to userspace. */
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
    __u64 message_id; /* for per connection counter */
};

/* Map to store events for userspace consumption. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
    __type(value, struct event);
} events SEC(".maps");

/* Basic stats data. */
struct events_stats_t {
    __u64 sent;
    __u64 lost;
};

/* Map for basic stats. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);                   /* always 0 */
    __type(value, struct events_stats_t); /* stats */
} events_stats SEC(".maps");

/*
 * Map to control which TGIDs are traced. A key of TGID_ENABLE_ALL means
 * all TGIDs are traced. Otherwise, only trace whatever's in the map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  /* TGID */
    __type(value, __u8); /* unused */
} tgids_to_trace SEC(".maps");

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
 * NOTE:
 * The following struct defs are for associating SSL_writes and SSL_reads to
 * socket information. This makes it limited to apps that are "BIO-native",
 * or those that use their TLS/SSL libraries to handle the networking
 * alongside crypto.
 *
 * Unfortunately, this won't support "BIO-custom apps", or those that only
 * use the TLS/SSL libraries for crypto, and handle networking by themselves.
 *
 * Anyway, this is easier to implement than using offsets, which is very
 * error-prone and requires a lot of maintenance. We might need to do offsets
 * in the future, for those BIO-custom apps.
 */

/* Key for the fd_connect map. */
struct ssl_callstack_k {
    __u64 pid_tgid;
    __u32 rw_flag; /* 0 = read, 1 = write */
};

/* Callstack context information. */
struct ssl_callstack_v {
    uintptr_t buf; /* instead of (char *), which bpf2go doesn't support */
    int len;
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

/* Active on SSL_{write|read} entry, removed on SSL_{write|read} exit. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ssl_callstack_k);
    __type(value, struct ssl_callstack_v);
} ssl_callstack SEC(".maps");

/* Optional comm (single) to trace (when provided from userspace). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);                 /* always 0 */
    __type(value, char[TASK_COMM_LEN]); /* comm to trace */
} trace_comm SEC(".maps");

/* should_trace_comm()'s buffer for getting comm instead of stack. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);                 /* always 0 */
    __type(value, char[TASK_COMM_LEN]); /* buffer for comm */
} buf_comm SEC(".maps");

/* Value for the fd_connect map. */
struct fd_connect_v {
    __u32 fd;
    uintptr_t sk; /* instead of (struct sock *), which bpf2go doesn't support */
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

/*
 * Check if a PID/TGID's fd has called connect on socket.
 * Active on sys_enter_connect, removed on sys_enter_close.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct fd_connect_v);
} fd_connect SEC(".maps");

/* Active on cgroup/connect4, removed on cgroup/sock_release. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct bpf_sock *); /* sk */
    __type(value, __u64);           /* pid_tgid */
} sk_to_pid_tgid SEC(".maps");
// for per connection msg counter
struct conn_key {
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct conn_key);
    __type(value, __u64); // message counter
} conn_msg_seq_map SEC(".maps");

/* Set process information in the event structure. */
static __always_inline void set_proc_info(struct event *event) {
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->tgid = pid_tgid >> 32;
}

/* Are we tracing this TGID? */
static __always_inline int should_trace_tgid(__u32 tgid) {
    __u32 all = TGID_ENABLE_ALL;
    if (bpf_map_lookup_elem(&tgids_to_trace, &all) == NULL)
        if (bpf_map_lookup_elem(&tgids_to_trace, &tgid) == NULL)
            return VORTEX_NO_TRACE;

    return VORTEX_TRACE;
}

/* Are we tracing this comm? */
static __always_inline int should_trace_comm(int *all) {
    *all = COMM_NO_TRACE_ALL;
    __u32 key = 0;
    char *comm_tr = bpf_map_lookup_elem(&trace_comm, &key);
    if (!comm_tr) {
        *all = COMM_TRACE_ALL;
        return VORTEX_TRACE;
    }

    char *comm = bpf_map_lookup_elem(&buf_comm, &key);
    if (!comm)
        return VORTEX_TRACE;

    __builtin_memset(comm, 0, TASK_COMM_LEN);
    bpf_get_current_comm(comm, sizeof(comm));
    int cmp = __builtin_memcmp(comm_tr, comm, TASK_COMM_LEN);

    return cmp == 0 ? VORTEX_TRACE : VORTEX_NO_TRACE;
}

/* Our wrapper to bpf_ringbuf_reserve() to track lost packets. */
static __always_inline void *rb_events_reserve_with_stats() {
    void *rb = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (rb)
        return rb;

    __u32 key = 0;
    struct events_stats_t *stats;
    stats = bpf_map_lookup_elem(&events_stats, &key);
    if (!stats) {
        struct events_stats_t n_stats = {.sent = 0, .lost = 1};
        bpf_map_update_elem(&events_stats, &key, &n_stats, BPF_ANY);
    } else {
        struct events_stats_t n_stats = {
            .sent = stats->sent,
            .lost = stats->lost + 1,
        };

        bpf_printk("rb_events_reserve_with_stats: lost=%llu", n_stats.lost);
        bpf_map_update_elem(&events_stats, &key, &n_stats, BPF_ANY);
    }

    return rb;
}

/* Our wrapper to bpf_ringbuf_submit() to track sent packets. */
static __always_inline void rb_events_submit_with_stats(void *event, __u64 flags) {
    bpf_ringbuf_submit(event, flags);

    __u32 key = 0;
    struct events_stats_t *stats;
    stats = bpf_map_lookup_elem(&events_stats, &key);
    if (!stats) {
        struct events_stats_t n_stats = {.sent = 1, .lost = 0};
        bpf_map_update_elem(&events_stats, &key, &n_stats, BPF_ANY);
        return;
    }

    struct events_stats_t n_stats = {
        .sent = stats->sent + 1,
        .lost = stats->lost,
    };

    /* bpf_printk("rb_events_submit_with_stats: sent=%llu", n_stats.sent); */
    bpf_map_update_elem(&events_stats, &key, &n_stats, BPF_ANY);
}

#endif /* __BPF_VORTEX_COMMON_C */
