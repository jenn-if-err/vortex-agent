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

#include "maps.c"

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
            return 0;

    return 1;
}

#endif /* __BPF_VORTEX_COMMON_C */
