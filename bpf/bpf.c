//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define TASK_COMM_LEN 16

enum event_direction {
    DIRECTION_UNKNOWN = 0,
    DIRECTION_SEND = 1,
    DIRECTION_RECV = 2,
};

struct event {
    __u32 pid;
    __u32 tgid;
    __u64 bytes;
    __u64 timestamp_ns;
    int direction;
    char comm[TASK_COMM_LEN]; // Process name, useful for debugging
};

// Define a ring buffer map for sending events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} events SEC(".maps");

// Helper function to populate and submit an event.
static __always_inline int submit_event(__u64 bytes, enum event_direction direction) {
    // Check if bytes transferred is valid (not an error code).
    if (bytes == 0 || bytes & (1ULL << 63)) {
        return 0;
    }

    // Allocate space in the ring buffer.
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF; // PID (thread ID)
    e->tgid = pid_tgid >> 32;       // TGID (process ID)
    e->bytes = bytes;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->direction = direction;
    bpf_get_current_comm(&e->comm, sizeof(e->comm)); // get process name

    // Submit the event to userspace.
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Kretprobe for sys_sendmsg (outgoing traffic).
SEC("kretprobe/sys_sendmsg")
int BPF_KRETPROBE(sys_sendmsg_ret) {
    /* __u64 bytes_sent = PT_REGS_RC(ctx); // return value is bytes sent */
    /* return submit_event(bytes_sent, DIRECTION_SEND); */
    return submit_event(1, DIRECTION_SEND);
}

// Kretprobe for sys_recvmsg (incoming traffic).
SEC("kretprobe/sys_recvmsg")
int BPF_KRETPROBE(sys_recvmsg_ret) {
    /* __u64 bytes_received = PT_REGS_RC(ctx); // return value is bytes received */
    /* return submit_event(bytes_received, DIRECTION_RECV); */
    return submit_event(2, DIRECTION_RECV);
}

char _license[] SEC("license") = "Dual MIT/GPL";
