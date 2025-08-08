//go:build ignore

#include "common.c"
#include "maps.c"
#include "openssl.c"
#include "socket.c"

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
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ssl_handshakes, &pid_tgid);
    return BPF_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
