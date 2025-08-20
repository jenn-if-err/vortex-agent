//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_TC_C
#define __BPF_VORTEX_TC_C

SEC("tc")
int tc_ingress(struct __sk_buff *skb) { return TC_ACT_OK; }

SEC("tc")
int tc_egress(struct __sk_buff *skb) { return TC_ACT_OK; }

#endif /* __BPF_VORTEX_TC_C */
