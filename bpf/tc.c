//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_TC_C
#define __BPF_VORTEX_TC_C

SEC("tc")
int tc_ingress(struct __sk_buff *skb) { return TC_ACT_OK; }

#define TLS_HANDSHAKE 0x16
#define TLS_CLIENT_HELLO 0x01
#define TLS_EXTENSION_SNI 0x0000

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 payload_off;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)eth + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    payload_off = sizeof(*eth) + (iph->ihl * 4);
    void *transport_header = (void *)iph + (iph->ihl * 4);
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;

    struct tcphdr *tcph;
    struct udphdr *udph;

    saddr = iph->saddr;
    daddr = iph->daddr;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        tcph = transport_header;
        if ((void *)tcph + sizeof(*tcph) > data_end)
            return TC_ACT_OK;

        sport = tcph->source;
        dport = tcph->dest;

        if (bpf_ntohs(sport) == 22) /* SSH, very noisy in test */
            return TC_ACT_OK;

        if (bpf_ntohs(dport) != 443) /* TLS is usually 443 */
            return TC_ACT_OK;

        bpf_printk("TCP packet: src=%pI4:%u, dst=%pI4:%u", &saddr, bpf_ntohs(sport), &daddr, bpf_ntohs(dport));

        payload_off += (tcph->doff * 4);
        unsigned char tls_header[6];
        if (bpf_skb_load_bytes(skb, payload_off, tls_header, sizeof(tls_header)) < 0)
            return TC_ACT_OK;

        /* Check for TLS Handshake Record (0x16) and Client Hello (0x01). */
        if (tls_header[0] != TLS_HANDSHAKE || tls_header[5] != TLS_CLIENT_HELLO)
            return TC_ACT_OK;

        bpf_printk("TLS Client Hello detected, checking for SNI extension");
        break;

    case IPPROTO_UDP:
        udph = transport_header;
        if ((void *)udph + sizeof(*udph) > data_end)
            return TC_ACT_OK;

        sport = udph->source;
        dport = udph->dest;
        /* bpf_printk("UDP packet: src=%pI4:%u, dst=%pI4:%u", &saddr, bpf_ntohs(sport), &daddr, bpf_ntohs(dport)); */
        break;
    }

    return TC_ACT_OK;
}

#endif /* __BPF_VORTEX_TC_C */
