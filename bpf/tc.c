//go:build ignore

#include "base.c"

#ifndef __BPF_VORTEX_TC_C
#define __BPF_VORTEX_TC_C

SEC("tc")
int tc_ingress(struct __sk_buff *skb) { return TC_ACT_OK; }

struct sni_loop_data {
    struct __sk_buff *skb;
    __u32 *offset;
    __u32 *extensions_end;
    __u32 *sni_len;
};

static int loop_parse_sni(u64 index, struct sni_loop_data *data) {
    if (*data->offset + 4 > *data->extensions_end)
        return BPF_END_LOOP;

    __u16 ext_type, ext_len;
    if (bpf_skb_load_bytes(data->skb, *data->offset, &ext_type, 2) < 0)
        return BPF_END_LOOP;

    *data->offset += 2;
    if (bpf_skb_load_bytes(data->skb, *data->offset, &ext_len, 2) < 0)
        return BPF_END_LOOP;

    *data->offset += 2;
    ext_type = bpf_ntohs(ext_type);
    ext_len = bpf_ntohs(ext_len);

    if (ext_type == TLS_EXTENSION_SNI) {
        /* Contains: list_len(2), type(1), name_len(2), name(...) */
        if (*data->offset + 5 > *data->extensions_end)
            return BPF_END_LOOP;

        __u16 sni_name_len;
        if (bpf_skb_load_bytes(data->skb, *data->offset + 3, &sni_name_len, 2) < 0)
            return BPF_END_LOOP;

        sni_name_len = bpf_ntohs(sni_name_len);
        if (*data->offset + 5 + sni_name_len > *data->extensions_end)
            return BPF_END_LOOP;

        *data->sni_len = (__u32)sni_name_len;
        *data->offset += 5;

        return BPF_END_LOOP;
    }

    *data->offset += ext_len;

    return BPF_CONTINUE_LOOP;
}

static __always_inline void set_sni_trace(__u64 pid_tgid, __u8 allowed) {
    __u32 key = 0, tmp = 0;
    bpf_map_update_elem(&tc_sni_trace_on, &key, &tmp, BPF_ANY);

    __u8 *ptr = bpf_map_lookup_elem(&tc_sni_trace, &pid_tgid);
    if (ptr) {
        *ptr |= allowed == VORTEX_TRACE ? 0x2 : 0x1;
        return;
    }

    __u8 val = allowed == VORTEX_TRACE ? 0x3 : 0x1;
    bpf_map_update_elem(&tc_sni_trace, &pid_tgid, &val, BPF_ANY);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    __u64 pid_tgid = 0;
    struct bpf_sock *sk = BPF_CORE_READ(skb, sk);
    __u64 *val = bpf_map_lookup_elem(&sk_to_pid_tgid, &sk);
    if (val)
        pid_tgid = *val;

    __u8 trace = VORTEX_NO_TRACE;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 offset;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        goto set_trace_and_exit;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto set_trace_and_exit;

    struct iphdr *iph = (void *)eth + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        goto set_trace_and_exit;

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        goto set_trace_and_exit;

    offset = sizeof(*eth) + (iph->ihl * 4);
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
            goto set_trace_and_exit;

        sport = tcph->source;
        dport = tcph->dest;

        if (bpf_ntohs(sport) == 22) /* SSH, very noisy in test */
            goto set_trace_and_exit;

        if (bpf_ntohs(dport) != 443) /* TLS is usually 443 */
            goto set_trace_and_exit;

        offset += (tcph->doff * 4);
        unsigned char tls_header[6];
        if (bpf_skb_load_bytes(skb, offset, tls_header, sizeof(tls_header)) < 0)
            goto set_trace_and_exit;

        /* Check for TLS Handshake Record (0x16) and ClientHello (0x01). */
        if (tls_header[0] != TLS_HANDSHAKE || tls_header[5] != TLS_CLIENT_HELLO)
            goto set_trace_and_exit;

        /* tls_header[6]; u24 length; u16 version; u8 random[32]; */
        offset += 6 + 3 + 2 + 32;

        __u8 session_id_len;
        if (bpf_skb_load_bytes(skb, offset, &session_id_len, 1) < 0)
            goto set_trace_and_exit;

        offset += 1 + session_id_len;

        __u16 cipher_suites_len;
        if (bpf_skb_load_bytes(skb, offset, &cipher_suites_len, 2) < 0)
            goto set_trace_and_exit;

        offset += 2 + bpf_ntohs(cipher_suites_len);

        __u8 comp_methods_len;
        if (bpf_skb_load_bytes(skb, offset, &comp_methods_len, 1) < 0)
            goto set_trace_and_exit;

        offset += 1 + comp_methods_len;

        __u16 extensions_len;
        if (bpf_skb_load_bytes(skb, offset, &extensions_len, 2) < 0)
            goto set_trace_and_exit;

        offset += 2;
        extensions_len = bpf_ntohs(extensions_len);

        __u32 extensions_end = offset + extensions_len;

        __u32 sni_len;
        char sni[MAX_SNI_LEN];
        __builtin_memset(sni, 0, sizeof(sni));

        struct sni_loop_data loop_data = {
            .skb = skb,
            .offset = &offset,
            .extensions_end = &extensions_end,
            .sni_len = &sni_len,
        };

        if (bpf_loop(20, loop_parse_sni, &loop_data, 0) < 0)
            goto set_trace_and_exit;

        if (sni_len > MAX_SNI_LEN - 1)
            sni_len = MAX_SNI_LEN - 1;

        /* This makes verifier happy, which somehow always get [0,255] range for sni_len (GKE v6.6). */
        __u32 sni_copy_len = 1;
        if (sni_len > 1)
            sni_copy_len += sni_len - 1;

        if (bpf_skb_load_bytes(skb, offset, sni, sni_copy_len) < 0)
            goto set_trace_and_exit;

        if (bpf_strncmp(sni, MAX_SNI_LEN, "generativelanguage.googleapis.com") == 0 /* Gemini */ ||
            bpf_strncmp(sni, MAX_SNI_LEN, "api.openai.com") == 0 /* ChatGPT */ ||
            bpf_strncmp(sni, MAX_SNI_LEN, "google.com") == 0 /* test:google */ ||
            bpf_strncmp(sni, MAX_SNI_LEN, "github.com") == 0 /* test:github */ ||
            bpf_strncmp(sni, MAX_SNI_LEN, "jsonplaceholder.typicode.com") == 0 /* test:node */ ||
            bpf_strncmp(sni, MAX_SNI_LEN, "alphaus.cloud") == 0 /* test:alphaus */)
            trace = VORTEX_TRACE;

        bpf_printk("tc_egress: sni=%s, src=%pI4:%u, dst=%pI4:%u, pid_tgid=%llu", sni, &saddr, bpf_ntohs(sport), &daddr,
                   bpf_ntohs(dport), pid_tgid);

        break;

    case IPPROTO_UDP:
        udph = transport_header;
        if ((void *)udph + sizeof(*udph) > data_end)
            return TC_ACT_OK;

        sport = udph->source;
        dport = udph->dest;

        break;
    }

set_trace_and_exit:
    set_sni_trace(pid_tgid, trace);
    return TC_ACT_OK;
}

#endif /* __BPF_VORTEX_TC_C */
