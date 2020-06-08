#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <inttypes.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include "../libbpf/src/bpf_helpers.h"
#include "helpers.h"
#include "common.h"

struct bpf_map_def SEC("maps") payload_map = 
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct payload),
    .max_entries = 1
};

#define printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

SEC("xdp_methodtwo")
int xdp_prog(struct xdp_md *ctx)
{    
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (eth + 1 > (struct ethhdr *)data_end)
    {
        return XDP_DROP;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (iph + 1 > (struct iphdr *)data_end)
    {
        return XDP_DROP;
    }

    if (unlikely(iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP))
    {
        return XDP_DROP;
    }

    uint16_t l4len = 0;

    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

        if (tcph + 1 > (struct tcphdr *)data_end)
        {
            return XDP_DROP;
        }

        l4len = tcph->doff * 4;
    }
    else
    {
        l4len = 8;
    }

    uint32_t key = 0;
    struct payload *pl = bpf_map_lookup_elem(&payload_map, &key);

    if (pl)
    {
        for (int i = 0; i < MAX_PAYLOAD_LENGTH; i++)
        {
            if (i + 1 > pl->length)
            {
                break;
            }

            uint8_t *byte = data + sizeof(struct ethhdr) + (iph->ihl * 4) + l4len + i;

            if (byte + 1 > (uint8_t *)data_end)
            {
                break;
            }

            if (*(byte + i) == pl->payload[i])
            {
                continue;
            }

            goto pass;
        }
    }

    return XDP_DROP;

    pass:
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";