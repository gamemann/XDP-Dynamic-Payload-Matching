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
    .type = BPF_MAP_TYPE_HASH,
    .key_size = MAX_PAYLOAD_LENGTH,
    .value_size = sizeof(uint8_t),
    .max_entries = 1
};

struct bpf_map_def SEC("maps") payload_length = 
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 1
};

#define printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

SEC("xdp_methodfour")
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

    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

        if (tcph + 1 > (struct tcphdr *)data_end)
        {
            return XDP_DROP;
        }

        uint16_t l4len = tcph->doff * 4;

        uint8_t *pcktdata = data + sizeof(struct ethhdr) + (iph->ihl * 4) + l4len;

        uint8_t hashkey[MAX_PAYLOAD_LENGTH];

        for (int i = 0; i < MAX_PAYLOAD_LENGTH; i++)
        {
            if (pcktdata + (i + 1) > (uint8_t *)data_end)
            {
                return XDP_PASS;
            }

            memcpy(hashkey + i, pcktdata + i, 1);
        }
        
        uint8_t *match = bpf_map_lookup_elem(&payload_map, &hashkey);

        if (match)
        {
            printk("Dropping matched packet.\n");
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";