# XDP Dynamic Payload Matching Findings
This repository is used to store my findings on matching dynamic payloads in XDP. In my opinion, being able to match payload data from a BPF map is important for the future of XDP.

I made a thread on the XDP Newbies mailing list [here](https://marc.info/?l=xdp-newbies&m=158894658804356&w=2) addressing this. Unfortunately, it appears nobody has found a way to match XDP payload data dynamically yet. However, Toke did give a suggestion that I plan on trying and noting in this repository.

In these XDP program sections, we try to compare payload data from the `payload_map` BPF map. You may specify the payload in `src/loader.c`.

## Section "methodone" (FAIL)
In this method, we attempt to match the payload data using a for loop. We check if the offset is outside of the packet via:

```C
if (byte + 1 > (uint8_t *)data_end)
{
    break;
}
```

Unfortunately, this still fails the BPF verifier:

```
invalid access to packet, off=22 size=1, R7(id=3,off=22,r=0)
R7 offset is outside of the packet
processed 55 insns (limit 1000000) max_states_per_insn 0 total_states 4 peak_states 4 mark_read 3
```

## Section "methodtwo" (FAIL)
In this method, we attempt to match the payload data using a for loop just like method one. However, we use goto.

We check if the offset is outside of the packet via:

```C
if (byte + 1 > (uint8_t *)data_end)
{
    break;
}
```

Unfortunately, this still fails the BPF verifier just like method one:

```
invalid access to packet, off=22 size=1, R7(id=3,off=22,r=0)
R7 offset is outside of the packet
processed 55 insns (limit 1000000) max_states_per_insn 0 total_states 4 peak_states 4 mark_read 3
```

## Section "methodthree" (FAIL)
*Not finished*

## Section "methodfour" (FAIL)
In this method, we attempt to match the payload data using a hash map and the payload data as the map's key. The max key size doesn't support up to 1500 bytes. Therefore, I override the size to 150 bytes here:

```C
#ifdef MAX_PAYLOAD_LENGTH
#undef MAX_PAYLOAD_LENGTH
#define MAX_PAYLOAD_LENGTH 150
#endif
```

Sadly, this also fails when compiling with the following error:

```
error: <unknown>:0:0: in function xdp_prog i32 (%struct.xdp_md*): A call to built-in function 'memcpy' is not supported.
```

This is due to using `*len` at:

```C
memcpy(&hashkey, pcktData, *len);
```

If we use a static length such as 10 bytes:

```C
uint32_t key = 0;
//uint8_t *len = bpf_map_lookup_elem(&payload_length, &key);
uint8_t len = 10;
uint8_t *pcktData = data + sizeof(struct ethhdr) + (iph->ihl * 4) + l4len;

if (!(pcktData + (len + 1) > (uint8_t *)data_end))
{
    uint8_t hashkey[10]; // Using `len` as the size also results in a compilation error. We'd have to use a pointer instead and dynamically allocate space to it via `malloc()` or something similar more than likely.

    memcpy(&hashkey, pcktData, len);
    
    uint8_t *match = bpf_map_lookup_elem(&payload_map, &hashkey);

    if (match)
    {
        printk("Dropping matched packet.\n");

        goto drop;
    }
}
```

The XDP program compiles without any issues. However, when attempting to run, results in the following error:

```
72: (85) call bpf_map_lookup_elem#1
invalid stack type R2 off=-16 access_size=150
processed 63 insns (limit 1000000) max_states_per_insn 0 total_states 3 peak_states 3 mark_read 3
```

This error occurs on this line:

```C
uint8_t *match = bpf_map_lookup_elem(&payload_map, &hashkey);
```

I'm unsure what the issue is, though.