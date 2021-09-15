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

## Section "methodfour" (SUCCESS!)
This method works! However, with its current implementation, it can only match payload data from the beginning of the string and once. With that said, the payload needs to be exact.

This is because we store the payload data we want to match inside of a BPF map as the key. The main code looks like this:


```C
uint8_t *pcktdata = data + sizeof(struct ethhdr) + (iph->ihl * 4) + l4len;

uint8_t hashkey[MAX_PAYLOAD_LENGTH] = {0};

for (int i = 0; i < MAX_PAYLOAD_LENGTH; i++)
{
    if (pcktdata + (i + 1) > (uint8_t *)data_end)
    {
        break;
    }

    hashkey[i] = *(pcktdata + i);
}

uint8_t *match = bpf_map_lookup_elem(&payload_map, &hashkey);

if (match)
{
    printk("Dropping matched packet.\n");
}
```

## Credits
* [Christian Deacon](https://github.com/gamemann)