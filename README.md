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