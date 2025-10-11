/* Shapes the control-flow graph has to get right: a bounded loop, nested
 * loops, a switch, an early exit, and a function that cannot fall through. */
#include "bpf.h"

SEC("socket/loop")
int loop(struct __sk_buff *skb)
{
    u64 s = 0;
    for (u32 i = 0; i < (skb->len & 0xff); i++)
        s += bpf_ktime_get_ns() & i;
    return (int)s;
}

SEC("socket/nested")
int nested(struct __sk_buff *skb)
{
    u64 s = 0;
    u32 n = skb->len & 0xf;
    for (u32 i = 0; i < n; i++)
        for (u32 j = 0; j < n; j++)
            s += bpf_get_prandom_u32() ^ (i * j);
    return (int)s;
}

SEC("socket/switch")
int sw(struct __sk_buff *skb)
{
    switch (skb->len & 7) {
    case 0: return 100;
    case 1: return (int)bpf_ktime_get_ns();
    case 2: return (int)bpf_get_prandom_u32();
    case 3: return (int)bpf_get_smp_processor_id();
    case 4: return (int)bpf_get_current_pid_tgid();
    case 5: return 105;
    case 6: return 106;
    default: return -1;
    }
}

SEC("socket/early")
int early(struct __sk_buff *skb)
{
    if (skb->len == 0) return -1;
    if (skb->mark == 0) return -2;
    if (skb->hash == 0) return -3;
    u64 t = bpf_ktime_get_ns();
    if (t & 1) return 1;
    return 0;
}

SEC("socket/whileloop")
int whileloop(struct __sk_buff *skb)
{
    u32 n = skb->len;
    u32 c = 0;
    while (n) { n &= n - 1; c++; }
    return (int)c;
}

LICENSE("GPL");
