/* Subprogram calls. A `call` whose src_reg is 1 is a relative call to another
 * function in the same object, not a helper, and the two share an opcode. */
#include "bpf.h"

static __attribute__((noinline)) u64 mix(u64 a, u64 b)
{
    return a * 1099511628211ull ^ b;
}

static __attribute__((noinline)) u64 fold(u64 *p, u32 n)
{
    u64 s = 0;
    for (u32 i = 0; i < (n & 7); i++) s = mix(s, p[0]);
    return s;
}

SEC("socket/caller")
int caller(struct __sk_buff *skb)
{
    u64 v = skb->len;
    u64 r = mix(v, skb->mark);
    r = fold(&r, skb->hash);
    return (int)r;
}

__attribute__((noinline)) u64 global_sub(u64 a)
{
    return a + bpf_ktime_get_ns();
}

SEC("socket/globalcall")
int globalcall(struct __sk_buff *skb)
{
    return (int)global_sub(skb->len);
}

LICENSE("GPL");
