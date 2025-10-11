/* Every load and store width, against the stack and against a pointer, so the
 * eight LDX/STX opcodes and the four ST-immediate opcodes all appear. */
#include "bpf.h"

SEC("socket/widths")
int widths(struct __sk_buff *skb)
{
    volatile u8 b8;
    volatile u16 b16;
    volatile u32 b32;
    volatile u64 b64;
    b8 = (u8)skb->len;
    b16 = (u16)skb->mark;
    b32 = skb->hash;
    b64 = (u64)skb->len << 32;
    return (int)(b8 + b16 + b32 + b64);
}

SEC("socket/stimm")
int stimm(struct __sk_buff *skb)
{
    volatile u8 a;
    volatile u16 b;
    volatile u32 c;
    volatile u64 d;
    a = 1;
    b = 2;
    c = 3;
    d = 4;
    if (skb->len) a = 9;
    return (int)(a + b + c + d);
}

SEC("socket/deep")
int deep(struct __sk_buff *skb)
{
    volatile char buf[128];
    for (int i = 0; i < 128; i++) buf[i] = (char)(skb->len + i);
    int s = 0;
    for (int i = 0; i < 128; i++) s += buf[i];
    return s;
}

LICENSE("GPL");
