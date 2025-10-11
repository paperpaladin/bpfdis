/* Arithmetic and compares over both widths, and the branch forms clang picks
 * when it cannot fold them away. */
#include "bpf.h"

SEC("socket/arith")
int arith(struct __sk_buff *skb)
{
    u32 a = skb->len;
    u64 b = skb->mark;
    u64 r = 0;
    r += a + b;
    r -= a * 3;
    r ^= b << 7;
    r |= (u64)a >> 2;
    r &= ~b;
    r += (u64)(long)((s32)a / 7);
    r += (u64)(long)((s32)a % 5);
    r += (u32)a / (u32)(b | 1);
    r += -(s64)r;
    return (int)r;
}

SEC("socket/cmp")
int cmp(struct __sk_buff *skb)
{
    u64 x = skb->len;
    s64 y = (s64)(s32)skb->mark;
    int n = 0;
    if (x > 10) n++;
    if (x >= 20) n++;
    if (x < 30) n++;
    if (x <= 40) n++;
    if (y > 10) n++;
    if (y >= 20) n++;
    if (y < 30) n++;
    if (y <= 40) n++;
    if (x != 50) n++;
    if (x == 60) n++;
    if (x & 0x80) n++;
    return n;
}

SEC("socket/cmp32")
int cmp32(struct __sk_buff *skb)
{
    u32 x = skb->len;
    s32 y = (s32)skb->mark;
    int n = 0;
    if (x > 10u) n++;
    if (x >= 20u) n++;
    if (x < 30u) n++;
    if (x <= 40u) n++;
    if (y > 10) n++;
    if (y >= 20) n++;
    if (y < 30) n++;
    if (y <= 40) n++;
    if (x != 50u) n++;
    if (x == 60u) n++;
    if (x & 0x80u) n++;
    return n;
}

SEC("socket/endian")
int endian(struct __sk_buff *skb)
{
    u64 v = skb->len;
    u16 a = __builtin_bswap16((u16)v);
    u32 b = __builtin_bswap32((u32)v);
    u64 c = __builtin_bswap64(v);
    return (int)(a + b + c);
}

LICENSE("GPL");
