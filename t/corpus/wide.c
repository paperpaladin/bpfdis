/* 64-bit immediates, which are the only two-slot instruction, and a string
 * reference that makes clang emit a relocation into the middle of one. */
#include "bpf.h"

SEC("socket/consts")
int consts(struct __sk_buff *skb)
{
    u64 a = 0x1122334455667788ull;
    u64 b = 0xffffffff00000000ull;
    u64 c = 0x00000000ffffffffull;
    u64 d = 0x8000000000000000ull;
    u64 v = skb->len;
    return (int)((v ^ a) + (v & b) - (v | c) + (v % (d | 1)));
}

SEC("socket/printk")
int printk(struct __sk_buff *skb)
{
    char fmt[] = "len=%u mark=%u\n";
    bpf_trace_printk(fmt, sizeof(fmt), skb->len, skb->mark);
    return 0;
}

LICENSE("GPL");
