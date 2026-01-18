#include "bpf.h"
int g_data = 7;
int g_bss;
const int g_ro = 11;
static const char msg[] = "hello";
SEC("socket/dz")
int dz(struct __sk_buff *skb) { g_bss += (int)skb->len; return g_data + g_ro + msg[0]; }
LICENSE("GPL");
