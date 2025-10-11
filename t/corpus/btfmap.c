/* The modern map definition: a BTF type whose members are pointers to arrays,
 * with the integers hidden in the array lengths. Unreadable without BTF. */
#include "bpf.h"

struct {
    int (*type)[BPF_MAP_TYPE_HASH];
    u32 *key;
    u64 *value;
    int (*max_entries)[4096];
} events SEC(".maps");

struct {
    int (*type)[BPF_MAP_TYPE_ARRAY];
    int (*max_entries)[8];
    u32 *key;
    struct { u64 a; u32 b; } *value;
} ring SEC(".maps");

SEC("socket/btfmaps")
int btfmaps(struct __sk_buff *skb)
{
    u32 k = skb->len;
    u64 *v = bpf_map_lookup_elem(&events, &k);
    void *w = bpf_map_lookup_elem(&ring, &k);
    if (!v || !w) return 0;
    return (int)*v;
}

LICENSE("GPL");
