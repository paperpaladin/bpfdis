/* Legacy bpf_map_def maps, the 16-byte map-fd load, and the atomic family. */
#include "bpf.h"

struct bpf_map_def counts SEC("maps") = {
    .type = BPF_MAP_TYPE_HASH, .key_size = 4, .value_size = 8,
    .max_entries = 1024, .map_flags = 0,
};
struct bpf_map_def slots SEC("maps") = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = 4, .value_size = 16,
    .max_entries = 64, .map_flags = 0,
};

SEC("socket/lookup")
int lookup(struct __sk_buff *skb)
{
    u32 k = skb->len;
    u64 *v = bpf_map_lookup_elem(&counts, &k);
    if (!v) {
        u64 init = 1;
        bpf_map_update_elem(&counts, &k, &init, 0);
        return 0;
    }
    __sync_fetch_and_add(v, 1);
    return (int)*v;
}

SEC("socket/atomics")
int atomics(struct __sk_buff *skb)
{
    u32 k = 0;
    u64 *v = bpf_map_lookup_elem(&counts, &k);
    if (!v) return 0;
    u64 d = skb->len;
    __sync_fetch_and_add(v, d);
    __sync_fetch_and_or(v, d);
    __sync_fetch_and_and(v, d);
    __sync_fetch_and_xor(v, d);
    u64 old = __sync_lock_test_and_set(v, d);
    u64 cas = __sync_val_compare_and_swap(v, old, d);
    u64 fa = __sync_fetch_and_add(v, 1);
    return (int)(old + cas + fa);
}

SEC("socket/two")
int two(struct __sk_buff *skb)
{
    u32 k = skb->len;
    void *a = bpf_map_lookup_elem(&counts, &k);
    void *b = bpf_map_lookup_elem(&slots, &k);
    bpf_map_delete_elem(&counts, &k);
    return (a != 0) + (b != 0) * 2;
}

LICENSE("GPL");
