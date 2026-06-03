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

/* A key that is itself a pointer, so the member is a pointer to a pointer
 * and the size that matters is the size of a pointer rather than the size
 * of what it points at. Without this map the mutation that makes a pointer
 * as big as its pointee changes no output anywhere: every other key and
 * value here is a pointer to an integer or a struct, where the pointee's
 * size is the right answer. The element type is u32 on purpose, so the
 * wrong answer is 4 and not 8. */
struct {
    int (*type)[BPF_MAP_TYPE_HASH];
    int (*max_entries)[16];
    u32 **key;
    u64 *value;
} ptrkey SEC(".maps");

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

/* More of the attribute vocabulary: explicit key_size and value_size rather
 * than key and value types, a nonzero map_flags, and the map kinds whose
 * definitions have a different shape. */
struct {
    int (*type)[BPF_MAP_TYPE_PERF_EVENT_ARRAY];
    int (*key_size)[4];
    int (*value_size)[4];
} perf SEC(".maps");

struct {
    int (*type)[BPF_MAP_TYPE_HASH];
    int (*max_entries)[7];
    int (*map_flags)[1];
    u64 *key;
    struct { char pad[48]; } *value;
} flagged SEC(".maps");

struct inner_map {
    int (*type)[BPF_MAP_TYPE_ARRAY];
    int (*max_entries)[2];
    u32 *key;
    u32 *value;
} inner SEC(".maps");

struct {
    int (*type)[12];           /* ARRAY_OF_MAPS */
    int (*max_entries)[3];
    u32 *key;
    struct inner_map *values[];
} outer SEC(".maps");

SEC("socket/btfmaps2")
int btfmaps2(struct __sk_buff *skb)
{
    u32 k = skb->len;
    void *a = bpf_map_lookup_elem(&perf, &k);
    void *b = bpf_map_lookup_elem(&flagged, &k);
    void *c = bpf_map_lookup_elem(&outer, &k);
    return (a != 0) + (b != 0) + (c != 0);
}
