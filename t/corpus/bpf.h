/* Hermetic BPF declarations.
 *
 * Neither <linux/bpf.h> for the BPF target nor libbpf's bpf_helpers.h is
 * installed here, and <linux/bpf.h> pulls in <asm/types.h> which does not
 * exist for the bpf triple. Everything the corpus needs is declared below so
 * the corpus compiles from this tree alone. */
#ifndef BPFDIS_CORPUS_BPF_H
#define BPFDIS_CORPUS_BPF_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef short s16;
typedef int s32;
typedef long long s64;

/* The prefix of struct __sk_buff that matters for the corpus. The real one is
 * longer; a load from any of these offsets is a context load either way. */
struct __sk_buff {
    u32 len;
    u32 pkt_type;
    u32 mark;
    u32 queue_mapping;
    u32 protocol;
    u32 vlan_present;
    u32 vlan_tci;
    u32 vlan_proto;
    u32 priority;
    u32 ingress_ifindex;
    u32 ifindex;
    u32 tc_index;
    u32 cb[5];
    u32 hash;
    u32 tc_classid;
    u32 data;
    u32 data_end;
};

/* Helper ids are the kernel's, from include/uapi/linux/bpf.h. Calling them
 * through a function pointer with a constant address is the pre-libbpf idiom
 * and makes clang emit `call <id>` directly. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
                                   u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read)(void *dst, u32 size, const void *src) = (void *)4;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_trace_printk)(const char *fmt, u32 fmt_size, ...) = (void *)6;
static u32 (*bpf_get_prandom_u32)(void) = (void *)7;
static u32 (*bpf_get_smp_processor_id)(void) = (void *)8;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, u32 offset,
                                   const void *from, u32 len, u64 flags) = (void *)9;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_perf_event_output)(void *ctx, void *map, u64 flags, void *data,
                                     u64 size) = (void *)25;
static long (*bpf_loop)(u32 nr_loops, void *callback_fn, void *callback_ctx,
                        u64 flags) = (void *)181;

struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4

#define SEC(x) __attribute__((section(x), used))
#define LICENSE(x) char _license[] SEC("license") = x

#endif
