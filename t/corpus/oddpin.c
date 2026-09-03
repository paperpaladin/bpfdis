/* A pinning value libbpf refuses the whole object for.
 *
 * LIBBPF_PIN_NONE is 0 and LIBBPF_PIN_BY_NAME is 1, and `bpf_object__open`
 * fails with "invalid pinning value 2" rather than reading the rest of the
 * file. bpfdis reads files nothing will load, so it keeps going and says
 * what is wrong; this object is here so that the saying is tested and so
 * that the refusal is measured rather than assumed.
 */
#include "bpf.h"

struct {
    int (*type)[BPF_MAP_TYPE_HASH];
    int (*max_entries)[4];
    int (*pinning)[2];
    u32 *key;
    u32 *value;
} oddpin SEC(".maps");

LICENSE("GPL");
