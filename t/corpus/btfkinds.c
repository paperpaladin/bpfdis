/* Every BTF kind clang will emit, so the BTF decoder has an oracle for each
 * rather than for the three a simple program happens to use. */
#include "bpf.h"

enum colour { RED = -1, GREEN = 0, BLUE = 7 };
enum big64 : unsigned long long { LOW = 1, HIGH = 0x100000000ull };
union both { u32 a; float f; double d; };
struct bits { u32 x : 3; u32 y : 5; int z; };
struct fwd_decl;
typedef const volatile u64 cvu64;

struct node {
    struct fwd_decl *fwd;
    union both u;
    struct bits b;
    enum colour c;
    enum big64 e;
    cvu64 t;
    float f;
    double d;
    char name[8];
    const char *restrict cp;
    int (*fn)(int, long);
};

struct node global_node SEC(".data.node");
const int ro_const SEC(".rodata.k") = 42;

/* A static variable and a static function give the other linkage values;
 * decl_tag and type_tag are the two kinds nothing else here reaches. */
static volatile int static_counter SEC(".data.cnt") = 1;
extern int extern_thing;

#define __tag(x) __attribute__((btf_decl_tag(x)))
struct tagged { int field; } __tag("a-decl-tag");
struct tagged tagged_var SEC(".data.tag");

typedef int __attribute__((btf_type_tag("a-type-tag"))) * tagged_ptr;
tagged_ptr tp SEC(".data.tp");

static __attribute__((noinline)) int helper_static(int a)
{
    return a + static_counter;
}

__attribute__((noinline)) int consume(struct node *n, int k)
{
    return (int)(n->t + k + n->c) + helper_static(k) + extern_thing;
}

SEC("socket/kinds")
int kinds(struct __sk_buff *skb)
{
    global_node.b.z = (int)skb->len;
    return consume(&global_node, (int)skb->mark);
}

LICENSE("GPL");
