/* CO-RE relocations: one of every kind the decoder can name.
 *
 * Nothing else in the corpus produces a single `core_relo` record, so
 * without this file a third of .BTF.ext is decoded and never exercised.
 * The builtins below are what libbpf's CO-RE macros expand to, used
 * directly because bpf_core_read.h is not installed here.
 *
 * The second argument of each builtin picks the relocation kind, so the 13
 * kinds in src/btfext.rs are reached by construction rather than by luck,
 * and the suite asserts that every one of them turns up.
 *
 * The values these compute are nonsense: `(struct outer *)0` is never
 * dereferenced, the builtins are constant-folded by the loader rather than
 * by clang, and nothing here would do anything useful if it ran. This file
 * is a source of relocation records, not a program.
 */
#include "bpf.h"

#define CORE __attribute__((preserve_access_index))

struct inner {
    u32 a;
    u32 b : 3;
    u32 c : 5;
} CORE;

struct outer {
    u32 x;
    struct inner in;
    u32 arr[4];
    signed int s;
} CORE;

enum colour { RED = 1, GREEN = 2, BLUE = 4 };

SEC("socket/corefield")
int corefield(struct outer *o)
{
    /* The plain accesses: clang emits a FIELD_BYTE_OFFSET for each. */
    return (int)(o->x + o->in.a + o->arr[2] + o->in.b);
}

SEC("socket/coreinfo")
int coreinfo(struct outer *o)
{
    u64 r = 0;
    r += __builtin_preserve_field_info(o->x, 0);    /* BYTE_OFFSET  */
    r += __builtin_preserve_field_info(o->x, 1);    /* BYTE_SIZE    */
    r += __builtin_preserve_field_info(o->x, 2);    /* EXISTS       */
    r += __builtin_preserve_field_info(o->s, 3);    /* SIGNED       */
    r += __builtin_preserve_field_info(o->in.b, 4); /* LSHIFT_U64   */
    r += __builtin_preserve_field_info(o->in.c, 5); /* RSHIFT_U64   */
    return (int)r;
}

SEC("socket/coretype")
int coretype(void *ctx)
{
    u64 r = 0;
    r += __builtin_btf_type_id(*(struct outer *)0, 0);      /* ID_LOCAL  */
    r += __builtin_btf_type_id(*(struct outer *)0, 1);      /* ID_TARGET */
    r += __builtin_preserve_type_info(*(struct inner *)0, 0); /* EXISTS  */
    r += __builtin_preserve_type_info(*(struct inner *)0, 1); /* SIZE    */
    r += __builtin_preserve_type_info(*(struct inner *)0, 2); /* MATCHES */
    return (int)r;
}

SEC("socket/coreenum")
int coreenum(void *ctx)
{
    u64 r = 0;
    r += __builtin_preserve_enum_value(*(enum colour *)GREEN, 0); /* EXISTS */
    r += __builtin_preserve_enum_value(*(enum colour *)BLUE, 1);  /* VALUE  */
    return (int)r;
}

LICENSE("GPL");
