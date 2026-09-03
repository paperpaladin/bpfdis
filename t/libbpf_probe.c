/* What libbpf itself makes of an object file.
 *
 * libbpf is the loader every BPF toolchain uses, and it reads maps and
 * programs out of an ELF object without any privilege: bpf_object__open_file
 * parses, bpf_object__load is what needs the kernel, and this never calls it.
 * That makes it a real external authority for the map table and the program
 * list, which nothing else installed here can supply. bpftool has it compiled
 * in but only exposes map names, through `gen skeleton`.
 *
 * There are no libbpf headers on this machine, only libbpf.so.1, so the
 * twenty entry points used here are declared from the published API and resolved
 * with dlopen. A missing or renamed symbol is reported and exits 2, never
 * silently skipped: a probe that prints nothing would be counted as a clean
 * run by anything reading its exit status.
 *
 * Output, one line per record:
 *   map <name> type=<n> key_size=<n> value_size=<n> max_entries=<n>
 *       flags=<n> btf_key=<n> btf_value=<n> extra=<n> numa=<n> pin=<path>
 *   prog <name> sec=<section> type=<n> eat=<n> insns=<n>
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void *lib;

static void *sym(const char *n)
{
    void *p = dlsym(lib, n);
    if (!p) {
        fprintf(stderr, "libbpf_probe: libbpf.so.1 has no symbol %s\n", n);
        exit(2);
    }
    return p;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: libbpf_probe FILE.o\n");
        return 2;
    }
    lib = dlopen("libbpf.so.1", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "libbpf_probe: %s\n", dlerror());
        return 2;
    }
    void *(*open_file)(const char *, const void *) = sym("bpf_object__open_file");
    void (*close_obj)(void *) = sym("bpf_object__close");
    void *(*next_map)(const void *, const void *) = sym("bpf_object__next_map");
    const char *(*map_name)(const void *) = sym("bpf_map__name");
    int (*map_type)(const void *) = sym("bpf_map__type");
    uint32_t (*map_key_size)(const void *) = sym("bpf_map__key_size");
    uint32_t (*map_value_size)(const void *) = sym("bpf_map__value_size");
    uint32_t (*map_max_entries)(const void *) = sym("bpf_map__max_entries");
    uint32_t (*map_flags)(const void *) = sym("bpf_map__map_flags");
    uint32_t (*map_btf_key)(const void *) = sym("bpf_map__btf_key_type_id");
    uint32_t (*map_btf_val)(const void *) = sym("bpf_map__btf_value_type_id");
    uint64_t (*map_extra)(const void *) = sym("bpf_map__map_extra");
    uint32_t (*map_numa)(const void *) = sym("bpf_map__numa_node");
    const char *(*map_pin)(const void *) = sym("bpf_map__pin_path");
    void *(*next_prog)(const void *, const void *) = sym("bpf_object__next_program");
    const char *(*prog_name)(const void *) = sym("bpf_program__name");
    const char *(*prog_sec)(const void *) = sym("bpf_program__section_name");
    int (*prog_type)(const void *) = sym("bpf_program__type");
    int (*prog_eat)(const void *) = sym("bpf_program__expected_attach_type");
    size_t (*prog_insn_cnt)(const void *) = sym("bpf_program__insn_cnt");

    void *obj = open_file(argv[1], NULL);
    /* libbpf returns an error encoded in the pointer rather than NULL. */
    if (!obj || (unsigned long)obj >= (unsigned long)-4095L) {
        fprintf(stderr, "libbpf_probe: cannot open %s\n", argv[1]);
        return 1;
    }
    for (void *m = next_map(obj, NULL); m; m = next_map(obj, m))
        printf("map %s type=%d key_size=%u value_size=%u max_entries=%u flags=%u"
               " btf_key=%u btf_value=%u extra=%llu numa=%u pin=%s\n",
               map_name(m), map_type(m), map_key_size(m), map_value_size(m),
               map_max_entries(m), map_flags(m), map_btf_key(m), map_btf_val(m),
               (unsigned long long)map_extra(m), map_numa(m),
               map_pin(m) ? map_pin(m) : "-");
    for (void *p = next_prog(obj, NULL); p; p = next_prog(obj, p))
        printf("prog %s sec=%s type=%d eat=%d insns=%zu\n", prog_name(p),
               prog_sec(p), prog_type(p), prog_eat(p), prog_insn_cnt(p));
    close_obj(obj);
    return 0;
}
