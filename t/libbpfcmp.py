#!/usr/bin/env python3
"""Compare bpfdis's maps and programs against libbpf's own.

libbpf is the loader every BPF toolchain uses. `bpf_object__open_file`
parses an ELF object without any privilege at all -- it is
`bpf_object__load` that needs the kernel, and t/libbpf_probe.c never calls
it. So the map table and the program list have a real external authority
even on a machine where nothing can be loaded.

One thing this cannot check, recorded in the README rather than papered
over: libbpf 1.0 removed support for legacy `maps` sections, so it refuses
those objects outright. An object libbpf refuses for any other reason
contributes nothing either; the count of objects it could open is printed
so a silent collapse to zero is visible.

The legacy maps are checked against the only thing left, which is the
source they were compiled from. `legacy_decls` reads the
`struct bpf_map_def` initialisers out of t/corpus/maps.c and requires
bpfdis to read back what was written. That is weaker than everything else
in this file and it is not nothing: clang laid the struct out, bpfdis read
it back, and the five fields are all the same width, so a reader that
takes them in the wrong order gets no warning from anywhere else. The
mutation that swaps two of them survived the entire suite before this
existed.
"""
import re
import subprocess
import sys

MAXSHOW = 20
MAPRE = re.compile(
    r"^map (\S+) type=(\d+) key_size=(\d+) value_size=(\d+) "
    r"max_entries=(\d+) flags=(\d+) btf_key=(\d+) btf_value=(\d+)$"
)
PROGRE = re.compile(
    r"^prog (\S+) sec=(\S+) type=(-?\d+) eat=(-?\d+) insns=(\d+)$")
LEGACY = re.compile(
    r"struct\s+bpf_map_def\s+(\w+)\s+SEC\(\"maps\"\)\s*=\s*\{([^}]*)\}")
FIELD = re.compile(r"\.(\w+)\s*=\s*([A-Za-z_0-9]+)")
OURMAP = re.compile(
    r"^map (\S+) source=(\S+) type=(\d+) \(\S+\) key_size=(\d+) "
    r"value_size=(\d+) max_entries=(\d+) flags=(\d+) btf_key=(\d+) "
    r"btf_value=(\d+)$"
)
OURPROG = re.compile(
    r"^prog (\S+) sec=(\S+) type=(\d+) \(\S+\) attach=(-?\d+) \(\S+\) "
    r"insns=(\d+)$")
# The section-name table lives in the Rust source and is read back out of it
# here. Deriving the row list from the code rather than restating it means a
# row added without a program in t/corpus/sections.c to reach it turns the
# suite red, instead of sitting in the table with nothing checking it.
TABLEROW = re.compile(
    r'^\s*\("([^"]+)",\s*(true|false),\s*(\d+),\s*"([A-Z_0-9]+)",\s*(-?\d+)\),$')


def legacy_decls(src):
    """{name: (type, key_size, value_size, max_entries, flags)} from the C."""
    names = {
        "BPF_MAP_TYPE_HASH": 1,
        "BPF_MAP_TYPE_ARRAY": 2,
        "BPF_MAP_TYPE_PERF_EVENT_ARRAY": 4,
    }
    out = {}
    text = open(src).read()
    for m in LEGACY.finditer(text):
        f = {}
        for k, v in FIELD.findall(m.group(2)):
            f[k] = names.get(v, None) if not v.isdigit() else int(v)
        out[m.group(1)] = (
            f.get("type"), f.get("key_size", 0), f.get("value_size", 0),
            f.get("max_entries", 0), f.get("map_flags", 0),
        )
    return out


def core_name(n):
    """Undo libbpf's naming of the three core data-section maps.

    libbpf calls them `<object>.data`, `<object>.rodata` and `<object>.bss`,
    where the object name comes from the path the file was opened from and
    is truncated to fit a 16-byte field. That is a fact about the file name,
    not about the object, so the comparison is on the section instead and
    this is the only thing it throws away. Sections with their own suffix
    (`.data.one`, `.rodata.str1.1`) keep their names in libbpf too and are
    compared unchanged.
    """
    for sfx in (".data", ".rodata", ".bss"):
        if n.endswith(sfx) and n != sfx:
            return sfx
    return n


def table_rows(src):
    """[(name, exact, type, type name)] read out of src/prog.rs."""
    rows = []
    inside = False
    for line in open(src):
        if line.startswith("pub const SEC_TYPES"):
            inside = True
            continue
        if inside:
            if line.startswith("]"):
                break
            m = TABLEROW.match(line)
            if m:
                rows.append((m.group(1), m.group(2) == "true",
                             int(m.group(3)), m.group(4), int(m.group(5))))
    return rows


def matches(sec, row):
    """The rule prog_type uses: exact, or, for a prefix row, name then '/'."""
    name, exact = row[0], row[1]
    return sec == name or (not exact and sec.startswith(name + "/"))


def main():
    probe, bpfdis, src, csrc = (sys.argv[1], sys.argv[2], sys.argv[3],
                                sys.argv[4])
    objs = sys.argv[5:]
    want_legacy = legacy_decls(csrc)
    legacy_cmp = legacy_differ = 0
    opened = refused = 0
    maps_cmp = maps_differ = progs_cmp = progs_differ = 0
    reached = set()
    bad = []
    for obj in objs:
        # bpfdis first, and unconditionally: the legacy maps live in the
        # objects libbpf refuses, so checking them after the refusal
        # `continue` below compared nothing and said so by printing zero.
        q = subprocess.run([bpfdis, "-m", "-P", obj], capture_output=True, text=True)
        for l in q.stdout.splitlines():
            m = OURMAP.match(l)
            if m and m.group(2) == "legacy":
                got = tuple(int(m.group(i)) for i in (3, 4, 5, 6, 7))
                want = want_legacy.get(m.group(1))
                if want is not None:
                    legacy_cmp += 1
                    if got != want:
                        legacy_differ += 1
                        bad.append("%s legacy map %s: the source declares %r, "
                                   "bpfdis reads %r"
                                   % (obj.split("/")[-1], m.group(1), want, got))
        p = subprocess.run([probe, obj], capture_output=True, text=True)
        if p.returncode == 2:
            print("libbpfcmp: probe failed: %s" % p.stderr.strip(), file=sys.stderr)
            return 2
        if p.returncode != 0:
            refused += 1
            continue
        opened += 1
        want_maps, want_progs = [], []
        for l in p.stdout.splitlines():
            m = MAPRE.match(l)
            if m:
                want_maps.append(
                    (core_name(m.group(1)),) + tuple(int(x) for x in m.groups()[1:])
                )
                continue
            m = PROGRE.match(l)
            if m:
                want_progs.append((m.group(1), m.group(2), int(m.group(3)),
                                   int(m.group(4)), int(m.group(5))))
        got_maps, got_progs = [], []
        for l in q.stdout.splitlines():
            m = OURMAP.match(l)
            if m and m.group(2) in ("btf", "section"):
                got_maps.append(
                    (m.group(1), int(m.group(3)), int(m.group(4)),
                     int(m.group(5)), int(m.group(6)), int(m.group(7)),
                     int(m.group(8)), int(m.group(9)))
                )
                continue
            m = OURPROG.match(l)
            if m:
                # libbpf reports 0 for both "no attach type" and for
                # cgroup_inet_ingress, which is attach type 0. bpfdis keeps
                # them apart with -1, so -1 is mapped back before comparing;
                # the distinction is ours and the oracle cannot see it.
                got_progs.append((m.group(1), m.group(2), int(m.group(3)),
                                  max(int(m.group(4)), 0), int(m.group(5))))
                reached.add(m.group(2))
        name = obj.split("/")[-1]
        for what, want, got in (
            ("maps", sorted(want_maps), sorted(got_maps)),
            ("progs", sorted(want_progs), sorted(got_progs)),
        ):
            n = max(len(want), len(got))
            if what == "maps":
                maps_cmp += len(want)
            else:
                progs_cmp += len(want)
            for i in range(n):
                a = want[i] if i < len(want) else None
                b = got[i] if i < len(got) else None
                if a != b:
                    if what == "maps":
                        maps_differ += 1
                    else:
                        progs_differ += 1
                    if len(bad) < MAXSHOW:
                        bad.append("%s %s:\n    libbpf %r\n    bpfdis %r"
                                   % (name, what, a, b))
    print("libbpf_opened=%d" % opened)
    print("libbpf_refused=%d" % refused)
    print("maps_compared=%d" % maps_cmp)
    print("maps_differ=%d" % maps_differ)
    print("progs_compared=%d" % progs_cmp)
    print("progs_differ=%d" % progs_differ)
    # Every row of the table must be reached by a section in the corpus, or
    # it is an entry with no oracle. The longest-match rule means a row can
    # be shadowed by a longer one, so a row counts as reached only when
    # prog_type would actually have picked it.
    rows = table_rows(src)
    unreached = []
    for row in rows:
        hit = False
        for sec in reached:
            if not matches(sec, row):
                continue
            best = max((r[0] for r in rows if matches(sec, r)), key=len)
            if best == row[0]:
                hit = True
                break
        if not hit:
            unreached.append(row[0])
    # prog_type returns the FIRST matching row, which is only right while no
    # two rows can match one name. That is a property of the table, so it is
    # asserted over every section the corpus holds rather than assumed: a row
    # added later that shadows another turns this red instead of quietly
    # making the answer depend on the order of the array.
    ambiguous = []
    for sec in sorted(reached):
        hits = [r[0] for r in rows if matches(sec, r)]
        if len(hits) > 1:
            ambiguous.append("%s matches %d table rows: %s"
                             % (sec, len(hits), ", ".join(hits)))
    print("legacy_compared=%d" % legacy_cmp)
    print("legacy_differ=%d" % legacy_differ)
    print("sectype_rows=%d" % len(rows))
    print("sectype_unreached=%d" % len(unreached))
    print("sectype_ambiguous=%d" % len(ambiguous))
    for u in unreached:
        bad.append("section-name table row %r is reached by no corpus section"
                   % u)
    bad.extend(ambiguous)
    for b in bad:
        print("  " + b)
    return 1 if (maps_differ or progs_differ or maps_cmp == 0
                 or progs_cmp == 0 or unreached or ambiguous or not rows
                 or legacy_differ or legacy_cmp == 0) else 0


if __name__ == "__main__":
    sys.exit(main())
