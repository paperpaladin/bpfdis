#!/usr/bin/env python3
"""Compare bpfdis's maps and programs against libbpf's own.

libbpf is the loader every BPF toolchain uses. `bpf_object__open_file`
parses an ELF object without any privilege at all -- it is
`bpf_object__load` that needs the kernel, and t/libbpf_probe.c never calls
it. So the map table and the program list have a real external authority
even on a machine where nothing can be loaded.

Two things this cannot check, both recorded in the README rather than
papered over. libbpf 1.0 removed support for legacy `maps` sections, so it
refuses those objects outright and bpfdis's legacy map reader has no oracle.
And an object libbpf refuses for any other reason contributes nothing; the
count of objects it could open is printed so a silent collapse to zero is
visible.
"""
import re
import subprocess
import sys

MAXSHOW = 20
MAPRE = re.compile(
    r"^map (\S+) type=(\d+) key_size=(\d+) value_size=(\d+) "
    r"max_entries=(\d+) flags=(\d+)$"
)
PROGRE = re.compile(r"^prog (\S+) sec=(\S+) type=(-?\d+) insns=(\d+)$")
OURMAP = re.compile(
    r"^map (\S+) source=(\S+) type=(\d+) \(\S+\) key_size=(\d+) "
    r"value_size=(\d+) max_entries=(\d+) flags=(\d+)$"
)
OURPROG = re.compile(r"^prog (\S+) sec=(\S+) insns=(\d+)$")


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


def main():
    probe, bpfdis = sys.argv[1], sys.argv[2]
    objs = sys.argv[3:]
    opened = refused = 0
    maps_cmp = maps_differ = progs_cmp = progs_differ = 0
    bad = []
    for obj in objs:
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
                want_progs.append((m.group(1), m.group(2), int(m.group(4))))
        q = subprocess.run([bpfdis, "-m", "-P", obj], capture_output=True, text=True)
        got_maps, got_progs = [], []
        for l in q.stdout.splitlines():
            m = OURMAP.match(l)
            if m and m.group(2) in ("btf", "section"):
                got_maps.append(
                    (m.group(1), int(m.group(3)), int(m.group(4)),
                     int(m.group(5)), int(m.group(6)), int(m.group(7)))
                )
                continue
            m = OURPROG.match(l)
            if m:
                got_progs.append((m.group(1), m.group(2), int(m.group(3))))
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
    for b in bad:
        print("  " + b)
    return 1 if (maps_differ or progs_differ or maps_cmp == 0 or progs_cmp == 0) else 0


if __name__ == "__main__":
    sys.exit(main())
