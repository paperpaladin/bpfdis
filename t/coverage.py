#!/usr/bin/env python3
"""What the corpus actually contains, counted rather than assumed.

Every comparison in this suite asserts it was non-vacuous in its own
terms: so many instructions, so many map records, so many BTF types. None
of them says which KINDS of thing were present, and a corpus of four
hundred `r0 = 0` instructions satisfies every one of those thresholds
while reaching one opcode.

So this counts the distinct constructs the corpus holds and prints them.
The numbers are floors in `run.sh`, which is the weak part and is the
point: they are there to go red when a corpus source is deleted or a
generator stops emitting something, not to prove the corpus is complete.

It shares the decoder with the thing under test, which is the same
weakness pcapd's construct counter has and for the same reason: a
construct bpfdis cannot see is one this cannot count either, and the pair
would agree the corpus is missing something it holds. The opcode column is
the exception, because it comes from the raw bytes rather than from the
decode.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from readelfp import readelf_relocs, readelf_sections  # noqa: E402

RAW = re.compile(r"^\s*\d+:\t((?:[0-9a-f]{2} )+)")
MAP = re.compile(r"^map \S+ source=(\S+) type=(\d+) \((\S+)\)")
PROG = re.compile(r"^prog \S+ sec=\S+ type=(\d+) \(\S+\) attach=(-?\d+)")
RELO = re.compile(r"^core_relo \S+ slot=\d+ type_id=\d+ kind=(\d+)")
ANALYSIS = re.compile(r"^analysis \S+ \S+ .* helpers=(\S+)$")


def main():
    bpfdis = sys.argv[1]
    objs = sys.argv[2:]
    opcodes = set()
    sectypes = set()
    reltypes = set()
    maptypes = set()
    mapsources = set()
    progtypes = set()
    attachtypes = set()
    helpers = set()
    corekinds = set()
    for obj in objs:
        out = subprocess.run([bpfdis, "-d", "--raw", obj],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            m = RAW.match(line)
            if m:
                opcodes.add(m.group(1).split()[0])
        for _nr, _nm, typ, *_rest in readelf_sections(obj):
            sectypes.add(typ)
        for _sec, _off, typ, _name in readelf_relocs(obj):
            reltypes.add(typ)
        out = subprocess.run([bpfdis, "-m", "-P", "-a", "-e", obj],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            m = MAP.match(line)
            if m:
                mapsources.add(m.group(1))
                maptypes.add(m.group(3))
                continue
            m = PROG.match(line)
            if m:
                progtypes.add(int(m.group(1)))
                attachtypes.add(int(m.group(2)))
                continue
            m = RELO.match(line)
            if m:
                corekinds.add(int(m.group(1)))
                continue
            m = ANALYSIS.match(line)
            if m and m.group(1) != "-":
                for h in m.group(1).split(","):
                    # `5(bpf_ktime_get_ns)`: the number is the construct,
                    # the name is the lookup and is checked elsewhere.
                    helpers.add(h.split("(")[0])
    print("cov_opcodes=%d" % len(opcodes))
    print("cov_section_types=%d" % len(sectypes))
    print("cov_reloc_types=%d" % len(reltypes))
    print("cov_map_types=%d" % len(maptypes))
    print("cov_map_sources=%d" % len(mapsources))
    print("cov_prog_types=%d" % len(progtypes))
    print("cov_attach_types=%d" % len(attachtypes))
    print("cov_helpers=%d" % len(helpers))
    print("cov_core_kinds=%d" % len(corekinds))
    print("  opcodes: " + " ".join(sorted(opcodes)))
    print("  section types: " + " ".join(sorted(sectypes)))
    print("  relocation types: " + " ".join(sorted(reltypes)))
    print("  map types: " + " ".join(sorted(maptypes)))
    print("  map sources: " + " ".join(sorted(mapsources)))
    print("  helper numbers: " + " ".join(sorted(helpers, key=int)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
