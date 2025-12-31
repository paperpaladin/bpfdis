#!/usr/bin/env python3
"""Compare bpfdis's ELF view against readelf, record by record.

readelf is GNU binutils and shares no code with LLVM or with this program, so
it is the one place in this repository where an entirely independent codebase
checks the parse. The comparison is on extracted fields, never on text: the
two formats have nothing in common and diffing them would measure rendering.

Prints one line per facet:

    FACET total=N mismatches=M

and exits 1 if any facet has a mismatch or a zero total.
"""
import re
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from readelfp import (  # noqa: E402
    readelf_relocs, readelf_sections, readelf_symbols, run,
)

MAXSHOW = 20


OURSEC_RE = re.compile(
    r"^\[\s*(\d+)\] name=(\S+) type=(\S+) flags=(\S+) addr=(\S+) off=(\S+) "
    r"size=(\S+) link=(\d+) info=(\d+) align=(\d+) entsize=(\d+)$"
)


def ours_sections(text):
    out = []
    for line in text.splitlines():
        m = OURSEC_RE.match(line)
        if not m:
            continue
        nr, name, typ, flg, addr, off, size, lk, inf, al, es = m.groups()
        out.append(
            (
                int(nr),
                name,
                typ,
                int(addr, 16),
                int(off, 16),
                int(size, 16),
                flg,
                int(lk),
                int(inf),
                int(al),
                int(es),
            )
        )
    return out


OURSYM_RE = re.compile(
    r"^\[\s*(\d+)\] name=(\S+) type=(\S+) bind=(\S+) shndx=(\S+) value=(\S+) size=(\S+)$"
)


def ours_symbols(text):
    out = []
    for line in text.splitlines():
        m = OURSYM_RE.match(line)
        if not m:
            continue
        num, name, typ, bind, ndx, val, size = m.groups()
        out.append((int(num), name, typ, bind, ndx, int(val, 16), int(size, 16)))
    return out


OURREL_RE = re.compile(r"^sec=(\S+) off=(\S+) type=(\S+) sym=(\S+) addend=(-?\d+)$")


def ours_relocs(text):
    out = []
    for line in text.splitlines():
        m = OURREL_RE.match(line)
        if m:
            sec, off, typ, sym, _add = m.groups()
            out.append((sec, int(off, 16), typ, sym))
    return out


def main():
    bpfdis = sys.argv[1]
    objs = sys.argv[2:]
    if not objs:
        print("elfcmp: no objects given", file=sys.stderr)
        return 2
    facets = {"sections": [0, 0], "symbols": [0, 0], "relocs": [0, 0]}
    bad = []
    for obj in objs:
        text = run(bpfdis, "-S", "-y", "-r", obj)
        pairs = [
            ("sections", readelf_sections(obj), ours_sections(text)),
            ("symbols", readelf_symbols(obj), ours_symbols(text)),
            ("relocs", readelf_relocs(obj), ours_relocs(text)),
        ]
        for name, want, got in pairs:
            facets[name][0] += len(want)
            if len(want) != len(got):
                facets[name][1] += abs(len(want) - len(got))
                bad.append(
                    "%s %s: readelf has %d records, bpfdis has %d"
                    % (obj.split("/")[-1], name, len(want), len(got))
                )
                continue
            for w, g in zip(want, got):
                if w != g:
                    facets[name][1] += 1
                    bad.append(
                        "%s %s:\n    readelf %r\n    bpfdis  %r"
                        % (obj.split("/")[-1], name, w, g)
                    )
    rc = 0
    for name in ("sections", "symbols", "relocs"):
        total, mis = facets[name]
        print("%s total=%d mismatches=%d" % (name, total, mis))
        if mis or total == 0:
            rc = 1
    for b in bad[:MAXSHOW]:
        print("  " + b)
    if len(bad) > MAXSHOW:
        print("  ... and %d more" % (len(bad) - MAXSHOW))
    return rc


if __name__ == "__main__":
    sys.exit(main())
