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

MAXSHOW = 20


def run(*cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout


SEC_RE = re.compile(
    r"^\s*\[\s*(\d+)\]\s+(?:(\S+)\s+)?(\S+)\s+([0-9a-f]{16})\s+([0-9a-f]{6})\s+"
    r"([0-9a-f]{6})\s+([0-9a-f]{2})\s+(?:([A-Za-z]+)\s+)?(\d+)\s+(\d+)\s+(\d+)\s*$"
)


def readelf_sections(obj):
    out = []
    for line in run("readelf", "-SW", obj).splitlines():
        m = SEC_RE.match(line)
        if not m:
            continue
        nr, name, typ, addr, off, size, es, flg, lk, inf, al = m.groups()
        out.append(
            (
                int(nr),
                name or "-",
                typ,
                int(addr, 16),
                int(off, 16),
                int(size, 16),
                flg or "-",
                int(lk),
                int(inf),
                int(al),
                int(es, 16),
            )
        )
    return out


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


SYM_RE = re.compile(
    r"^\s*(\d+):\s+([0-9a-f]{16})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)\s*$"
)


def readelf_symbols(obj):
    out = []
    started = False
    for line in run("readelf", "-sW", obj).splitlines():
        if line.startswith("Symbol table '.symtab'"):
            started = True
            continue
        if not started:
            continue
        m = SYM_RE.match(line)
        if not m:
            continue
        num, val, size, typ, bind, _vis, ndx, name = m.groups()
        if ndx == "COM":
            ndx = "COMMON"
        out.append((int(num), name or "-", typ, bind, ndx, int(val, 16), int(size)))
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


REL_HDR = re.compile(r"^Relocation section '(\S+)'")
REL_RE = re.compile(
    r"^([0-9a-f]{16})\s+([0-9a-f]{16})\s+(\S+)\s+([0-9a-f]{16})\s*(\S*)\s*$"
)


def readelf_relocs(obj):
    out = []
    sec = None
    for line in run("readelf", "-rW", obj).splitlines():
        m = REL_HDR.match(line)
        if m:
            sec = m.group(1)
            for pre in (".rela", ".rel"):
                if sec.startswith(pre):
                    sec = sec[len(pre):]
                    break
            continue
        m = REL_RE.match(line)
        if m and sec is not None:
            off, info, typ, _symval, name = m.groups()
            out.append((sec, int(off, 16), typ, name or "-"))
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
