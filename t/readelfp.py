"""Parsing readelf's output.

readelf is GNU binutils and shares no code with LLVM or with bpfdis, which
is what makes it worth comparing against. Its output is columnar text, so
the regexes below are anchored on the shapes that cannot move: a sixteen-hex
address, a six-hex offset, a two-hex entry size. The flags column can be
empty and the name column can be empty, which is why both are optional and
the match is allowed to backtrack.
"""
import re
import subprocess


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


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


