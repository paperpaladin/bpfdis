#!/usr/bin/env python3
"""Check bpfdis -e against two other readers of the same facts.

Nothing installed here prints .BTF.ext. bpftool has no subcommand for it,
libbpf parses it but exposes no accessor, and llvm-readelf will only give
the bytes. So the records are checked indirectly, against the two places
the same information exists in another form:

func_info says which BTF type each program is. The type id must name a
KIND_FUNC record whose name is the ELF symbol at that instruction offset.
bpftool btf dump supplies the type names and readelf supplies the symbols,
so neither half comes from bpfdis.

line_info says which source line each instruction came from, and so does
DWARF, which clang emits from the same front end but through a different
back end and a different section. `llvm-objdump -dl` prints the DWARF
answer against the same instruction indices the comparison already uses.

The two disagree in one place on purpose and it is counted separately
rather than smoothed over: at the first instruction of a function BTF.ext
records the line of the declaration and DWARF records the line of the
opening brace.
"""
import os
import re
import subprocess
import sys

MAXSHOW = 20

OURFUNC = re.compile(r"^func_info (\S+) slot=(\d+) type_id=(\d+) (.*)$")
OURLINE = re.compile(r"^line_info (\S+) slot=(\d+) (.*):(\d+):(\d+)$")
OURRELO = re.compile(r"^core_relo (\S+) slot=(\d+) type_id=(\d+) kind=(\d+) ")
BTFFUNC = re.compile(r"^\[(\d+)\] FUNC '([^']*)'")
SECLINE = re.compile(r"^Disassembly of section (.*):\s*$")
SRCLINE = re.compile(r"^; (/.*):(\d+)$")
SLOT = re.compile(r"^\s*(\d+):\s*$")


def ours(bpfdis, obj):
    p = subprocess.run([bpfdis, "-e", obj], capture_output=True, text=True)
    funcs, lines, relos = [], [], []
    for l in p.stdout.splitlines():
        m = OURFUNC.match(l)
        if m:
            funcs.append((m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)))
            continue
        m = OURLINE.match(l)
        if m:
            lines.append((m.group(1), int(m.group(2)), m.group(3),
                          int(m.group(4)), int(m.group(5))))
            continue
        m = OURRELO.match(l)
        if m:
            relos.append((m.group(1), int(m.group(2)), int(m.group(3)),
                          int(m.group(4))))
    return funcs, lines, relos, p.returncode


def btf_funcs(obj):
    """{type id: name} for every KIND_FUNC, from bpftool."""
    out = {}
    p = subprocess.run(["/usr/sbin/bpftool", "btf", "dump", "file", obj],
                       capture_output=True, text=True)
    for l in p.stdout.splitlines():
        m = BTFFUNC.match(l.strip())
        if m:
            out[int(m.group(1))] = m.group(2)
    return out


def elf_funcs(obj):
    """{(section, slot): name} for every STT_FUNC symbol, from readelf."""
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    from readelfp import readelf_sections, readelf_symbols
    secname = {nr: nm for nr, nm, *_ in readelf_sections(obj)}
    out = {}
    for _num, name, typ, _bind, ndx, value, _size in readelf_symbols(obj):
        if typ == "FUNC" and ndx.isdigit():
            out[(secname.get(int(ndx)), value // 8)] = name
    return out


def dwarf_lines(obj):
    """{(section, slot): (file, line)} from llvm-objdump's DWARF annotation."""
    p = subprocess.run(["llvm-objdump", "-dl", "--triple=bpf", obj],
                       capture_output=True, text=True)
    out = {}
    sec = None
    cur = None
    for line in p.stdout.splitlines():
        m = SECLINE.match(line)
        if m:
            sec, cur = m.group(1), None
            continue
        m = SRCLINE.match(line)
        if m:
            cur = (m.group(1), int(m.group(2)))
            continue
        parts = line.split("\t")
        if len(parts) >= 3 and sec is not None:
            m = SLOT.match(parts[0])
            if m and cur is not None:
                out[(sec, int(m.group(1)))] = cur
    return out


def main():
    bpfdis = sys.argv[1]
    objs = sys.argv[2:]
    objs_with = 0
    f_cmp = f_differ = 0
    l_cmp = l_differ = l_entry = l_nodwarf = 0
    r_cmp = 0
    bad = []
    for obj in objs:
        name = obj.split("/")[-1]
        funcs, lines, relos, rc = ours(bpfdis, obj)
        if rc != 0:
            bad.append("%s: bpfdis -e exited %d" % (name, rc))
            continue
        if not funcs and not lines and not relos:
            continue
        objs_with += 1
        types = btf_funcs(obj)
        syms = elf_funcs(obj)
        for sec, slot, tid, tname in funcs:
            f_cmp += 1
            want = types.get(tid)
            sym = syms.get((sec, slot))
            if want is None:
                f_differ += 1
                if len(bad) < MAXSHOW:
                    bad.append("%s %s[%d]: type_id %d is not a FUNC in bpftool's dump"
                               % (name, sec, slot, tid))
            elif want != tname:
                f_differ += 1
                if len(bad) < MAXSHOW:
                    bad.append("%s %s[%d]: bpfdis names type %d %r, bpftool says %r"
                               % (name, sec, slot, tid, tname, want))
            elif sym != want:
                f_differ += 1
                if len(bad) < MAXSHOW:
                    bad.append("%s %s[%d]: func_info says %r, the ELF symbol there "
                               "is %r" % (name, sec, slot, want, sym))
        dw = dwarf_lines(obj)
        entries = {(s, sl) for s, sl, _t, _n in funcs}
        for sec, slot, f, ln, _col in lines:
            got = dw.get((sec, slot))
            if got is None:
                l_nodwarf += 1
                continue
            if (sec, slot) in entries or slot == 0:
                # The declaration line against the opening brace. Counted,
                # and required to be the declaration: a BTF line AFTER the
                # DWARF one would be a different bug wearing the same shape.
                l_entry += 1
                if not (f == got[0] and ln <= got[1]):
                    l_differ += 1
                    if len(bad) < MAXSHOW:
                        bad.append("%s %s[%d]: function entry at %s:%d, DWARF says "
                                   "%s:%d, which is not the declaration before the "
                                   "brace" % (name, sec, slot, f, ln, got[0], got[1]))
                continue
            l_cmp += 1
            if (f, ln) != got:
                l_differ += 1
                if len(bad) < MAXSHOW:
                    bad.append("%s %s[%d]: line_info says %s:%d, DWARF says %s:%d"
                               % (name, sec, slot, f, ln, got[0], got[1]))
        r_cmp += len(relos)
    print("btfext_objects=%d" % objs_with)
    print("func_info_compared=%d" % f_cmp)
    print("func_info_differ=%d" % f_differ)
    print("line_info_compared=%d" % l_cmp)
    print("line_info_differ=%d" % l_differ)
    print("line_info_entry=%d" % l_entry)
    print("line_info_no_dwarf=%d" % l_nodwarf)
    print("core_relo_records=%d" % r_cmp)
    for b in bad:
        print("  " + b)
    return 1 if (f_differ or l_differ or f_cmp == 0 or l_cmp == 0) else 0


if __name__ == "__main__":
    sys.exit(main())
