#!/usr/bin/env python3
"""A second control-flow graph, built from llvm-objdump's text.

The decoder has LLVM. The graph has almost nothing: llvm-objdump annotates a
branch with the symbol it lands in, which `disasm_cmp.py` already compares,
and that is the only outside statement about control flow anywhere on this
machine. So this is a second implementation rather than an authority, and the
README says so.

What makes it worth more than zero is that it shares no code and no decode
with bpfdis. Instruction lengths come from the raw opcode byte llvm-objdump
prints, branch offsets come from llvm-objdump's own text, and function
boundaries come from readelf's symbol table. If bpfdis's decoder gets a jump
offset wrong, or loses the 16-byte load's second slot, or measures an offset
from the jump rather than from the instruction after it, the two graphs come
out different shapes.

Functions llvm-objdump cannot read in full are skipped and counted, never
silently dropped: it elides a run of zero bytes as a bare "..." and prints
<unknown> for three atomic encodings its own assembler emits, and a function
holding either cannot be reconstructed from its output.
"""
import re
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from readelfp import readelf_sections, readelf_symbols  # noqa: E402

MAXSHOW = 20

# The left column of an llvm-objdump BPF listing is the instruction slot
# index in decimal, not a byte address. The `<sym+0xNN>` annotations on
# branches are byte offsets, which is the trap: reading the one as the other
# divides every index by eight and lands every instruction in slot 0.
ADDR_RE = re.compile(r"^\s*(\d+):\s*$")
SEC_RE = re.compile(r"^Disassembly of section (.*):\s*$")
# `goto +0x3`, `goto -0x8`, `gotol +0x200`, `if r1 > 0x2 goto +0x3`.
GOTO_RE = re.compile(r"\bgotol?\s+([+-])0x([0-9a-f]+)")
MAYGOTO_RE = re.compile(r"\bmay_goto\s+([+-])0x([0-9a-f]+)")


def dump(obj):
    """{section: [(slot, slots, text)]} from llvm-objdump, plus a bad set."""
    p = subprocess.run(
        ["llvm-objdump", "-d", "--triple=bpf", obj], capture_output=True, text=True
    )
    out = {}
    elided = set()
    sec = None
    for line in p.stdout.splitlines():
        m = SEC_RE.match(line)
        if m:
            sec = m.group(1)
            out.setdefault(sec, [])
            continue
        if sec is None:
            continue
        if line.strip() == "...":
            # A run of zero bytes, printed with no instruction lines at all.
            # The slots are missing from the output, so a graph built from it
            # would have holes it cannot see.
            elided.add(sec)
            continue
        # llvm-objdump separates address, raw bytes and text with tabs, so
        # splitting on them is steadier than a regex over the whole line:
        # the text column holds spaces, commas and tabs of its own in some
        # mnemonics and the byte column is a different width for the two
        # instruction lengths.
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        m = ADDR_RE.match(parts[0])
        if not m:
            continue
        slot = int(m.group(1), 10)
        raw = parts[1].split()
        # 0x18 is BPF_LD | BPF_IMM | BPF_DW, the only 16-byte instruction.
        # Taking the length from the opcode rather than from the gap to the
        # next printed address keeps this independent of what bpfdis thinks
        # and works for the last instruction in a section.
        slots = 2 if raw and int(raw[0], 16) == 0x18 else 1
        out.setdefault(sec, []).append((slot, slots, parts[2].strip()))
    return out, elided


def funcs(obj):
    """[(section, name, start_slot, end_slot)] from readelf alone."""
    secname = {}
    secsize = {}
    for nr, name, _t, _a, _o, size, *_rest in readelf_sections(obj):
        secname[nr] = name
        secsize[nr] = size
    out = []
    for _num, name, typ, _bind, ndx, value, size in readelf_symbols(obj):
        if typ != "FUNC" or not ndx.isdigit():
            continue
        sec = secname.get(int(ndx))
        if sec is None:
            continue
        slots = secsize.get(int(ndx), 0) // 8
        start = min(value // 8, slots)
        end = start + size // 8 if size else slots
        out.append((sec, name, start, min(max(end, start), slots)))
    # A symbol with no size runs to the next one, which is what prog.rs does.
    out.sort(key=lambda f: (f[0], f[2]))
    for i, (sec, name, start, end) in enumerate(out):
        for j in range(i + 1, len(out)):
            if out[j][0] != sec:
                break
            if out[j][2] > start:
                end = min(end, out[j][2])
                break
        out[i] = (sec, name, start, max(end, start))
    return out


def target(slot, slots, text):
    """The absolute target slot of a branch, or None."""
    m = GOTO_RE.search(text) or MAYGOTO_RE.search(text)
    if not m:
        return None
    off = int(m.group(2), 16)
    if m.group(1) == "-":
        off = -off
    return slot + slots + off


def classify(text):
    """Exit, Jump, Cond or None, from llvm-objdump's text only."""
    if text == "exit":
        return "Exit"
    if text.startswith("goto ") or text.startswith("gotol "):
        return "Jump"
    if text.startswith("if ") and " goto " in text:
        return "Cond"
    if text.startswith("may_goto "):
        return "Cond"
    return None


def build(insns, start, end):
    """{start_slot: (term, [succ slots])}, reachable set, in that order."""
    at = {s: (s, n, t) for (s, n, t) in insns}
    order = [s for (s, _n, _t) in insns]
    leaders = [start]
    for slot, slots, text in insns:
        kind = classify(text)
        if kind in ("Jump", "Cond"):
            t = target(slot, slots, text)
            # Outside the function is not an edge, and neither is a landing
            # in the second half of a 16-byte load: no instruction starts
            # there, so `at` has no entry for it.
            if t is not None and start <= t < end and t in at:
                leaders.append(t)
        if kind is not None and slot + slots < end:
            leaders.append(slot + slots)
    leaders = sorted({l for l in leaders if l in at})

    blocks = {}
    for i, l in enumerate(leaders):
        nxt = leaders[i + 1] if i + 1 < len(leaders) else end
        body = [s for s in order if l <= s < nxt]
        if not body:
            continue
        last = body[-1]
        _s, slots, text = at[last]
        kind = classify(text)
        succs = []
        if kind == "Exit":
            term = "Exit"
        elif kind == "Jump":
            term = "Jump"
            t = target(last, slots, text)
            if t in leaders:
                succs = [t]
        elif kind == "Cond":
            term = "Cond"
            if last + slots in leaders:
                succs.append(last + slots)
            t = target(last, slots, text)
            if t in leaders and t != last + slots:
                succs.append(t)
        elif last + slots >= end:
            term = "FallsOffEnd"
        else:
            term = "Fall"
            if last + slots in leaders:
                succs = [last + slots]
        blocks[l] = (term, succs, nxt)

    seen = set()
    stack = [start] if start in blocks else []
    while stack:
        b = stack.pop()
        if b in seen:
            continue
        seen.add(b)
        stack.extend(blocks[b][1])
    return blocks, seen


OURCFG = re.compile(
    r"^cfg (\S+) (\S+) blocks=(\d+) edges=(\d+) reachable=(\d+) insns=(\d+)$"
)
OURBLK = re.compile(r"^block (\d+)\.\.(\d+) term=(\S+) reach=(\d+) succs=(\S+)$")


def ours(bpfdis, obj):
    """{(section, function): (header tuple, {start: (term, succs, end, reach)})}"""
    out = {}
    cur = None
    for line in subprocess.run(
        [bpfdis, "-c", obj], capture_output=True, text=True
    ).stdout.splitlines():
        m = OURCFG.match(line)
        if m:
            cur = (m.group(1), m.group(2))
            out[cur] = ((int(m.group(3)), int(m.group(4)), int(m.group(5)),
                         int(m.group(6))), {})
            continue
        m = OURBLK.match(line)
        if m and cur is not None:
            succs = [] if m.group(5) == "-" else [int(x) for x in m.group(5).split(",")]
            out[cur][1][int(m.group(1))] = (
                m.group(3), succs, int(m.group(2)), int(m.group(4))
            )
    return out


def main():
    bpfdis = sys.argv[1]
    objs = sys.argv[2:]
    funcs_cmp = funcs_differ = skipped = blocks_cmp = edges_cmp = 0
    bad = []
    for obj in objs:
        name = obj.split("/")[-1]
        secs, elided = dump(obj)
        mine = ours(bpfdis, obj)
        for sec, fn, start, end in funcs(obj):
            if sec not in secs or sec in elided:
                skipped += 1
                continue
            insns = [(s, n, t) for (s, n, t) in secs[sec] if start <= s < end]
            if not insns or any("<unknown>" in t for (_s, _n, t) in insns):
                skipped += 1
                continue
            want_blocks, want_reach = build(insns, start, end)
            got = mine.get((sec, fn))
            funcs_cmp += 1
            if got is None:
                funcs_differ += 1
                if len(bad) < MAXSHOW:
                    bad.append("%s %s/%s: bpfdis emitted no cfg" % (name, sec, fn))
                continue
            (nb, ne, nr, _ni), gb = got
            blocks_cmp += len(want_blocks)
            edges_cmp += sum(len(v[1]) for v in want_blocks.values())
            problems = []
            if nb != len(want_blocks):
                problems.append("blocks %d vs %d" % (nb, len(want_blocks)))
            if ne != sum(len(v[1]) for v in want_blocks.values()):
                problems.append("edges %d vs %d"
                                % (ne, sum(len(v[1]) for v in want_blocks.values())))
            if nr != len(want_reach):
                problems.append("reachable %d vs %d" % (nr, len(want_reach)))
            for l in sorted(set(want_blocks) | set(gb)):
                w = want_blocks.get(l)
                g = gb.get(l)
                if w is None:
                    problems.append("block at %d only in bpfdis" % l)
                    continue
                if g is None:
                    problems.append("block at %d only in the second graph" % l)
                    continue
                if (w[0], sorted(w[1]), w[2]) != (g[0], sorted(g[1]), g[2]):
                    problems.append(
                        "block %d: %s end=%d succs=%s vs %s end=%d succs=%s"
                        % (l, g[0], g[2], sorted(g[1]), w[0], w[2], sorted(w[1]))
                    )
                if (l in want_reach) != bool(g[3]):
                    problems.append("block %d: reachable %d vs %d"
                                    % (l, g[3], l in want_reach))
            if problems:
                funcs_differ += 1
                if len(bad) < MAXSHOW:
                    bad.append("%s %s/%s: %s" % (name, sec, fn, "; ".join(problems)))
    print("cfg_funcs=%d" % funcs_cmp)
    print("cfg_blocks=%d" % blocks_cmp)
    print("cfg_edges=%d" % edges_cmp)
    print("cfg_differ=%d" % funcs_differ)
    print("cfg_skipped=%d" % skipped)
    for b in bad:
        print("  " + b)
    return 1 if (funcs_differ or funcs_cmp == 0) else 0


if __name__ == "__main__":
    sys.exit(main())
