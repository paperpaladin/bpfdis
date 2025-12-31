#!/usr/bin/env python3
"""Compare bpfdis -d against llvm-objdump, one instruction at a time.

A per-program diff tells you that something disagreed somewhere in four
hundred instructions. This lines the two dumps up by (section, slot index)
and names the opcode of every instruction that differs.

Both tools print the same assembly syntax; only the radix differs, so the
comparison normalises every number to decimal and then compares the strings
whole. Normalising rather than tokenising keeps punctuation, spacing and the
`*(u32 *)` type spellings inside the comparison, which a token list would
throw away.

Buckets, each counted separately and never merged:

    agree         both decoded it, to the same text
    disagree      both decoded it, differently
    we-refuse     llvm-objdump decoded it, bpfdis printed (bad)
    llvm-refuse   bpfdis decoded it, llvm-objdump printed <unknown>
    both-refuse   neither decoded it

A refusal is not a pass. The suite fails on any disagreement; the refusal
counts are printed and checked against expectations written down in run.sh.
"""
import re
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from llvmbpf import assemble, norm, rawbytes  # noqa: E402
from readelfp import SEC_RE, SYM_RE  # noqa: E402

MAXSHOW = 25

def objdump(obj):
    """{section: {index: (bytes, text)}} from llvm-objdump."""
    p = subprocess.run(
        ["llvm-objdump", "-dr", "--triple=bpf", obj], capture_output=True, text=True
    )
    out = {}
    rel = {}
    fns = {}
    ell = set()
    sec = None
    for line in p.stdout.splitlines():
        m = re.match(r"^Disassembly of section (.*):\s*$", line)
        if m:
            sec = m.group(1)
            out.setdefault(sec, {})
            continue
        if sec is None:
            continue
        m = re.match(r"^([0-9a-f]{16}) <(.*)>:\s*$", line)
        if m:
            fns.setdefault(sec, []).append((int(m.group(1), 16) // 8, m.group(2)))
            continue
        # llvm-objdump elides a run of zero bytes as a bare "..." and prints
        # no instruction lines for it at all. That is a rendering choice, not
        # a verdict, so the comparison has to know about it rather than
        # reporting the missing instructions as a disagreement.
        if line.strip() == "...":
            ell.add(sec)
            continue
        # A relocation line is indented past the instruction column:
        #     \t\t0000000000000020:  R_BPF_64_64\tmymap
        m = re.match(r"^\t\t([0-9a-f]+):\s+(\S+)\t(.*)$", line)
        if m:
            rel.setdefault(sec, {})[int(m.group(1), 16) // 8] = (
                m.group(2), m.group(3).strip() or "-")
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        m = re.match(r"^\s*([0-9a-f]+):\s*$", parts[0])
        if not m:
            continue
        idx = int(m.group(1), 10)
        raw = parts[1].strip()
        text = parts[2]
        out[sec][idx] = (raw, text)
    return out, rel, fns, ell


def ours(bpfdis, obj):
    p = subprocess.run([bpfdis, "-d", "--raw", obj], capture_output=True, text=True)
    out = {}
    rel = {}
    fns = {}
    sec = None
    for line in p.stdout.splitlines():
        m = re.match(r"^func (\S+) \S+ slots=(\d+)\.\.(\d+)$", line)
        if m and sec is not None:
            fns.setdefault(sec, []).append(
                (int(m.group(2)), int(m.group(3)), m.group(1)))
            continue
        m = re.match(r"^section (.*) slots=\d+ insns=\d+ funcs=\d+$", line)
        if m:
            sec = m.group(1)
            out.setdefault(sec, {})
            continue
        if sec is None:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        m = re.match(r"^\s*(\d+):\s*$", parts[0])
        if not m:
            continue
        idx = int(m.group(1))
        rest = parts[1]
        if len(parts) > 2 and parts[2].lstrip().startswith("; "):
            f = parts[2].lstrip()[2:].split()
            rel.setdefault(sec, {})[idx] = (f[0], f[1] if len(f) > 1 else "-")
        # "<hex bytes padded> <text>": the byte column is fixed width.
        m = re.match(r"^((?:[0-9a-f]{2} )*[0-9a-f]{2}) +(.*)$", rest)
        if not m:
            continue
        out[sec][idx] = (m.group(1), m.group(2))
    return out, rel, fns


# ---------------------------------------------------------------- allow-list
#
# Places where bpfdis prints something different from llvm-objdump on purpose.
# Each rule gets the raw encoding as well as the two texts, so it can insist
# on the bit that justifies the divergence rather than pattern-matching
# plausible-looking text.


def allow_local_call(raw, llvm, ours):
    """`call N` where src_reg is 1 is a relative call to another subprogram.

    llvm-objdump prints `call -15` for it, exactly as it prints a call to
    helper 15. The two mean entirely different things and the kernel treats
    them as different instructions. bpfdis prints `call pc-15`. The rule
    demands src_reg == 1 in the actual bytes, so it cannot fire on a helper
    call that happens to look similar.
    """
    b = [int(x, 16) for x in raw.split()]
    if len(b) < 8 or b[0] != 0x85 or (b[1] >> 4) != 1:
        return False
    m1 = re.match(r"^call (-?\d+)$", llvm)
    m2 = re.match(r"^call pc([-+]\d+)$", ours)
    return bool(m1 and m2 and int(m1.group(1)) == int(m2.group(1)))


def allow_kfunc_call(raw, llvm, ours):
    """`call N` where src_reg is 2 is a call to a kernel function by BTF id."""
    b = [int(x, 16) for x in raw.split()]
    if len(b) < 8 or b[0] != 0x85 or (b[1] >> 4) != 2:
        return False
    m1 = re.match(r"^call (-?\d+)$", llvm)
    m2 = re.match(r"^callkf (-?\d+)$", ours)
    return bool(m1 and m2 and int(m1.group(1)) == int(m2.group(1)))


ALLOWED = [
    ("local-call", allow_local_call),
    ("kfunc-call", allow_kfunc_call),
]


def expected_funcs(obj):
    """{section: [(start_slot, end_slot, name)]} from readelf alone.

    This is a second implementation rather than an outside authority: no tool
    here prints where a BPF function ends. What IS external is every input it
    uses -- the symbol values and sizes and the section sizes all come from
    binutils -- and the rule it applies is three lines long and written down
    in the README. The mutation it exists for is deleting the st_size
    handling, which the whole compiled corpus cannot see because every
    compiler-generated function reaches its section's end or its neighbour.
    """
    secs = {}
    for line in subprocess.run(
        ["readelf", "-SW", obj], capture_output=True, text=True
    ).stdout.splitlines():
        m = SEC_RE.match(line)
        if m:
            nr, nm = m.group(1), m.group(2)
            secs[int(nr)] = (nm or "", int(m.group(6), 16), m.group(8) or "")
    out = {}
    started = False
    for line in subprocess.run(
        ["readelf", "-sW", obj], capture_output=True, text=True
    ).stdout.splitlines():
        if line.startswith("Symbol table '.symtab'"):
            started = True
            continue
        if not started:
            continue
        m = SYM_RE.match(line)
        if not m or m.group(4) != "FUNC":
            continue
        ndx = m.group(7)
        if not ndx.isdigit() or int(ndx) not in secs:
            continue
        nm, size, flg = secs[int(ndx)]
        if "X" not in flg:
            continue
        out.setdefault(nm, []).append(
            (int(m.group(2), 16) // 8, int(m.group(3)) // 8, m.group(8), size // 8)
        )
    final = {}
    for sec, lst in out.items():
        lst.sort()
        slots = lst[0][3]
        res = []
        for i, (start, sz, name, _s) in enumerate(lst):
            nxt = lst[i + 1][0] if i + 1 < len(lst) else slots
            end = min(start + sz, slots) if sz > 0 else slots
            res.append((start, min(end, nxt), name))
        final[sec] = res
    # A section with no FUNC symbol is one anonymous program named after the
    # section, which is what bpfdis prints; add it so the comparison is over
    # the same set.
    for nr, (nm, size, flg) in secs.items():
        if "X" in flg and size > 0 and nm not in final:
            final[nm] = [(0, size // 8, nm)]
    return final


def main():
    bpfdis = sys.argv[1]
    objs = sys.argv[2:]
    if not objs:
        print("disasm_cmp: no objects given", file=sys.stderr)
        return 2
    counts = dict(
        agree=0, disagree=0, we_refuse=0, llvm_refuse=0, both_refuse=0,
        bytes_differ=0, only_llvm=0, only_ours=0, sections=0,
        reloc_agree=0, reloc_differ=0, func_agree=0, func_differ=0,
        llvm_elided_zeros=0, llvm_cannot_read=0, allowed_roundtrip=0,
    )
    allowed = dict((n, 0) for n, _ in ALLOWED)
    pending_diff = []
    pending_refuse = []
    bad = []
    for obj in objs:
        a, arel, afn, aell = objdump(obj)
        b, brel, bfn = ours(bpfdis, obj)
        # Function boundaries. llvm-objdump labels each one from the symbol
        # table; a section with three STT_FUNC symbols is three programs and
        # every per-program number below depends on the split being right.
        exp = expected_funcs(obj)
        for sec in sorted(set(afn) | set(bfn) | set(exp)):
            x, y = sorted(exp.get(sec, [])), sorted(bfn.get(sec, []))
            if x == y:
                counts["func_agree"] += len(x)
            else:
                counts["func_differ"] += 1
                bad.append("%s %s: functions %r vs %r"
                           % (obj.split("/")[-1], sec, x, y))
        name = obj.split("/")[-1]
        # The relocations llvm-objdump interleaves into the disassembly are a
        # second, independent statement about which instruction each one
        # patches. readelf already agreed about the records; this agrees
        # about where they land.
        for sec in sorted(set(arel) | set(brel)):
            x, y = arel.get(sec, {}), brel.get(sec, {})
            for idx in sorted(set(x) | set(y)):
                if x.get(idx) == y.get(idx):
                    counts["reloc_agree"] += 1
                else:
                    counts["reloc_differ"] += 1
                    bad.append("%s %s[%d]: relocation %r vs %r"
                               % (name, sec, idx, x.get(idx), y.get(idx)))
        for sec in sorted(set(a) | set(b)):
            ai = a.get(sec, {})
            bi = b.get(sec, {})
            if not ai and not bi:
                continue
            counts["sections"] += 1
            for idx in sorted(set(ai) | set(bi)):
                if idx not in ai:
                    braw = bi[idx][0]
                    if sec in aell and set(braw.split()) == {"00"}:
                        counts["llvm_elided_zeros"] += 1
                        continue
                    counts["only_ours"] += 1
                    bad.append("%s %s[%d]: bpfdis has an instruction llvm-objdump does not: %s"
                               % (name, sec, idx, bi[idx][1]))
                    continue
                if idx not in bi:
                    counts["only_llvm"] += 1
                    bad.append("%s %s[%d]: llvm-objdump has an instruction bpfdis does not: %s"
                               % (name, sec, idx, ai[idx][1]))
                    continue
                araw, atext = ai[idx]
                braw, btext = bi[idx]
                if araw.lower() != braw.lower():
                    counts["bytes_differ"] += 1
                    bad.append("%s %s[%d]: raw bytes differ\n    llvm   %s\n    bpfdis %s"
                               % (name, sec, idx, araw, braw))
                    continue
                a_bad = "<unknown>" in atext
                b_bad = btext.strip().startswith("(bad)")
                if a_bad and b_bad:
                    counts["both_refuse"] += 1
                elif a_bad:
                    pending_refuse.append((name, sec, idx, braw, btext))
                elif b_bad:
                    counts["we_refuse"] += 1
                    bad.append("%s %s[%d]: bpfdis refuses, llvm-objdump decodes: %s (%s)"
                               % (name, sec, idx, atext, braw))
                elif norm(atext) == norm(btext):
                    counts["agree"] += 1
                else:
                    hit = None
                    for rname, fn in ALLOWED:
                        if fn(araw, norm(atext), norm(btext)):
                            hit = rname
                            break
                    if hit:
                        allowed[hit] += 1
                        continue
                    pending_diff.append((name, sec, idx, araw, atext, btext))
    # Anything the two tools still differ about goes to LLVM's assembler.
    # If llvm-mc writes bpfdis's text back to exactly the bytes in the
    # object, then bpfdis printed what LLVM itself produces going the other
    # way, and the disagreement is inside LLVM.
    if pending_diff:
        asm = assemble([norm(t[5]) for t in pending_diff])
        for (name, sec, idx, araw, atext, btext), got in zip(pending_diff, asm):
            if got is not None and got == rawbytes(araw):
                counts["allowed_roundtrip"] += 1
            else:
                counts["disagree"] += 1
                bad.append("%s %s[%d] %s:\n    llvm   %s\n    bpfdis %s"
                           % (name, sec, idx, araw.split()[0], norm(atext),
                              norm(btext)))
    if pending_refuse:
        asm = assemble([norm(t[4]) for t in pending_refuse])
        for (name, sec, idx, braw, btext), got in zip(pending_refuse, asm):
            if got is not None and got == rawbytes(braw):
                counts["llvm_cannot_read"] += 1
            else:
                counts["we_refuse"] += 0
                counts["llvm_refuse"] += 1
                bad.append("%s %s[%d]: llvm-objdump refuses, bpfdis decodes "
                           "%s, and llvm-mc will not assemble it back"
                           % (name, sec, idx, btext))

    for k in ("sections", "agree", "allowed_roundtrip", "disagree", "we_refuse", "llvm_refuse",
              "both_refuse", "bytes_differ", "only_llvm", "only_ours",
              "reloc_agree", "reloc_differ", "func_agree", "func_differ",
              "llvm_elided_zeros", "llvm_cannot_read"):
        print("%s=%d" % (k, counts[k]))
    for n, _ in ALLOWED:
        print("allowed_%s=%d" % (n.replace("-", "_"), allowed[n]))
    for b in bad[:MAXSHOW]:
        print("  " + b)
    if len(bad) > MAXSHOW:
        print("  ... and %d more" % (len(bad) - MAXSHOW))
    hard = (counts["disagree"] + counts["bytes_differ"] + counts["only_llvm"]
            + counts["only_ours"] + counts["we_refuse"] + counts["llvm_refuse"]
            + counts["reloc_differ"] + counts["func_differ"])
    if counts["agree"] == 0:
        print("  compared nothing")
        return 1
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
