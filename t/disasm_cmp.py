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

MAXSHOW = 25

NUM = re.compile(r"(?<![0-9A-Za-z_])(-?)(0[xX][0-9a-fA-F]+|[0-9]+)")
SYMSUF = re.compile(r"\s*<[^<>]*>\s*$")
WS = re.compile(r"\s+")


def norm(text):
    """Canonicalise an instruction so two printers can be compared whole."""
    t = SYMSUF.sub("", text.strip())
    t = WS.sub(" ", t)

    def rep(m):
        sign, digits = m.groups()
        v = int(digits, 16) if digits[:2].lower() == "0x" else int(digits, 10)
        return "%s%d" % (sign, v)

    return NUM.sub(rep, t)


def objdump(obj):
    """{section: {index: (bytes, text)}} from llvm-objdump."""
    p = subprocess.run(
        ["llvm-objdump", "-d", "--triple=bpf", obj], capture_output=True, text=True
    )
    out = {}
    sec = None
    for line in p.stdout.splitlines():
        m = re.match(r"^Disassembly of section (.*):\s*$", line)
        if m:
            sec = m.group(1)
            out.setdefault(sec, {})
            continue
        if sec is None:
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
    return out


def ours(bpfdis, obj):
    p = subprocess.run([bpfdis, "-d", "--raw", obj], capture_output=True, text=True)
    out = {}
    sec = None
    for line in p.stdout.splitlines():
        m = re.match(r"^section (.*) slots=\d+ insns=\d+$", line)
        if m:
            sec = m.group(1)
            out.setdefault(sec, {})
            continue
        if sec is None:
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        m = re.match(r"^\s*(\d+):\s*$", parts[0])
        if not m:
            continue
        idx = int(m.group(1))
        rest = parts[1]
        # "<hex bytes padded> <text>": the byte column is fixed width.
        m = re.match(r"^((?:[0-9a-f]{2} )*[0-9a-f]{2}) +(.*)$", rest)
        if not m:
            continue
        out[sec][idx] = (m.group(1), m.group(2))
    return out


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


def main():
    bpfdis = sys.argv[1]
    objs = sys.argv[2:]
    if not objs:
        print("disasm_cmp: no objects given", file=sys.stderr)
        return 2
    counts = dict(
        agree=0, disagree=0, we_refuse=0, llvm_refuse=0, both_refuse=0,
        bytes_differ=0, only_llvm=0, only_ours=0, sections=0,
    )
    allowed = dict((n, 0) for n, _ in ALLOWED)
    bad = []
    for obj in objs:
        a = objdump(obj)
        b = ours(bpfdis, obj)
        name = obj.split("/")[-1]
        for sec in sorted(set(a) | set(b)):
            ai = a.get(sec, {})
            bi = b.get(sec, {})
            if not ai and not bi:
                continue
            counts["sections"] += 1
            for idx in sorted(set(ai) | set(bi)):
                if idx not in ai:
                    counts["only_ours"] += 1
                    bad.append("%s %s[%d]: bpfdis has an instruction llvm-objdump does not"
                               % (name, sec, idx))
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
                    counts["llvm_refuse"] += 1
                    bad.append("%s %s[%d]: llvm-objdump refuses, bpfdis decodes: %s"
                               % (name, sec, idx, btext))
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
                    counts["disagree"] += 1
                    bad.append("%s %s[%d] %s:\n    llvm   %s\n    bpfdis %s"
                               % (name, sec, idx, araw.split()[0], norm(atext), norm(btext)))
    for k in ("sections", "agree", "disagree", "we_refuse", "llvm_refuse",
              "both_refuse", "bytes_differ", "only_llvm", "only_ours"):
        print("%s=%d" % (k, counts[k]))
    for n, _ in ALLOWED:
        print("allowed_%s=%d" % (n.replace("-", "_"), allowed[n]))
    for b in bad[:MAXSHOW]:
        print("  " + b)
    if len(bad) > MAXSHOW:
        print("  ... and %d more" % (len(bad) - MAXSHOW))
    hard = (counts["disagree"] + counts["bytes_differ"] + counts["only_llvm"]
            + counts["only_ours"] + counts["we_refuse"] + counts["llvm_refuse"])
    if counts["agree"] == 0:
        print("  compared nothing")
        return 1
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
