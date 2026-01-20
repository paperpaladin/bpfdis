#!/usr/bin/env python3
"""Check bpfdis's stack depth against LLVM's own frame-size accounting.

The kernel verifier is the real authority for stack depth and it is not
reachable here. LLVM is the next best thing and it turns out to be exact.
The BPF backend refuses to compile a function whose frame reaches the stack
limit, and the limit is settable:

    clang -target bpf -mllvm -bpf-stack-size=N

Measured against t/corpus/mem.c, whose three functions have frames of 16,
16 and 128 bytes: the error appears at N = 16 and N = 128 respectively and
is gone at N = 17 and N = 129. So LLVM's rule is `error if N <= depth`, and
the smallest clean N is exactly depth + 1. That makes the threshold an
exact measurement of the frame size rather than a bound on it.

For each function bpfdis reports a depth D for, this compiles the source
twice and requires both halves:

    at -bpf-stack-size=D      the function must be refused
    at -bpf-stack-size=D+1    the function must compile

Only requiring the second would pass for any D that is too large; only
requiring the first would pass for any D that is too small. Together they
pin the number.

Functions bpfdis says use no stack are checked against N = 1, where any
stack use at all would be refused.

LLVM reports the error at the source position of the INSTRUCTION that
formed the stack address, not of the function, so the position often names
a local variable. The error line is mapped to the enclosing function by
finding each reported function's definition line in the source and taking
the last definition at or before the error. That is a heuristic over a
corpus this repository controls, so it is checked rather than trusted:
every function bpfdis reports must be located in the source, and the run
fails if one is not.
"""
import os
import re
import subprocess
import sys

ERR = re.compile(r"^(\S+):(\d+):(\d+): error: Looks like the BPF stack limit")
ANALYSIS = re.compile(r"^analysis (\S+) (\S+) insns=\d+ blocks=\d+ stack=(\d+) ")
IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
MAXSHOW = 20


def def_lines(src, names):
    """{name: definition line} for each name, or None if any is missing."""
    lines = open(src).read().splitlines()
    out = {}
    for n in names:
        pat = re.compile(r"\b%s\s*\(" % re.escape(n))
        for i, l in enumerate(lines):
            if pat.search(l) and not l.lstrip().startswith(("*", "//")):
                out[n] = i + 1
                break
    return out


def enclosing(defs, line):
    """The function whose definition is the last one at or before `line`."""
    best, bestline = None, -1
    for n, dl in defs.items():
        if dl <= line and dl > bestline:
            best, bestline = n, dl
    return best


def errors_at(src, flags, limit, defs):
    p = subprocess.run(
        ["clang", "-target", "bpf"] + flags
        + ["-mllvm", "-bpf-stack-size=%d" % limit, "-c", src, "-o", "/dev/null"],
        capture_output=True, text=True,
    )
    out = set()
    for line in p.stderr.splitlines():
        m = ERR.match(line)
        if m:
            n = enclosing(defs, int(m.group(2)))
            if n:
                out.add(n)
    return out


def main():
    bpfdis, corpus, srcdir = sys.argv[1], sys.argv[2], sys.argv[3]
    unlocated = 0
    checked_nonzero = checked_zero = wrong = 0
    bad = []
    for obj in sorted(os.listdir(corpus)):
        # One object per source is enough for this check and each one costs
        # two or three clang runs; the variants chosen are the two ends of
        # the matrix.
        if not (obj.endswith(".v3.O2.o") or obj.endswith(".v1.O1.o")):
            continue
        base = obj.split(".")[0]
        src = os.path.join(srcdir, base + ".c")
        if not os.path.exists(src):
            continue
        cpu, opt = obj.split(".")[1], obj.split(".")[2]
        flags = ["-mcpu=" + cpu, "-" + opt, "-g", "-I", srcdir]
        depths = {}
        for line in subprocess.run(
            [bpfdis, "-a", os.path.join(corpus, obj)], capture_output=True, text=True
        ).stdout.splitlines():
            m = ANALYSIS.match(line)
            if m:
                depths[m.group(2)] = int(m.group(3))
        if not depths:
            continue
        defs = def_lines(src, depths.keys())
        missing = [n for n in depths if n not in defs]
        if missing:
            unlocated += len(missing)
            bad.append("%s: cannot find the definition of %s in %s"
                       % (obj, ", ".join(sorted(missing)), src))
            continue
        byd = {}
        for fn, d in depths.items():
            byd.setdefault(d, []).append(fn)
        for d, fns in sorted(byd.items()):
            if d == 0:
                errs = errors_at(src, flags, 1, defs)
                for fn in fns:
                    checked_zero += 1
                    if fn in errs:
                        wrong += 1
                        if len(bad) < MAXSHOW:
                            bad.append(
                                "%s %s: bpfdis says no stack, clang refuses it at "
                                "a 1-byte limit" % (obj, fn))
                continue
            lo = errors_at(src, flags, d, defs)
            hi = errors_at(src, flags, d + 1, defs)
            for fn in fns:
                checked_nonzero += 1
                if fn not in lo:
                    wrong += 1
                    if len(bad) < MAXSHOW:
                        bad.append(
                            "%s %s: bpfdis says %d bytes, clang compiles it with a "
                            "%d-byte limit, so the real frame is smaller"
                            % (obj, fn, d, d))
                elif fn in hi:
                    wrong += 1
                    if len(bad) < MAXSHOW:
                        bad.append(
                            "%s %s: bpfdis says %d bytes, clang still refuses it with "
                            "a %d-byte limit, so the real frame is larger"
                            % (obj, fn, d, d + 1))
    print("stack_nonzero_checked=%d" % checked_nonzero)
    print("stack_zero_checked=%d" % checked_zero)
    print("stack_unlocated=%d" % unlocated)
    print("stack_wrong=%d" % wrong)
    for b in bad:
        print("  " + b)
    return 1 if (wrong or unlocated or checked_nonzero == 0 or checked_zero == 0) else 0


if __name__ == "__main__":
    sys.exit(main())
