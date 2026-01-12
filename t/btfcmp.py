#!/usr/bin/env python3
"""Compare bpfdis -b against `bpftool btf dump file`, line for line.

bpftool is libbpf, a third codebase after binutils and LLVM, and it is the
only oracle here for BTF. The comparison is an exact line-by-line diff
rather than a fact extraction, because bpfdis deliberately reproduces
bpftool's own output format: when two tools claim to print the same thing,
requiring the same bytes is a stronger assertion than agreeing on a subset
of fields, not a weaker one.

Prints the number of type records compared, the number of distinct BTF
kinds reached, and the number of lines that differ.
"""
import re
import subprocess
import sys

MAXSHOW = 20
KIND_RE = re.compile(r"^\[\d+\] ([A-Z_0-9]+) ")


def main():
    bpfdis = sys.argv[1]
    objs = sys.argv[2:]
    types = 0
    lines = 0
    differ = 0
    kinds = {}
    objs_with_btf = 0
    bad = []
    for obj in objs:
        p = subprocess.run(
            ["/usr/sbin/bpftool", "btf", "dump", "file", obj],
            capture_output=True,
            text=True,
        )
        if p.returncode != 0:
            continue
        want = p.stdout.splitlines()
        if not want:
            continue
        objs_with_btf += 1
        got = subprocess.run(
            [bpfdis, "-b", obj], capture_output=True, text=True
        ).stdout.splitlines()
        for l in want:
            m = KIND_RE.match(l)
            if m:
                types += 1
                kinds[m.group(1)] = kinds.get(m.group(1), 0) + 1
        n = max(len(want), len(got))
        lines += len(want)
        for i in range(n):
            a = want[i] if i < len(want) else "<missing>"
            b = got[i] if i < len(got) else "<missing>"
            if a != b:
                differ += 1
                if len(bad) < MAXSHOW:
                    bad.append(
                        "%s line %d:\n    bpftool %r\n    bpfdis  %r"
                        % (obj.split("/")[-1], i + 1, a, b)
                    )
    print("objects_with_btf=%d" % objs_with_btf)
    print("btf_types=%d" % types)
    print("btf_lines=%d" % lines)
    print("btf_lines_differ=%d" % differ)
    print("btf_kinds=%d" % len(kinds))
    print("kinds: " + " ".join("%s=%d" % kv for kv in sorted(kinds.items())))
    for b in bad:
        print("  " + b)
    return 1 if (differ or types == 0) else 0


if __name__ == "__main__":
    sys.exit(main())
