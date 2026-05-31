#!/usr/bin/env python3
"""Two halves of the same question about the analysis.

The first half has an authority of a kind: clang. Code a working compiler
emits is code the verifier accepts, so every function in every object built
from C must produce no rejection at all. A false positive anywhere in the
analysis shows up here, over every function in the compiled corpus, and
this is the only check on the analysis that is not self-referential.

The second half has none. Whether bpfdis is RIGHT that a program would be
rejected can only be settled by the verifier, and the verifier is
unreachable on this machine; see t/verifier_probe.c. So the fixtures in
t/corpus/badflow.s are hand-built, one defect per function, and all this
asserts is that each finding is reached by something and that a mutation
disabling one has a test to kill. That is worth having and it is not the
same as being checked.
"""
import os
import re
import subprocess
import sys

ANALYSIS = re.compile(r"^analysis (\S+) (\S+) ")

# function -> a substring that must appear in one of its findings.
EXPECTED = {
    "midwide": "the second half of a 16-byte load",
    "unreach": "are not reachable from the entry",
    "outside": "outside the function",
    "uninit": "reads r3, which no path has written",
    "spin": "a loop",
    "runoff": "is not an exit or a jump",
    "badcall": "not the first instruction of a function in this section",
}


def findings(bpfdis, obj):
    """{function: [finding lines]} from one object."""
    out = {}
    cur = None
    for line in subprocess.run(
        [bpfdis, "-a", obj], capture_output=True, text=True
    ).stdout.splitlines():
        m = ANALYSIS.match(line)
        if m:
            cur = m.group(2)
            out.setdefault(cur, [])
        elif cur is not None and line.startswith("  "):
            out[cur].append(line.strip())
    return out


def main():
    bpfdis, corpus = sys.argv[1], sys.argv[2]
    funcs = 0
    false_positives = 0
    bad = []
    for obj in sorted(os.listdir(corpus)):
        # Only the objects built from C: a compiler's output is the thing
        # that must be clean. The hand-written fixtures are deliberate
        # rubbish and are checked separately below.
        if not re.search(r"\.v\d\.O\d\.o$", obj):
            continue
        for fn, fs in findings(bpfdis, os.path.join(corpus, obj)).items():
            funcs += 1
            for f in fs:
                if f.startswith("reject:"):
                    false_positives += 1
                    if len(bad) < 20:
                        bad.append("%s %s: %s" % (obj, fn, f))
    print("compiled_functions=%d" % funcs)
    print("false_positives=%d" % false_positives)

    found = 0
    missing = []
    bf = os.path.join(corpus, "badflow.asm.o")
    if os.path.exists(bf):
        got = findings(bpfdis, bf)
        for fn, want in sorted(EXPECTED.items()):
            fs = got.get(fn)
            if fs is None:
                missing.append("%s: no analysis emitted at all" % fn)
            elif any(want in f for f in fs):
                found += 1
            else:
                missing.append("%s: expected a finding containing %r, got %r"
                               % (fn, want, fs))
    else:
        missing.append("badflow.asm.o is not in the corpus")
    print("findings_reached=%d of %d" % (found, len(EXPECTED)))

    # The exit status is what a pipeline reads, so it is checked both ways.
    rc_bad = subprocess.run([bpfdis, "-a", "--strict", bf],
                            capture_output=True).returncode
    clean = None
    for obj in sorted(os.listdir(corpus)):
        if re.search(r"\.v3\.O2\.o$", obj):
            clean = os.path.join(corpus, obj)
            break
    rc_clean = subprocess.run([bpfdis, "-a", "--strict", clean],
                              capture_output=True).returncode if clean else -1
    print("strict_exit_on_bad=%d" % rc_bad)
    print("strict_exit_on_clean=%d" % rc_clean)
    for b in bad + missing:
        print("  " + b)
    ok = (false_positives == 0 and not missing and funcs > 100
          and rc_bad == 3 and rc_clean == 0)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
