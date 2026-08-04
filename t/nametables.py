#!/usr/bin/env python3
"""The three name tables in src, against the lists bpftool was built with.

`bpftool feature list_builtins GROUP` prints the helper, program-type and
map-type names bpftool holds, in the order of the kernel's enumerations,
and needs no privilege. That makes it an oracle for three tables this
repository would otherwise have written from memory, and the README said
for a while that no such list existed here.

The tables are read out of the Rust source rather than out of bpfdis's
output, for the same reason the section-name table is: a row no corpus
object reaches would otherwise have nothing checking it, and a helper
number nothing calls is most of the list.

What this proves is transcription fidelity and nothing more. Both sides
came from the same place once, so an agreement is not independent
evidence about what the kernel calls helper 181. It still earns itself: a
bpftool built against a different kernel disagrees, and a name edited by
hand disagrees, and both are things that otherwise show up as a wrong
word in somebody's output.
"""
import re
import subprocess
import sys

BPFTOOL = "/usr/sbin/bpftool"
MAXSHOW = 20


def builtins(group):
    p = subprocess.run([BPFTOOL, "feature", "list_builtins", group],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return None
    return [l.strip() for l in p.stdout.splitlines() if l.strip()]


def rust_array(path, decl, pattern):
    """The strings an array in the Rust source holds, in order."""
    out = []
    inside = False
    for line in open(path):
        if line.startswith(decl):
            inside = True
            continue
        if inside:
            if line.startswith("]"):
                break
            out.extend(pattern.findall(line))
    return out


def rust_match_arms(path, fn):
    """{number: name} out of a `match` that maps integers to names."""
    out = {}
    src = open(path).read()
    at = src.index(fn)
    end = src.index("\n}", at)
    for m in re.finditer(r'^\s*(\d+) => "([A-Z_0-9]+)",$', src[at:end], re.M):
        out[int(m.group(1))] = m.group(2)
    return out


def compare(what, ours, theirs, bad):
    """ours and theirs are {index: name}; returns (compared, differ)."""
    cmp = differ = 0
    for i in sorted(ours):
        if i >= len(theirs):
            differ += 1
            if len(bad) < MAXSHOW:
                bad.append("%s %d: bpfdis says %r, bpftool's list stops at %d"
                           % (what, i, ours[i], len(theirs) - 1))
            continue
        cmp += 1
        if ours[i].lower() != theirs[i].lower():
            differ += 1
            if len(bad) < MAXSHOW:
                bad.append("%s %d: bpfdis says %r, bpftool says %r"
                           % (what, i, ours[i], theirs[i]))
    return cmp, differ


HELPERCALL = re.compile(r"\b(\d+)\(([a-z_0-9]+)\)")
ANALYSIS = re.compile(r"^analysis \S+ \S+ .* helpers=(\S+)$")
# A declaration spans lines, so the body is matched with a class that
# excludes the semicolon rather than with DOTALL, which ran from the first
# declaration to the last and matched once.
DECL = re.compile(
    r"\(\*(bpf_[a-z_0-9]+)\)\([^;]*?\)\s*=\s*\(void \*\)(\d+);")


def main():
    src = sys.argv[1]
    bad = []
    total = differ = 0

    helpers = builtins("helpers")
    progs = builtins("prog_types")
    maps = builtins("map_types")
    if helpers is None or progs is None or maps is None:
        print("nametables: bpftool feature list_builtins failed", file=sys.stderr)
        return 2

    ours = rust_array(src + "/cfg.rs", "pub const HELPERS",
                      re.compile(r'"([a-z_0-9]+)"'))
    c, d = compare("helper", dict(enumerate(ours)), helpers, bad)
    print("helper_names=%d" % c)
    total += c
    differ += d
    if len(ours) != len(helpers):
        differ += 1
        bad.append("the helper table has %d entries, bpftool lists %d"
                   % (len(ours), len(helpers)))

    # The program-type names live in the fourth column of the section-name
    # table, so the same number appears many times and each occurrence is
    # checked.
    rows = re.findall(r'^\s*\("[^"]+", (?:true|false), (\d+), "([A-Z_0-9]+)"\),$',
                      open(src + "/prog.rs").read(), re.M)
    c, d = compare("prog type", {int(n): nm for n, nm in rows}, progs, bad)
    print("prog_type_names=%d" % c)
    total += c
    differ += d

    c, d = compare("map type", rust_match_arms(src + "/maps.rs",
                                               "pub fn map_type_name"), maps, bad)
    print("map_type_names=%d" % c)
    total += c
    differ += d

    # The table being right is not the same as the lookup using it right.
    # Every helper bpfdis names in the corpus is checked against the same
    # list, which is what exercises helper_name rather than the array: the
    # mutation that indexes it from one survived until this existed.
    named = 0
    bpfdis = sys.argv[2]
    for obj in sys.argv[3:]:
        out = subprocess.run([bpfdis, "-a", obj], capture_output=True,
                             text=True).stdout
        for line in out.splitlines():
            m = ANALYSIS.match(line)
            if not m or m.group(1) == "-":
                continue
            for num, name in HELPERCALL.findall(m.group(1)):
                named += 1
                want = helpers[int(num)] if int(num) < len(helpers) else None
                if name != want:
                    differ += 1
                    if len(bad) < MAXSHOW:
                        bad.append("%s: call %s is named %r, bpftool says %r"
                                   % (obj.split("/")[-1], num, name, want))
    print("helpers_named_in_corpus=%d" % named)

    # And the corpus's own declarations, which are where the numbers in the
    # object files come from. t/corpus/bpf.h gives each helper a name and an
    # address, clang turns the address into the imm of a call, and bpftool
    # says what that number is called. A wrong id in the header would make
    # every program using it call something else.
    decls = 0
    for name, num in DECL.findall(open(sys.argv[1] + "/../t/corpus/bpf.h").read()):
        decls += 1
        want = helpers[int(num)] if int(num) < len(helpers) else None
        if name != want:
            differ += 1
            if len(bad) < MAXSHOW:
                bad.append("t/corpus/bpf.h declares %s as %s, bpftool calls "
                           "that %r" % (name, num, want))
    print("corpus_helper_decls=%d" % decls)

    print("name_table_entries=%d" % total)
    print("name_table_differ=%d" % differ)
    for b in bad:
        print("  " + b)
    return 1 if (differ or total < 200 or named == 0 or decls == 0) else 0


if __name__ == "__main__":
    sys.exit(main())
