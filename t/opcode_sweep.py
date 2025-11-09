#!/usr/bin/env python3
"""Sweep the BPF encoding space against LLVM's disassembler.

The corpus reaches the opcodes clang chooses to emit, which is 61 of them.
This reaches the rest, including every field value a compiler would never
produce, which is where a decoder is actually wrong.

Every encoding is put to `llvm-mc --disassemble -triple=bpfel` and to
`bpfdis -x`, and the pair of verdicts is sorted into one of six buckets:

    agree          both decoded it, to the same text
    disagree       both decoded it, differently
    both-refuse    neither decoded it
    we-refuse      LLVM decoded it, bpfdis did not
    over-accept-flagged   LLVM refused it, bpfdis decoded it and recorded at
                   least one reserved-field defect against it
    over-accept-clean     LLVM refused it, bpfdis decoded it and saw nothing
                   wrong

The last bucket is the dangerous one, and the point of separating it from
the one above: bpfdis is deliberately more permissive than LLVM about
reserved fields, because it names the instruction and then reports the dirty
field, but an encoding it accepts with nothing to say about it is an
encoding it believes is well-formed and LLVM does not.

`we-refuse` and `over-accept-clean` are reported with the reasons grouped,
not as one number, because the question "which rule accounts for these" has
an answer and "how many are there" does not.

llvm-mc prints nothing at all for an encoding it rejects, and names the
rejected line on stderr, so the alignment between input lines and output
lines has to be reconstructed. The reconstruction is checked rather than
trusted: every chunk asserts that decoded lines plus rejected lines equals
the lines fed in, and splits itself if they do not.
"""
import collections
import re
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from llvmbpf import assemble, disasm, norm, rawbytes  # noqa: E402

CHUNK = 2000


def ours(bpfdis, lines):
    p = subprocess.run(
        [bpfdis, "-x"], input="\n".join(lines) + "\n", capture_output=True, text=True
    )
    out = {}
    for l in p.stdout.splitlines():
        f = l.split("\t")
        if len(f) != 4:
            continue
        out[int(f[0])] = (f[1] == "OK", f[2], f[3])
    return [out.get(i, (False, "no output", "-")) for i in range(1, len(lines) + 1)]


def enc(code, dst=1, src=2, off=0, imm=0, hi=None, tail=(0, 0, 0)):
    b = [
        code & 0xFF,
        ((src & 0xF) << 4) | (dst & 0xF),
        off & 0xFF,
        (off >> 8) & 0xFF,
        imm & 0xFF,
        (imm >> 8) & 0xFF,
        (imm >> 16) & 0xFF,
        (imm >> 24) & 0xFF,
    ]
    if hi is not None:
        b += [
            tail[0] & 0xFF,
            tail[1] & 0xFF,
            tail[2] & 0xFF,
            (tail[2] >> 8) & 0xFF,
            hi & 0xFF,
            (hi >> 8) & 0xFF,
            (hi >> 16) & 0xFF,
            (hi >> 24) & 0xFF,
        ]
    return ",".join("0x%02x" % x for x in b)


OFFS = [0, 1, 2, 3, 4, 8, 16, 32, -1, -4, 0x7FFF, -0x8000]
IMMS = [
    0, 1, 2, 3, 7, 8, 16, 32, 64,
    0x40, 0x41, 0x50, 0x51, 0xA0, 0xA1, 0xE0, 0xE1, 0xF0, 0xF1,
    -1, 0x7FFFFFFF, -0x80000000,
]


def generate():
    """Deterministic. Axis sweeps first, then a pseudo-random sample."""
    seen = set()
    out = []

    def add(s):
        if s not in seen:
            seen.add(s)
            out.append(s)

    for code in range(256):
        if code == 0x18:
            continue
        for d in range(16):
            add(enc(code, dst=d))
        for s in range(16):
            add(enc(code, src=s))
        for o in OFFS:
            add(enc(code, off=o))
        for i in IMMS:
            add(enc(code, imm=i))
    # The wide load has a second half of its own, and the only instruction
    # whose length is not eight is the one most likely to be mishandled.
    for s in range(16):
        for d in (0, 1, 10, 11):
            add(enc(0x18, dst=d, src=s, hi=0x11223344))
    for hi in (0, 1, -1, 0x7FFFFFFF, -0x80000000):
        for lo in (0, 1, -1, 0x7FFFFFFF, -0x80000000):
            add(enc(0x18, dst=1, src=0, imm=lo, hi=hi))
    for tail in ((0, 0, 0), (0x95, 0, 0), (0, 0x21, 0), (0, 0, 7), (0xB7, 0x31, -4)):
        add(enc(0x18, dst=1, src=0, imm=1, hi=2, tail=tail))
    # A linear congruential walk over the interesting pools. Fixed constants,
    # no seed argument: a sweep whose contents move between runs cannot be
    # compared with the number in a README.
    st = 0x12345678
    def nxt(n):
        nonlocal st
        st = (st * 1103515245 + 12345) & 0x7FFFFFFF
        return st % n
    for _ in range(40000):
        code = nxt(256)
        if code == 0x18:
            code = 0x19
        add(
            enc(
                code,
                dst=nxt(16),
                src=nxt(16),
                off=OFFS[nxt(len(OFFS))],
                imm=IMMS[nxt(len(IMMS))],
            )
        )
    return out


def main():
    bpfdis = sys.argv[1]
    lines = generate()
    counts = collections.Counter()
    we_refuse = collections.Counter()
    over_clean = collections.Counter()
    over_flagged = collections.Counter()
    disagreements = []
    pending = []
    refused = []
    overs = []
    flagged = []
    roundtrip = collections.Counter()
    overs_confirmed = collections.Counter()
    lossy = collections.Counter()
    unchecked = collections.Counter()
    faithful = collections.Counter()
    for i in range(0, len(lines), CHUNK):
        chunk = lines[i : i + CHUNK]
        a = disasm(chunk)
        b = ours(bpfdis, chunk)
        for raw, (aok, atext), (bok, btext, bdef) in zip(chunk, a, b):
            if aok and bok:
                if norm(atext) == norm(btext):
                    counts["agree"] += 1
                elif allow_local_call(raw, norm(atext), norm(btext)):
                    counts["allowed"] += 1
                else:
                    pending.append((raw, norm(atext), norm(btext)))
            elif not aok and not bok:
                counts["both_refuse"] += 1
            elif aok and not bok:
                counts["we_refuse"] += 1
                we_refuse[btext.split(";")[0][:60]] += 1
                refused.append((raw, atext, btext))
            else:
                if bdef == "-":
                    counts["over_accept_clean"] += 1
                    over_clean[opclass(raw)] += 1
                    overs.append((raw, btext))
                else:
                    counts["over_accept_flagged"] += 1
                    over_flagged[bdef] += 1
                    flagged.append((raw, bdef))
    # The last word on a divergence is LLVM's assembler, not its
    # disassembler. If llvm-mc assembles bpfdis's text back to exactly these
    # bytes, then the text bpfdis printed is the text LLVM itself produces
    # going the other way, and the two halves of LLVM disagree with each
    # other rather than with us. That is measured here, not asserted.
    if pending:
        asm = assemble([t[2] for t in pending])
        for (raw, atext, btext), got in zip(pending, asm):
            if got is not None and got == rawbytes(raw):
                counts["allowed_roundtrip"] += 1
                roundtrip[btext.split("(")[0].strip()[:40]] += 1
            else:
                counts["disagree"] += 1
                if len(disagreements) < 40:
                    disagreements.append(
                        "%s\n    llvm-objdump %s\n    bpfdis       %s\n"
                        "    llvm-mc assembling the bpfdis text gives %s"
                        % (raw, atext, btext,
                           "nothing" if got is None
                           else ",".join("%02x" % x for x in got))
                    )
    # An encoding bpfdis decodes and llvm-objdump refuses is only defensible
    # if LLVM's own assembler produces those exact bytes from the text we
    # printed. 17 of them do, which makes them instructions LLVM can write
    # and cannot read.
    if overs:
        asm = assemble([t[1] for t in overs])
        for (raw, btext), got in zip(overs, asm):
            if got is not None and got == rawbytes(raw):
                counts["over_accept_confirmed"] += 1
                overs_confirmed[btext.split("(")[0].strip()[:40]] += 1

    # And an encoding bpfdis refuses and LLVM decodes is defensible when
    # LLVM's decode is lossy: assembling its own text back does not
    # reproduce the bytes, so the fields bpfdis objected to are fields LLVM
    # dropped on the floor. Where the round trip is faithful, LLVM is
    # reading something real that bpfdis is not, and the sweep says so.
    if refused:
        asm = assemble([t[1] for t in refused])
        for (raw, atext, btext), got in zip(refused, asm):
            key = btext.split(";")[0][:60]
            if got is not None and got == rawbytes(raw):
                faithful[key] += 1
                counts["we_refuse_llvm_faithful"] += 1
            else:
                lossy[key] += 1
                counts["we_refuse_llvm_lossy"] += 1

    # over-accept-flagged is the bucket that could hide a wrong answer: an
    # encoding decoded to the wrong instruction would land here as long as
    # some reserved field was also dirty. So each one is re-tested with the
    # fields bpfdis objected to zeroed. Both tools then see the same clean
    # bytes, and if they still agree the opcode identification was right and
    # the only thing between them was the dirt.
    if flagged:
        cleaned = [clean(raw, bdef) for raw, bdef in flagged]
        la = disasm(cleaned)
        lb = ours(bpfdis, cleaned)
        retry = []
        for (raw, bdef), c, (aok, atext), (bok, btext, _d) in zip(
            flagged, cleaned, la, lb
        ):
            if aok and bok and norm(atext) == norm(btext):
                counts["over_accept_flagged_confirmed"] += 1
            elif aok and bok and allow_local_call(c, norm(atext), norm(btext)):
                counts["over_accept_flagged_confirmed"] += 1
            elif bok:
                # The cleaned encoding landed in the same LLVM gap. Ask the
                # assembler instead: if it writes our text back to exactly
                # the cleaned bytes, the decode is confirmed anyway.
                retry.append((c, btext, bdef, raw))
            else:
                counts["over_accept_flagged_unchecked"] += 1
                unchecked["%s %s" % (bdef, opclass(raw))] += 1
        if retry:
            asm2 = assemble([t[1] for t in retry])
            for (c, btext, bdef, raw), got in zip(retry, asm2):
                if got is not None and got == rawbytes(c):
                    counts["over_accept_flagged_confirmed"] += 1
                else:
                    counts["over_accept_flagged_unchecked"] += 1
                    unchecked["%s %s" % (bdef, opclass(raw))] += 1

    print("encodings=%d" % len(lines))
    for k in (
        "agree", "allowed", "allowed_roundtrip", "disagree", "both_refuse",
        "we_refuse", "we_refuse_llvm_lossy", "we_refuse_llvm_faithful",
        "over_accept_flagged", "over_accept_flagged_confirmed",
        "over_accept_flagged_unchecked",
        "over_accept_clean", "over_accept_confirmed",
    ):
        print("%s=%d" % (k, counts[k]))
    for reason, n in roundtrip.most_common():
        print("  roundtrip: %6d  %s" % (n, reason))
    for reason, n in overs_confirmed.most_common():
        print("  over-accept-confirmed: %6d  %s" % (n, reason))
    for reason, n in faithful.most_common():
        print("  we-refuse-but-llvm-is-faithful: %6d  %s" % (n, reason))
    for reason, n in unchecked.most_common(15):
        print("  flagged-unchecked: %6d  %s" % (n, reason))
    for name, c in (
        ("we-refuse-llvm-lossy", lossy),
        ("over-accept-clean", over_clean),
        ("over-accept-flagged", over_flagged),
    ):
        for reason, n in c.most_common():
            print("  %s: %6d  %s" % (name, n, reason))
    for d in disagreements:
        print("  disagree " + d)
    return 1 if (counts["disagree"] or counts["agree"] == 0) else 0


def clean(raw, defects):
    """Zero the fields bpfdis objected to, so the encoding becomes one LLVM
    will read. Registers above r10 are moved into range rather than zeroed,
    because zeroing a register changes which register the instruction names
    and r0 is a legal choice that means something else."""
    b = bytearray(rawbytes(raw))
    d = set(defects.split(","))
    dst, src = b[1] & 0xF, b[1] >> 4
    if "reg-above-r10" in d:
        if dst > 10:
            dst = 1
        if src > 10:
            src = 2
    if "dst-not-zero" in d:
        dst = 0
    if "src-not-zero" in d:
        src = 0
    b[1] = (src << 4) | dst
    if "off-not-zero" in d:
        b[2] = b[3] = 0
    if "imm-not-zero" in d:
        b[4] = b[5] = b[6] = b[7] = 0
    return ",".join("0x%02x" % x for x in b)


def opclass(raw):
    return "code=%#04x" % rawbytes(raw)[0]


def allow_local_call(raw, llvm, ours_text):
    b = rawbytes(raw)
    if b[0] != 0x85 or (b[1] >> 4) not in (1, 2):
        return False
    m1 = re.match(r"^call (-?\d+)$", llvm)
    if (b[1] >> 4) == 1:
        m2 = re.match(r"^call pc([-+]\d+)$", ours_text)
    else:
        m2 = re.match(r"^callkf (-?\d+)$", ours_text)
    return bool(m1 and m2 and int(m1.group(1)) == int(m2.group(1)))


if __name__ == "__main__":
    sys.exit(main())
