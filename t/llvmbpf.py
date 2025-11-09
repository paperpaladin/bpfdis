"""Driving LLVM's BPF assembler and disassembler, and comparing their output.

Shared by t/disasm_cmp.py and t/opcode_sweep.py.

Both directions are used as oracles and they are not the same oracle. The
disassembler turns bytes into text; the assembler turns text into bytes. LLVM
disagrees with itself about the 32-bit atomic family, which only a tool that
runs both directions can see.
"""
import re
import subprocess

NUM = re.compile(r"(?<![0-9A-Za-z_])(-?)(0[xX][0-9a-fA-F]+|[0-9]+)")
SYMSUF = re.compile(r"\s*<[^<>]*>\s*$")
WS = re.compile(r"\s+")


def norm(text):
    """Canonicalise an instruction so two printers can be compared whole.

    Numbers become decimal; whitespace runs become one space; a trailing
    `<sym+0x20>` annotation from llvm-objdump is dropped. Everything else,
    including punctuation and the `*(u32 *)` type spellings, stays inside the
    comparison. A token list would have thrown those away.
    """
    t = SYMSUF.sub("", text.strip())
    t = WS.sub(" ", t)

    def rep(m):
        sign, digits = m.groups()
        v = int(digits, 16) if digits[:2].lower() == "0x" else int(digits, 10)
        return "%s%d" % (sign, v)

    return NUM.sub(rep, t)


def _run(args, text):
    return subprocess.run(args, input=text, capture_output=True, text=True)


def disasm(lines):
    """[(ok, text)] for hex-byte lines, one instruction per line.

    llvm-mc prints nothing at all for an encoding it rejects and names the
    line on stderr, so the alignment between input and output has to be
    reconstructed. It is checked rather than trusted: if decoded plus
    rejected does not equal the lines fed in, the chunk is bisected, and a
    single line that still will not line up is reported as such.
    """
    if not lines:
        return []
    p = _run(["llvm-mc", "--disassemble", "-triple=bpfel"], "\n".join(lines) + "\n")
    if ": error:" in p.stderr:
        first = [l for l in p.stderr.splitlines() if ": error:" in l][:1]
        raise SystemExit("llvmbpf: llvm-mc could not read its input: %s" % first)
    bad = set(
        int(m.group(1))
        for m in re.finditer(r"^<stdin>:(\d+):\d+: warning:", p.stderr, re.M)
    )
    good = [
        l.strip()
        for l in p.stdout.splitlines()
        if l.strip() and not l.strip().startswith(".")
    ]
    if len(good) + len(bad) != len(lines):
        if len(lines) == 1:
            return [(False, "llvm-mc produced %d outputs for one line" % len(good))]
        h = len(lines) // 2
        return disasm(lines[:h]) + disasm(lines[h:])
    out = []
    gi = 0
    for i in range(1, len(lines) + 1):
        if i in bad:
            out.append((False, ""))
        else:
            out.append((True, good[gi]))
            gi += 1
    return out


ENCRE = re.compile(r"#\s*encoding:\s*\[([^\]]*)\]")


def assemble(lines):
    """[bytes or None] for assembly source lines, one instruction each."""
    if not lines:
        return []
    p = _run(["llvm-mc", "-triple=bpfel", "--show-encoding"], "\n".join(lines) + "\n")
    bad = set(
        int(m.group(1))
        for m in re.finditer(r"^<stdin>:(\d+):\d+: error:", p.stderr, re.M)
    )
    good = []
    for l in p.stdout.splitlines():
        m = ENCRE.search(l)
        if m:
            good.append(
                bytes(int(x, 16) for x in m.group(1).replace(" ", "").split(",") if x)
            )
    if len(good) + len(bad) != len(lines):
        if len(lines) == 1:
            return [None]
        h = len(lines) // 2
        return assemble(lines[:h]) + assemble(lines[h:])
    out = []
    gi = 0
    for i in range(1, len(lines) + 1):
        if i in bad:
            out.append(None)
        else:
            out.append(good[gi])
            gi += 1
    return out


def rawbytes(raw):
    """The bytes of an encoding written as `0x..,0x..` or `.. ..`."""
    return bytes(int(x, 16) for x in raw.replace(",", " ").split())
