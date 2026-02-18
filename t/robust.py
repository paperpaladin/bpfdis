#!/usr/bin/env python3
"""Hostile input: truncation, byte corruption, and a header that lies.

Every length and offset in an ELF object comes out of the object, so the
off-by-one most likely to exist is the one on a number an attacker chose.
bpfdis is Rust and bounds-checks every index, which means the failure mode
is not a wild read: it is an abort, and an abort is still a crash. The
sweep watches exit statuses.

Accepted: 0 (parsed) and 1 (refused with a diagnostic). Anything else --
2 would be a usage error the harness did not ask for, 101 a Rust panic
under the default runtime, 134 a panic under `panic = "abort"`, 124 a
timeout -- is a failure and is named.

Each sweep asserts it is non-vacuous in both directions: some inputs must
be refused and some must still parse. A sweep where everything is refused
is testing the magic check and nothing else.
"""
import os
import random
import subprocess
import sys

TIMEOUT = 10
MAXSHOW = 15


def run(bpfdis, path):
    try:
        p = subprocess.run(
            [bpfdis, "-A", "--strict", path],
            capture_output=True,
            timeout=TIMEOUT,
        )
        return p.returncode
    except subprocess.TimeoutExpired:
        return 124


def sweep(name, bpfdis, tmp, variants, counts, bad):
    """`variants` yields (label, bytes). Runs each and classifies."""
    clean = refused = strict = 0
    for label, data in variants:
        with open(tmp, "wb") as f:
            f.write(data)
        rc = run(bpfdis, tmp)
        if rc == 0:
            clean += 1
        elif rc == 1:
            refused += 1
        elif rc == 3:
            strict += 1
        else:
            counts[name + "_crashed"] += 1
            if len(bad) < MAXSHOW:
                bad.append("%s %s: exit %d" % (name, label, rc))
    counts[name + "_runs"] += clean + refused + strict + counts[name + "_crashed"]
    counts[name + "_clean"] += clean
    counts[name + "_refused"] += refused + strict


def truncations(data):
    # Every length up to 128 bytes, where the headers live and where an
    # off-by-one is most likely, then a stride through the rest.
    seen = set()
    for n in list(range(0, min(129, len(data)))) + list(range(0, len(data), 37)):
        if n in seen:
            continue
        seen.add(n)
        yield ("truncated to %d" % n, data[:n])


def corruptions(data, rng):
    for off in range(0, len(data), 29):
        for v in (0x00, 0xFF, 0x7F):
            b = bytearray(data)
            b[off] = v
            yield ("byte %d := %#x" % (off, v), bytes(b))
    # Multi-byte smashes, which is what breaks a length field rather than a
    # single digit of one.
    for _ in range(150):
        b = bytearray(data)
        off = rng.randrange(max(1, len(b) - 8))
        for i in range(8):
            if off + i < len(b):
                b[off + i] = rng.randrange(256)
        yield ("8 random bytes at %d" % off, bytes(b))


def shrinks(data):
    """Section headers that lie about how long their section is.

    Truncating the file is one-sided by construction -- a clang object puts
    the section header table last, so cutting any bytes off the end leaves
    no section table and the parse is refused before anything interesting
    happens. Editing sh_size in place is the other half: the file stays
    whole and well formed and one section claims a length it does not have,
    which is the shape that reaches the instruction decoder, the slot map
    and the BTF reader with a short buffer.
    """
    if len(data) < 64:
        return
    shoff = int.from_bytes(data[0x28:0x30], "little")
    shnum = int.from_bytes(data[0x3C:0x3E], "little")
    if shoff + shnum * 64 > len(data):
        return
    for i in range(shnum):
        base = shoff + i * 64
        old = int.from_bytes(data[base + 32:base + 40], "little")
        for v in (0, 1, 7, 8, 9, old // 2, max(0, old - 1), old + 1,
                  old + 8, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            b = bytearray(data)
            b[base + 32:base + 40] = (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            yield ("section %d sh_size := %#x" % (i, v), bytes(b))


def main():
    bpfdis, corpus, scratch = sys.argv[1], sys.argv[2], sys.argv[3]
    rng = random.Random(20261019)
    counts = {}
    for n in ("truncate", "corrupt", "shrink", "nonelf"):
        for k in ("runs", "clean", "refused", "crashed"):
            counts[n + "_" + k] = 0
    bad = []
    tmp = os.path.join(scratch, "robust.o")
    bases = [
        f
        for f in ("maps.v3.O2.o", "btfkinds.v3.O2.o", "exotic.asm.o",
                  "badflow.asm.o", "padding.asm.o")
        if os.path.exists(os.path.join(corpus, f))
    ]
    if len(bases) < 4:
        print("robust: only %d base objects found" % len(bases), file=sys.stderr)
        return 2
    for b in bases:
        data = open(os.path.join(corpus, b), "rb").read()
        sweep("truncate", bpfdis, tmp, truncations(data), counts, bad)
        sweep("corrupt", bpfdis, tmp, corruptions(data, rng), counts, bad)
        sweep("shrink", bpfdis, tmp, shrinks(data), counts, bad)

    # Inputs that are not objects at all.
    junk = [
        ("empty", b""),
        ("magic only", b"\x7fELF"),
        ("elf32", b"\x7fELF\x01\x01\x01" + b"\0" * 57),
        ("big endian", b"\x7fELF\x02\x02\x01" + b"\0" * 57),
        ("text", b"#!/bin/sh\necho hello\n" * 50),
        ("all ff", b"\xff" * 4096),
        ("random", bytes(rng.randrange(256) for _ in range(4096))),
    ]
    for _ in range(100):
        n = rng.randrange(1, 3000)
        junk.append(("random %d" % n,
                     bytes(rng.randrange(256) for _ in range(n))))
    # An ELF header with a plausible shape and hostile section headers.
    good = open(os.path.join(corpus, bases[0]), "rb").read()
    for field, off in (("e_shoff", 0x28), ("e_shnum", 0x3C), ("e_shstrndx", 0x3E)):
        for v in (0xFFFFFFFF, 0x7FFFFFFF, 1, 0):
            b = bytearray(good)
            for i in range(4 if field == "e_shoff" else 2):
                b[off + i] = (v >> (8 * i)) & 0xFF
            junk.append(("%s := %#x" % (field, v), bytes(b)))
    sweep("nonelf", bpfdis, tmp, junk, counts, bad)

    for k in sorted(counts):
        print("%s=%d" % (k, counts[k]))
    for b in bad:
        print("  " + b)
    ok = all(counts[n + "_crashed"] == 0
             for n in ("truncate", "corrupt", "shrink", "nonelf"))
    # Both directions, for every sweep that can have both. The truncation
    # sweep cannot: a clang object keeps its section header table at the
    # end of the file, so every prefix of it is refused at the header, and
    # the shrink sweep above exists because of that.
    for n in ("corrupt", "shrink"):
        if counts[n + "_clean"] == 0 or counts[n + "_refused"] == 0:
            print("  %s sweep is one-sided: %d clean, %d refused"
                  % (n, counts[n + "_clean"], counts[n + "_refused"]))
            ok = False
    if counts["truncate_refused"] == 0:
        print("  the truncation sweep refused nothing")
        ok = False
    if counts["nonelf_refused"] == 0:
        print("  nothing in the junk sweep was refused")
        ok = False
    try:
        os.unlink(tmp)
    except OSError:
        pass
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
