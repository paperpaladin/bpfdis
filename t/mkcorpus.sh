#!/bin/sh
# Build the corpus into $1. Every source is compiled at several -mcpu levels,
# because the ISA version decides which opcodes clang is allowed to emit:
# v1 has no 32-bit jumps, v3 has them, v4 adds movsx/ldsx/sdiv/bswap/gotol.
set -eu
OUT=$1
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$OUT"
built=0
for src in "$HERE"/corpus/*.c; do
    b=$(basename "$src" .c)
    # Two sources are built once rather than at every -mcpu and -O level.
    # sections.c is 91 copies of the same two instructions, one per row of
    # the section-name table, and eight copies of that would add 1456
    # identical instructions to the disassembly comparison and make the
    # number look like variety it does not have. oddpin.c is an object
    # libbpf refuses outright, so every copy is a copy of nothing it can
    # compare.
    if [ "$b" = sections ] || [ "$b" = oddpin ]; then
        o="$OUT/$b.v3.O2.o"
        clang -target bpf -mcpu=v3 -O2 -g -c "$src" -o "$o" && built=$((built+1))
        continue
    fi
    for cpu in v1 v2 v3 v4; do
        for opt in O2 O1; do
            o="$OUT/$b.$cpu.$opt.o"
            if clang -target bpf -mcpu=$cpu -$opt -g -c "$src" -o "$o" 2>"$o.err"; then
                built=$((built+1))
                rm -f "$o.err"
            else
                rm -f "$o" "$o.err"
            fi
        done
    done
done
for src in "$HERE"/corpus/*.s; do
    [ -e "$src" ] || continue
    b=$(basename "$src" .s)
    o="$OUT/$b.asm.o"
    if clang -target bpf -mcpu=v4 -c "$src" -o "$o" 2>"$o.err"; then
        built=$((built+1)); rm -f "$o.err"
    else
        echo "mkcorpus: $src failed to assemble:" >&2; cat "$o.err" >&2; rm -f "$o" "$o.err"
    fi
done
echo "$built"
