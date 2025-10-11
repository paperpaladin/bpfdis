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
