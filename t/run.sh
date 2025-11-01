#!/bin/sh
# bpfdis test suite.
#
# Run it as `make test`, never directly: the Makefile's test target depends on
# `all`, and a harness that does not build the thing it tests reports passes
# for whatever binary was lying around. The staleness guard below is a second
# line of defence for when it is invoked directly anyway.
#
# Final line is exactly "N passed, M failed"; the collection's tooling parses
# it.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname "$HERE")
BIN=$ROOT/target/release/bpfdis

pass=0
fail=0
ok()   { pass=$((pass+1)); echo "ok   $*"; }
no()   { fail=$((fail+1)); echo "FAIL $*"; }
note() { echo "--- $*"; }

if [ ! -x "$BIN" ]; then
    echo "bpfdis: $BIN does not exist; run make test, not t/run.sh" >&2
    exit 2
fi
for f in "$ROOT"/src/*.rs "$ROOT"/Cargo.toml; do
    if [ "$f" -nt "$BIN" ]; then
        echo "bpfdis: $f is newer than $BIN; run make test, not t/run.sh" >&2
        exit 2
    fi
done

for tool in clang llvm-objdump llvm-mc readelf; do
    command -v $tool >/dev/null 2>&1 || {
        echo "bpfdis: $tool is not installed; it is the oracle for most of" \
             "this suite and a reduced run would report passes having" \
             "checked nothing" >&2
        exit 2
    }
done

W=$(mktemp -d) || exit 2
trap 'rm -rf "$W"' EXIT INT TERM

# ---------------------------------------------------------------- the corpus
note "corpus"
n=$(sh "$HERE/mkcorpus.sh" "$W/obj")
if [ "${n:-0}" -ge 40 ]; then
    ok "corpus built ($n objects)"
else
    no "corpus built only ${n:-0} objects, expected at least 40"
fi
set -- "$W"/obj/*.o
if [ "$#" -lt 40 ]; then
    no "corpus directory holds $# objects"
fi

# ------------------------------------------------- oracle 1: is it reachable
note "oracle: the kernel verifier"
if cc -O1 -o "$W/vp" "$HERE/verifier_probe.c" 2>"$W/vp.err"; then
    vout=$("$W/vp" 2>&1)
    case "$vout" in
        VERIFIER:*) ok "verifier probe ran: $vout" ;;
        *) no "verifier probe printed no verdict: $vout" ;;
    esac
else
    no "verifier probe did not compile"; cat "$W/vp.err"
fi

# --------------------------------------------------- oracle 4: GNU binutils
note "oracle: readelf (GNU binutils), per record"
if out=$(python3 "$HERE/elfcmp.py" "$BIN" "$W"/obj/*.o); then
    echo "$out" | sed 's/^/     /'
    ok "ELF sections, symbols and relocations agree with readelf"
else
    echo "$out" | sed 's/^/     /'
    no "ELF facts disagree with readelf"
fi
for facet in sections symbols relocs; do
    tot=$(echo "$out" | sed -n "s/^$facet total=\([0-9]*\).*/\1/p")
    if [ "${tot:-0}" -gt 0 ]; then
        ok "$facet comparison is non-vacuous ($tot records)"
    else
        no "$facet comparison compared nothing"
    fi
done

# -------------------------------------- oracle 2: LLVM, per instruction
note "oracle: llvm-objdump, per instruction"
dout=$(python3 "$HERE/disasm_cmp.py" "$BIN" "$W"/obj/*.o)
drc=$?
echo "$dout" | grep -v '^  ' | sed 's/^/     /'
if [ $drc -eq 0 ]; then
    ok "every decoded instruction matches llvm-objdump"
else
    no "instructions disagree with llvm-objdump"
    echo "$dout" | grep '^  ' | head -30
fi
dget() { echo "$dout" | sed -n "s/^$1=\([0-9-]*\)$/\1/p"; }
agree=$(dget agree)
if [ "${agree:-0}" -ge 3000 ]; then
    ok "instruction comparison is non-vacuous ($agree instructions)"
else
    no "instruction comparison covered only ${agree:-0} instructions"
fi
for b in disagree we_refuse llvm_refuse bytes_differ only_llvm only_ours; do
    v=$(dget $b)
    if [ "${v:-1}" -eq 0 ]; then
        ok "bucket $b is empty"
    else
        no "bucket $b holds $v instructions"
    fi
done
# The allow-list exists for one measured divergence. If it ever stops firing,
# either the corpus lost its subprogram calls or the rule stopped matching,
# and both are reasons to look rather than to report a pass.
lc=$(dget allowed_local_call)
if [ "${lc:-0}" -gt 0 ]; then
    ok "the local-call divergence from llvm-objdump fired $lc times"
else
    no "the local-call allow-list rule never fired; it is not being exercised"
fi

# ----------------------------------------------------------------- exit codes
note "exit status"
"$BIN" >/dev/null 2>&1; [ $? -eq 2 ] && ok "no argument is a usage error (2)" \
    || no "no argument did not exit 2"
"$BIN" --nonsense "$W/obj" >/dev/null 2>&1; [ $? -eq 2 ] \
    && ok "unknown option is a usage error (2)" || no "unknown option did not exit 2"
"$BIN" "$W/no-such-file" >/dev/null 2>&1; [ $? -eq 1 ] \
    && ok "missing file is a malformed-input error (1)" || no "missing file did not exit 1"
printf 'not an elf file at all\n' > "$W/text"
"$BIN" "$W/text" >/dev/null 2>&1; [ $? -eq 1 ] \
    && ok "non-ELF input exits 1" || no "non-ELF input did not exit 1"
"$BIN" "$W" >/dev/null 2>&1; [ $? -eq 1 ] \
    && ok "a directory exits 1" || no "a directory did not exit 1"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
