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

# The sweep imports t/llvmbpf.py, and an import writes a __pycache__ next to
# it. `cq c` stages the whole tree, so a stray build artifact becomes a
# tracked file; two of them already did once.
export PYTHONDONTWRITEBYTECODE=1

W=$(mktemp -d) || exit 2
trap 'rm -rf "$W"' EXIT INT TERM

# ---------------------------------------------------------------- the corpus
note "corpus"
n=$(sh "$HERE/mkcorpus.sh" "$W/obj")
if [ "${n:-0}" -ge 56 ]; then
    ok "corpus built ($n objects)"
else
    no "corpus built only ${n:-0} objects, expected at least 56"
fi
set -- "$W"/obj/*.o
if [ "$#" -lt 56 ]; then
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
if [ "${agree:-0}" -ge 3100 ]; then
    ok "instruction comparison is non-vacuous ($agree instructions)"
else
    no "instruction comparison covered only ${agree:-0} instructions"
fi
for b in disagree we_refuse llvm_refuse bytes_differ only_llvm only_ours \
         reloc_differ func_differ; do
    v=$(dget $b)
    if [ "${v:-1}" -eq 0 ]; then
        ok "bucket $b is empty"
    else
        no "bucket $b holds $v instructions"
    fi
done
for f in reloc_agree func_agree llvm_cannot_read allowed_roundtrip; do
    v=$(dget $f)
    if [ "${v:-0}" -gt 0 ]; then
        ok "$f is non-vacuous ($v records)"
    else
        no "$f is zero; the fixture that exercises it is missing"
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

# -------------------------------- oracle 3: llvm-mc, over the encoding space
note "oracle: llvm-mc, sweeping encodings no compiler emits"
sout=$(python3 "$HERE/opcode_sweep.py" "$BIN")
src_=$?
echo "$sout" | grep -v "^  " | sed 's/^/     /'
echo "$sout" | grep "^  " | sed 's/^/     /' | head -40
sget() { echo "$sout" | sed -n "s/^$1=\([0-9-]*\)$/\1/p"; }
if [ $src_ -eq 0 ]; then
    ok "no encoding decodes differently in bpfdis and llvm-mc"
else
    no "the encoding sweep found a disagreement"
fi
sweepn=$(sget encodings)
if [ "${sweepn:-0}" -eq 24279 ]; then
    ok "the sweep is deterministic and covered $sweepn encodings"
else
    no "the sweep covered ${sweepn:-0} encodings, expected 24279"
fi
sa=$(sget agree)
if [ "${sa:-0}" -ge 8000 ]; then
    ok "sweep agreement is non-vacuous ($sa encodings decoded identically)"
else
    no "sweep agreed on only ${sa:-0} encodings"
fi
sb=$(sget both_refuse)
if [ "${sb:-0}" -ge 10000 ]; then
    ok "the sweep reaches unallocated encoding space ($sb refused by both)"
else
    no "the sweep refused only ${sb:-0} encodings; it is not reaching bad space"
fi
# Every bucket that is not plain agreement has to be accounted for by an
# outside authority, not by an opinion written here.
v=$(sget we_refuse_llvm_faithful)
if [ "${v:-1}" -eq 0 ]; then
    ok "every encoding bpfdis refuses is one llvm-mc decodes lossily ($(sget we_refuse_llvm_lossy) of them)"
else
    no "$v encodings are refused by bpfdis while llvm round-trips them faithfully"
fi
if [ "$(sget over_accept_clean)" = "$(sget over_accept_confirmed)" ] \
   && [ "${v:-1}" -eq 0 ]; then
    ok "every unflagged over-acceptance is confirmed by llvm-mc as an assembler ($(sget over_accept_clean))"
else
    no "an over-acceptance is not confirmed by the assembler"
fi
v=$(sget over_accept_flagged_unchecked)
if [ "${v:-1}" -eq 0 ]; then
    ok "all $(sget over_accept_flagged) flagged over-acceptances survive having their dirty fields cleaned"
else
    no "$v flagged over-acceptances could not be confirmed"
fi
v=$(sget allowed_roundtrip)
if [ "${v:-0}" -gt 0 ]; then
    ok "$v divergences are LLVM disagreeing with itself, proved by assembling our text back"
else
    no "the assembler round-trip rule never fired"
fi

# ------------------------------------------- oracle 5: bpftool, for BTF
note "oracle: bpftool btf dump (libbpf), line for line"
bout=$(python3 "$HERE/btfcmp.py" "$BIN" "$W"/obj/*.o)
brc=$?
echo "$bout" | grep -v "^  " | sed 's/^/     /'
if [ $brc -eq 0 ]; then
    ok "every BTF line matches bpftool byte for byte"
else
    no "BTF output differs from bpftool"
    echo "$bout" | grep "^  " | head -20
fi
bget() { echo "$bout" | sed -n "s/^$1=\([0-9]*\)$/\1/p"; }
v=$(bget btf_types)
if [ "${v:-0}" -ge 1000 ]; then
    ok "BTF comparison is non-vacuous ($v type records, $(bget btf_lines) lines)"
else
    no "BTF comparison covered only ${v:-0} type records"
fi
v=$(bget btf_kinds)
if [ "${v:-0}" -ge 19 ]; then
    ok "all 19 BTF kinds are reached by the corpus"
else
    no "the corpus reaches only ${v:-0} BTF kinds of 19"
fi

# ------------------------------------------ oracle 6: libbpf itself
note "oracle: libbpf, for maps and programs"
if cc -O1 -o "$W/lp" "$HERE/libbpf_probe.c" -ldl 2>"$W/lp.err"; then
    lout=$(python3 "$HERE/libbpfcmp.py" "$W/lp" "$BIN" "$W"/obj/*.o)
    lrc=$?
    echo "$lout" | grep -v "^  " | sed "s/^/     /"
    if [ $lrc -eq 0 ]; then
        ok "maps and programs agree with libbpf"
    else
        no "maps or programs disagree with libbpf"
        echo "$lout" | grep "^  " | head -20
    fi
    lget() { echo "$lout" | sed -n "s/^$1=\([0-9]*\)$/\1/p"; }
    v=$(lget libbpf_opened)
    if [ "${v:-0}" -ge 50 ]; then
        ok "libbpf opened $v of the corpus objects"
    else
        no "libbpf opened only ${v:-0} objects; the comparison is near-vacuous"
    fi
    v=$(lget maps_compared)
    if [ "${v:-0}" -ge 60 ]; then
        ok "map comparison is non-vacuous ($v map records)"
    else
        no "map comparison covered only ${v:-0} records"
    fi
    v=$(lget progs_compared)
    if [ "${v:-0}" -ge 100 ]; then
        ok "program comparison is non-vacuous ($v programs)"
    else
        no "program comparison covered only ${v:-0} programs"
    fi
    # libbpf 1.0 removed legacy map sections. That refusal is the reason
    # bpfdis's legacy reader has no oracle, and it is asserted rather than
    # remembered, because if libbpf ever opened them the README would be
    # wrong and the legacy path would suddenly be checkable.
    if [ "$(lget libbpf_refused)" -gt 0 ]; then
        ok "libbpf refused $(lget libbpf_refused) objects, legacy map sections among them"
    else
        no "libbpf refused nothing; the note about legacy maps needs re-measuring"
    fi
else
    no "libbpf_probe did not build"; cat "$W/lp.err"
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
