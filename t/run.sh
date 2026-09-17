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

# ------------------------------------------- which tools produced the numbers
#
# Every figure this suite prints is a figure about one toolchain. The README
# says several of the measured behaviours are version-specific, and which
# atomic encodings LLVM's disassembler refuses is one of them, so the
# versions belong in the output that produces the numbers rather than in a
# sentence somebody has to remember to update.
note "oracle versions"
echo "     clang        $(clang --version | sed -n '1s/.*version //p')"
echo "     llvm-objdump $(llvm-objdump --version | sed -n 's/.*LLVM version //p')"
echo "     llvm-mc      $(llvm-mc --version | sed -n 's/.*LLVM version //p')"
echo "     readelf      $(readelf --version | sed -n '1s/.* //p')"
if [ -x /usr/sbin/bpftool ]; then
    echo "     bpftool      $(/usr/sbin/bpftool version 2>/dev/null | sed -n '1s/^bpftool //p') with libbpf $(/usr/sbin/bpftool version 2>/dev/null | sed -n '2s/^using libbpf //p')"
fi
echo "     kernel       $(uname -r)"
# llvm-mc and llvm-objdump share a backend and the suite treats one as a
# check on the other in places, so a mismatched pair would make a
# disagreement between them mean something different from what is written
# down about it.
a=$(llvm-objdump --version | sed -n 's/.*LLVM version //p')
b=$(llvm-mc --version | sed -n 's/.*LLVM version //p')
if [ -n "$a" ] && [ "$a" = "$b" ]; then
    ok "llvm-objdump and llvm-mc are both LLVM $a"
else
    no "llvm-objdump is LLVM ${a:-?} and llvm-mc is LLVM ${b:-?}"
fi

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
         reloc_differ func_differ target_differ; do
    v=$(dget $b)
    if [ "${v:-1}" -eq 0 ]; then
        ok "bucket $b is empty"
    else
        no "bucket $b holds $v instructions"
    fi
done
for f in reloc_agree func_agree llvm_cannot_read allowed_roundtrip target_agree; do
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

# ---------------- subprogram calls that cross a section (hand-read fixture)
#
# A program calls its subprograms in `.text` through a relocation, and the
# target is the symbol's slot plus the offset llvm left in `imm`. Nothing
# installed here resolves that for an unlinked object, so the expected
# depths below are read off t/corpus/calls.c by hand: caller calls mix and
# fold, fold calls mix, globalcall calls global_sub. Weaker than the rest of
# this file and written out here rather than hidden in a comparison.
#
# Without the relocation path every one of these is 1, which is also what a
# missing edge looks like, so the numbers are what prove the path ran.
note "subprogram call depth across sections (hand-read, no oracle)"
dchk() {
    got=$("$BIN" -a "$W/obj/calls.v3.O2.o" 2>/dev/null \
          | sed -n "s/^analysis [^ ]* $1 .* depth=\([0-9]*\) .*/\1/p")
    if [ "${got:-}" = "$2" ]; then
        ok "$1 is $2 call frames deep"
    else
        no "$1 is ${got:-missing} call frames deep, expected $2"
    fi
}
dchk caller 3
dchk globalcall 3
dchk fold 2
dchk mix 1
dchk global_sub 2

# ------------- the oversized-buffer rule, in the form Rust leaves open
#
# `make overread` covers the one place where a buffer longer than its data
# turns a panic into a wrong answer. This covers the other shape: a buffer
# the right size for a full record, filled from a section that is shorter,
# where the leftover zeros are reported as though they had been read. Rust
# calls none of that uninitialised and nothing crashes, so the only thing
# that can tell the two apart is a reader that counts what it actually got.
note "a legacy map with less section behind it than the struct needs"
mout=$("$BIN" -m "$W/obj/shortmap.asm.o" 2>&1)
case "$mout" in
    *"only 3 of the 5 words"*)
        ok "a 12-byte struct bpf_map_def is reported as 3 words of 5" ;;
    *)
        no "the short legacy map was read without saying how much was there: $mout" ;;
esac
case "$mout" in
    *"max_entries=0"*)
        ok "the words with no file behind them are reported as zero, beside the note" ;;
    *)
        no "the short legacy map did not report a zero for a missing word: $mout" ;;
esac

# ------------- the one attach-type fact libbpf cannot confirm either way
#
# bpf_program__expected_attach_type returns 0 both for a section with no
# attach type and for cgroup_skb/ingress, whose attach type really is zero.
# bpfdis keeps those apart, printing -1 for the first, and the libbpf
# comparison maps -1 back to 0 before asking, so the distinction is invisible
# to the oracle. It is asserted here instead, which is the same treatment the
# call src_reg divergence gets in the disassembly comparison.
note "attach type 0 and no attach type, which libbpf reports identically"
pout=$("$BIN" -P "$W/obj/sections.v3.O2.o" 2>/dev/null)
case "$pout" in
    *"sec=cgroup_skb/ingress type=8 (CGROUP_SKB) attach=0 (cgroup_inet_ingress)"*)
        ok "cgroup_skb/ingress is attach type 0, and says so" ;;
    *)
        no "cgroup_skb/ingress did not report attach type 0" ;;
esac
case "$pout" in
    *"sec=socket type=1 (SOCKET_FILTER) attach=-1 (-)"*)
        ok "a socket filter has no attach type, and says that rather than 0" ;;
    *)
        no "the socket section did not report an absent attach type" ;;
esac

# ------------------------------------------- big-endian BPF: refused, cleanly
#
# METHOD's unimpl() shape: the oracle must ACCEPT the input and bpfdis must
# refuse it in a way that says why. The failure mode of a missing feature is
# not a missing error message, it is reading the file anyway and getting
# every field byte-swapped, which for BPF means a plausible-looking
# disassembly of different instructions.
note "big-endian BPF, which llvm-objdump reads and bpfdis refuses"
if clang -target bpfeb -mcpu=v3 -O2 -c "$HERE/corpus/basic.c" -o "$W/eb.o" 2>/dev/null; then
    n=$(llvm-objdump -d --triple=bpfeb "$W/eb.o" 2>/dev/null | grep -cE "^\s+[0-9]+:")
    if [ "${n:-0}" -ge 20 ]; then
        ok "llvm-objdump decodes $n instructions from the big-endian object"
    else
        no "llvm-objdump read only ${n:-0} instructions; the object is not a fixture"
    fi
    msg=$("$BIN" -A "$W/eb.o" 2>&1 >/dev/null)
    rc=$?
    case "$rc:$msg" in
        1:*not\ little-endian*)
            ok "bpfdis refuses it with exit 1 and names the reason: $msg" ;;
        *)
            no "bpfdis exited $rc on a big-endian object saying: $msg" ;;
    esac
else
    no "clang cannot build for bpfeb; the big-endian refusal is untested"
fi

# ---------------- the name tables, against the lists bpftool was built with
#
# `bpftool feature list_builtins` prints the helper, program-type and
# map-type names in the order of the kernel's enumerations and needs no
# privilege. Both sides of this comparison came from that command once, so
# it proves transcription fidelity rather than anything about the kernel,
# and the README says so. It still earns itself: a bpftool from a different
# kernel disagrees, and so does a name edited by hand.
note "oracle: bpftool feature list_builtins, for the name tables"
nout=$(python3 "$HERE/nametables.py" "$ROOT/src" "$BIN" "$W"/obj/*.o)
nrc=$?
echo "$nout" | grep -v "^  " | sed "s/^/     /"
if [ $nrc -eq 0 ]; then
    ok "every helper, program-type and map-type name matches bpftool's own list"
else
    no "a name table disagrees with bpftool"
    echo "$nout" | grep "^  " | head -20
fi
nget() { echo "$nout" | sed -n "s/^$1=\([0-9]*\)$/\1/p"; }
v=$(nget helper_names)
if [ "${v:-0}" -ge 200 ]; then
    ok "the helper name table is $v entries and all of them are compared"
else
    no "only ${v:-0} helper names were compared"
fi
v=$(nget helpers_named_in_corpus)
if [ "${v:-0}" -ge 40 ]; then
    ok "$v helper calls in the corpus are named, and the names match bpftool's list"
else
    no "only ${v:-0} helper calls were named; the lookup is barely exercised"
fi
v=$(nget corpus_helper_decls)
if [ "${v:-0}" -ge 10 ]; then
    ok "$v helper ids declared in t/corpus/bpf.h are the ones bpftool names"
else
    no "only ${v:-0} helper declarations were checked against bpftool"
fi

# ------------------------------- the disassembler oracles that are not here
#
# Every instruction number in this suite comes from LLVM, and the README says
# so in its what-does-not-work section. The two tools that could have been a
# second opinion are measured here rather than remembered, because each of
# these assertions is the kind that should turn red one day: a binutils with
# a BPF target, or a bpftool built with a disassembler, would make a real
# second authority available and the README would be wrong the moment it
# arrived.
note "the disassemblers this machine does not have"
if objdump -d "$W"/obj/basic.v3.O2.o >/dev/null 2>"$W/od.err"; then
    no "GNU objdump disassembled a BPF object; it is a second oracle now"
elif grep -q "UNKNOWN" "$W/od.err"; then
    ok "GNU binutils $(objdump --version | sed -n 's/^GNU objdump.* \([0-9.]*\)$/\1/p') has no BPF target: $(head -1 "$W/od.err")"
else
    no "GNU objdump refused a BPF object for an unexpected reason: $(head -1 "$W/od.err")"
fi
if [ -x /usr/sbin/bpftool ]; then
    bf=$(/usr/sbin/bpftool -p version 2>/dev/null | sed -n 's/.*"libbfd": *\([a-z]*\).*/\1/p')
    bl=$(/usr/sbin/bpftool -p version 2>/dev/null | sed -n 's/.*"llvm": *\([a-z]*\).*/\1/p')
    if [ "${bf:-}" = "false" ] && [ "${bl:-}" = "false" ]; then
        ok "bpftool was built with neither libbfd nor llvm, so it cannot disassemble"
    else
        no "bpftool reports libbfd=${bf:-?} llvm=${bl:-?}; it may disassemble now"
    fi
    # `prog dump xlated` takes id, tag, name or pinned and has no file form,
    # so it needs a loaded program, and loading is what the privilege check
    # refuses. Asking for the program list is the cheapest way to show it.
    if /usr/sbin/bpftool prog list >/dev/null 2>"$W/bt.err"; then
        no "bpftool can list loaded programs; prog dump xlated may be reachable"
    else
        ok "bpftool cannot reach a loaded program: $(head -1 "$W/bt.err")"
    fi
else
    no "/usr/sbin/bpftool is missing; it is the only oracle for BTF"
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

# --------------------------------- .BTF.ext, against bpftool, readelf, DWARF
note "oracle: bpftool types, readelf symbols and DWARF lines, for .BTF.ext"
xout=$(python3 "$HERE/btfextcmp.py" "$BIN" "$W"/obj/*.o)
xrc=$?
echo "$xout" | grep -v "^  " | sed "s/^/     /"
if [ $xrc -eq 0 ]; then
    ok "every func_info and line_info record agrees with another reader"
else
    no ".BTF.ext records disagree with bpftool, readelf or DWARF"
    echo "$xout" | grep "^  " | head -20
fi
xget() { echo "$xout" | sed -n "s/^$1=\([0-9]*\)$/\1/p"; }
v=$(xget func_info_compared)
if [ "${v:-0}" -ge 200 ]; then
    ok "func_info comparison is non-vacuous ($v records)"
else
    no "func_info comparison covered only ${v:-0} records"
fi
v=$(xget line_info_compared)
if [ "${v:-0}" -ge 1000 ]; then
    ok "line_info comparison is non-vacuous ($v records against DWARF)"
else
    no "line_info comparison covered only ${v:-0} records"
fi
# Every line_info record must land on an instruction DWARF also has a line
# for. A record DWARF says nothing about is not a disagreement, but it is a
# record this comparison did not check, so it is counted and required to
# stay at zero rather than being left to grow unseen.
v=$(xget line_info_no_dwarf)
if [ "${v:-1}" -eq 0 ]; then
    ok "no line_info record falls on an instruction DWARF has no line for"
else
    no "$v line_info records are at instructions DWARF says nothing about"
fi
v=$(xget line_info_entry)
if [ "${v:-0}" -gt 0 ]; then
    ok "$v function entries where BTF.ext names the declaration and DWARF the brace"
else
    no "no function entry was compared; the declaration-line rule is untested"
fi
# The CO-RE table has no outside reader at all. All that can be asked of it
# is that it points at things that exist, and that every kind the decoder
# can name is reached by t/corpus/core.c, so no row of that list is a guess
# nothing runs over.
v=$(xget core_relo_bad)
if [ "${v:-1}" -eq 0 ]; then
    ok "all $(xget core_relo_records) core_relo records name a real BTF type and a known kind"
else
    no "$v core_relo records point at something that is not there"
fi
v=$(xget core_relo_kinds)
if [ "${v:-0}" -eq 13 ]; then
    ok "all 13 CO-RE relocation kinds are reached by the corpus"
else
    no "the corpus reaches only ${v:-0} CO-RE relocation kinds of 13"
fi

# -------------------------------- stack depth, against LLVM's own accounting
note "oracle: clang -mllvm -bpf-stack-size, for the stack frame"
kout=$(python3 "$HERE/stackcmp.py" "$BIN" "$W/obj" "$HERE/corpus")
krc=$?
echo "$kout" | grep -v "^  " | sed "s/^/     /"
if [ $krc -eq 0 ]; then
    ok "every stack depth is pinned between a limit clang refuses and one it accepts"
else
    no "a stack depth disagrees with clang"
    echo "$kout" | grep "^  " | head -20
fi
kget() { echo "$kout" | sed -n "s/^$1=\([0-9]*\)$/\1/p"; }
if [ "$(kget stack_nonzero_checked)" -ge 10 ] && [ "$(kget stack_zero_checked)" -ge 10 ]; then
    ok "stack check covers $(kget stack_nonzero_checked) frames and $(kget stack_zero_checked) empty ones"
else
    no "the stack check is near-vacuous"
fi

# Two shapes clang never emits, and for which no oracle exists. The numbers
# below are read off the five instructions in t/corpus/stackderived.s and
# are asserted as hand-computed values, which is weaker than everything
# else in this file and is why they are written out here rather than being
# folded into the comparison above. They exist because two mutations
# survived the whole compiled corpus: dropping the base register's own
# frame offset, and letting a 32-bit move carry the frame-pointer fact.
note "stack depth through a register that is not r10 (hand-computed, no oracle)"
sa=$("$BIN" -a "$W/obj/stackderived.asm.o" 2>/dev/null \
     | sed -n 's/^analysis \.text derived .*stack=\([0-9]*\) .*/\1/p')
sb=$("$BIN" -a "$W/obj/stackderived.asm.o" 2>/dev/null \
     | sed -n 's/^analysis \.text truncated .*stack=\([0-9]*\) .*/\1/p')
[ "${sa:-}" = "32" ] && ok "a store at (r10 - 8) - 24 makes a 32-byte frame" \
    || no "derived-base frame is ${sa:-missing}, expected 32"
[ "${sb:-}" = "0" ] && ok "a 32-bit move of r10 does not produce a stack address" \
    || no "truncated-pointer frame is ${sb:-missing}, expected 0"

# ------------------------------------------ oracle 6: libbpf itself
note "oracle: libbpf, for maps and programs"
if cc -O1 -o "$W/lp" "$HERE/libbpf_probe.c" -ldl 2>"$W/lp.err"; then
    lout=$(python3 "$HERE/libbpfcmp.py" "$W/lp" "$BIN" "$ROOT/src/prog.rs" \
                   "$HERE/corpus/maps.c" "$W"/obj/*.o)
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
    # The legacy maps are the half libbpf refuses, so they are checked
    # against the source they were compiled from. All five fields are the
    # same width, so a reader that takes them in the wrong order gets no
    # warning from anywhere else in the suite.
    v=$(lget legacy_differ)
    if [ "${v:-1}" -eq 0 ] && [ "$(lget legacy_compared)" -gt 0 ]; then
        ok "$(lget legacy_compared) legacy bpf_map_def records read back what the source declares"
    else
        no "${v:-?} legacy map records differ from their source declaration"
    fi
    if [ "$(lget libbpf_refused)" -gt 0 ]; then
        ok "libbpf refused $(lget libbpf_refused) objects, legacy map sections among them"
    else
        no "libbpf refused nothing; the note about legacy maps needs re-measuring"
    fi
    # Every row of the section-name table in src/prog.rs has to be reached
    # by a section in the corpus. A row nothing exercises is a number nobody
    # checked, and this table is transcribed from a header that is not
    # installed here, so it is exactly where a transcription error lives.
    # The row count is asserted as well as the unreached count. A regex
    # that stopped matching the table reported zero rows, zero unreached
    # and a pass, which is the vacuous shape this file exists to avoid.
    v=$(lget sectype_unreached)
    if [ "${v:-1}" -eq 0 ] && [ "$(lget sectype_rows)" -ge 80 ]; then
        ok "all $(lget sectype_rows) section-name table rows are reached and agree with libbpf"
    else
        no "${v:-?} of $(lget sectype_rows) section-name table rows are reached by nothing"
    fi
    # prog_type returns the first row that matches, so the table has to be
    # unambiguous for that to be the right answer.
    v=$(lget sectype_ambiguous)
    if [ "${v:-1}" -eq 0 ]; then
        ok "no corpus section matches two section-name table rows"
    else
        no "$v corpus sections match more than one table row"
    fi
else
    no "libbpf_probe did not build"; cat "$W/lp.err"
fi

# ---------------------------- a pinning value libbpf refuses the object for
#
# METHOD's refuse() shape: the oracle rejects the input and bpfdis must say
# something about it rather than reading on quietly. libbpf fails
# bpf_object__open with "invalid pinning value 2", so it contributes nothing
# else about this object, and what bpfdis says has to be asserted here.
note "a map pinning value outside the two libbpf defines"
pin=$("$BIN" -m "$W/obj/oddpin.v3.O2.o" 2>&1)
case "$pin" in
    *"pinning is 2"*) ok "pinning 2 is reported as outside what libbpf defines" ;;
    *) no "a pinning value of 2 was read without comment: $pin" ;;
esac
case "$pin" in
    *"pin=-"*) ok "and the map is not reported as pinned anywhere" ;;
    *) no "a map with pinning 2 was given a pin path: $pin" ;;
esac
if "$W/lp" "$W/obj/oddpin.v3.O2.o" >/dev/null 2>&1; then
    no "libbpf opened the object with pinning 2; the refusal needs re-measuring"
else
    ok "libbpf refuses that object outright, which is why the two lines above exist"
fi

# ------------------------------------- .BTF.ext whose strings are not there
#
# Every string in .BTF.ext is an offset into .BTF's string table, so the two
# sections are one input in two pieces. An object with the second and not
# the first is a refusal, not an output full of empty names, and llvm-objcopy
# will make one in a line.
note ".BTF.ext with its string table removed"
if llvm-objcopy --remove-section=.BTF "$W/obj/flow.v3.O2.o" "$W/nobtf.o" 2>/dev/null; then
    msg=$("$BIN" -e "$W/nobtf.o" 2>&1 >/dev/null)
    rc=$?
    case "$rc:$msg" in
        1:*".BTF.ext with no .BTF"*)
            ok "a .BTF.ext with no .BTF exits 1 and says which section is missing" ;;
        *)
            no "a .BTF.ext with no .BTF exited $rc saying: $msg" ;;
    esac
    # And the other way round, which must still work: .BTF alone is a
    # complete input and -b has to read it.
    if llvm-objcopy --remove-section=.BTF.ext "$W/obj/flow.v3.O2.o" "$W/noext.o" 2>/dev/null; then
        n=$("$BIN" -b "$W/noext.o" 2>/dev/null | grep -c .)
        if [ "${n:-0}" -gt 10 ]; then
            ok ".BTF without .BTF.ext still dumps $n lines of types"
        else
            no ".BTF without .BTF.ext produced ${n:-0} lines"
        fi
    else
        no "llvm-objcopy could not remove .BTF.ext"
    fi
else
    no "llvm-objcopy could not remove .BTF; the paired-section case is untested"
fi

# ----------------------- the control-flow graph, against a second one in t/
note "cfg: a second graph built from llvm-objdump's text, not from our decode"
cout=$(python3 "$HERE/cfgcmp.py" "$BIN" "$W"/obj/*.o)
crc=$?
echo "$cout" | grep -v "^  " | sed "s/^/     /"
if [ $crc -eq 0 ]; then
    ok "every basic block, edge and reachability flag matches the second graph"
else
    no "the two control-flow graphs differ"
    echo "$cout" | grep "^  " | head -20
fi
cget() { echo "$cout" | sed -n "s/^$1=\([0-9]*\)$/\1/p"; }
v=$(cget cfg_funcs)
if [ "${v:-0}" -ge 200 ]; then
    ok "the graph comparison covers $v functions"
else
    no "the graph comparison covered only ${v:-0} functions"
fi
v=$(cget cfg_edges)
if [ "${v:-0}" -ge 1000 ]; then
    ok "the graph comparison is non-vacuous ($v edges)"
else
    no "the graph comparison covered only ${v:-0} edges"
fi
# llvm-objdump elides runs of zero bytes and refuses three atomic encodings
# its own assembler emits, so a couple of corpus functions cannot be
# reconstructed from its output at all. The count is asserted small rather
# than zero: a skip that grows silently is a comparison quietly shrinking.
v=$(cget cfg_skipped)
if [ "${v:-99}" -le 4 ]; then
    ok "only $v functions are unreadable in llvm-objdump's output"
else
    no "$v functions were skipped; llvm-objdump could not read them"
fi

# ------------------------------------- the analysis: false positives, findings
note "analysis: clang's output must be clean, and every finding must be reached"
fout=$(python3 "$HERE/flowcheck.py" "$BIN" "$W/obj")
frc=$?
echo "$fout" | grep -v "^  " | sed "s/^/     /"
if [ $frc -eq 0 ]; then
    ok "no finding against any function clang produced, and all 9 findings reached"
else
    no "the analysis has a false positive or an unreached finding"
    echo "$fout" | grep "^  " | head -20
fi
fget() { echo "$fout" | sed -n "s/^$1=\([0-9]*\)$/\1/p"; }
v=$(fget compiled_functions)
if [ "${v:-0}" -ge 200 ]; then
    ok "the false-positive check covers $v compiled functions"
else
    no "the false-positive check covers only ${v:-0} functions"
fi

# ------------------------------------------------------------- hostile input
note "robustness: truncation, corruption, lying section headers"
rout=$(python3 "$HERE/robust.py" "$BIN" "$W/obj" "$W")
rrc=$?
echo "$rout" | grep -v "^  " | sed "s/^/     /"
if [ $rrc -eq 0 ]; then
    ok "no malformed input made bpfdis exit outside 0, 1 and 3"
else
    no "a malformed input crashed, hung, or a sweep was vacuous"
    echo "$rout" | grep "^  " | head -20
fi
rget() { echo "$rout" | sed -n "s/^$1=\([0-9]*\)$/\1/p"; }
tot=$(( $(rget truncate_runs) + $(rget corrupt_runs) + $(rget shrink_runs) \
        + $(rget nonelf_runs) + $(rget btf_runs) ))
if [ "$tot" -ge 5000 ]; then
    ok "the robustness sweep ran $tot inputs"
else
    no "the robustness sweep ran only $tot inputs"
fi
# A sweep where everything is refused has tested the magic check and
# nothing else, so both directions are asserted for the two sweeps that
# can have both.
for n in corrupt shrink btf; do
    if [ "$(rget ${n}_clean)" -gt 0 ] && [ "$(rget ${n}_refused)" -gt 0 ]; then
        ok "$n sweep is two-sided ($(rget ${n}_clean) parsed, $(rget ${n}_refused) refused)"
    else
        no "$n sweep is one-sided"
    fi
done

# ------------------------------- hostile text on the raw-decoding entry point
#
# The opcode sweep feeds -x 24279 well-formed lines. What it never feeds it
# is malformed TEXT, and -x is the one entry point whose input is not an ELF
# file: it splits a line on commas and whitespace, strips an 0x prefix and
# parses each token as a byte. Every refusal there has to be a BAD line and
# an exit of 0, never a panic and never a hang.
note "hostile input on the hex entry point"
hexbad=0
hexruns=0
hexrefused=0
while IFS= read -r line; do
    hexruns=$((hexruns+1))
    out=$(printf '%s\n' "$line" | timeout 10 "$BIN" -x 2>/dev/null)
    rc=$?
    if [ $rc -ne 0 ]; then
        hexbad=$((hexbad+1))
        [ $hexbad -le 5 ] && echo "     exit $rc on: $line"
    fi
    case "$out" in *BAD*) hexrefused=$((hexrefused+1)) ;; esac
done <<'HEXEOF'
b
0x
0xzz
b7 00 00 00 00 00 00
b7 00 00 00 00 00 00 00 00
,,,,,,,,
0x0x0x0x 0x0x 00 00 00 00 00 00
18 01 00 00 00 00 00 00
18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
-1 -1 -1 -1 -1 -1 -1 -1
100 00 00 00 00 00 00 00
b7,00,00,00,00,00,00,00
   b7	00   00 00 00 00 00 00
0xb7 0x00 0X00 0x00 0x00 0x00 0x00 0x00
ffffffffffffffffffffffffffffffff
HEXEOF
if [ $hexbad -eq 0 ]; then
    ok "all $hexruns malformed hex lines exited 0, none crashed or hung"
else
    no "$hexbad of $hexruns malformed hex lines exited non-zero"
fi
# Two-sided: some of those lines are well formed and must decode, or this
# is a sweep that only proves the refusal path exists.
if [ $hexrefused -gt 0 ] && [ $hexrefused -lt $hexruns ]; then
    ok "the hex sweep is two-sided ($hexrefused refused of $hexruns)"
else
    no "the hex sweep refused $hexrefused of $hexruns; it is one-sided"
fi
# And five thousand generated lines in one go, which the 15 above cannot
# reach: random separators, random prefixes, random token counts and
# tokens that are hex, nearly hex, or not hex at all. One invocation,
# because the assertion is that nothing crashes and a crash on line 3000
# shows up as a nonzero exit either way.
python3 - <<'GENEOF' > "$W/hexfuzz.txt"
import random
r = random.Random(20261021)
toks = ["00", "ff", "7f", "b7", "18", "zz", "0x", "0xb7", "-1", "100", "",
        "g0", "0X18", "FF", "0", "000"]
seps = [" ", ",", "\t", "  ", ", ", " ,"]
for _ in range(5000):
    n = r.randrange(0, 20)
    print(r.choice(seps).join(r.choice(toks) for _ in range(n)))
GENEOF
hout=$(timeout 60 "$BIN" -x < "$W/hexfuzz.txt" 2>/dev/null)
hrc=$?
hlines=$(printf '%s\n' "$hout" | grep -c . )
if [ $hrc -eq 0 ]; then
    ok "5000 generated hex lines exited 0 with $hlines lines of output"
else
    no "the generated hex sweep exited $hrc"
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
