# bpfdis

Reads an ELF relocatable object for `EM_BPF`, disassembles every executable
section one instruction at a time, decodes BTF and the map definitions, builds
a control-flow graph per function, and reports the properties the kernel
verifier would reject a program for. Rust 2021, `std` only, no dependencies
and no `unsafe`.

```
bpfdis [MODE...] FILE

  -S, --sections    the ELF section table
  -y, --symbols     the symbol table
  -r, --relocs      relocations, resolved against the symbol table
  -d, --disasm      every executable section, one line per instruction
      --raw         with -d, also print the raw bytes
  -c, --cfg         basic blocks and control-flow edges, per function
  -a, --analyse     the verifier-relevant report, per function
      --strict      with -a, exit 3 if any finding would be a rejection
  -P, --progs       the programs libbpf would find
  -m, --maps        map definitions, legacy and BTF-defined
  -b, --btf         the .BTF type section, in bpftool's own dump format
  -e, --btfext      the .BTF.ext section: func_info, line_info, CO-RE relocs
  -x, --hex         decode hex-encoded instructions from stdin
  -A, --all         every mode above
```

`make test` builds and runs the suite. It needs `clang`, `llvm-objdump`,
`llvm-mc` and `readelf`, and exits 2 without any of them rather than
reporting a smaller number having checked less. `bpftool`, `libbpf.so.1` and
`cc` widen the run when they are present.

## What it is measured against

Nothing here is checked against a value worked out by hand, except where this
file says so.

`llvm-objdump 19.1.7` with `-dr --triple=bpf` is the main oracle for the
disassembler, compared per instruction rather than per program: the two dumps
are lined up by (section, slot index), every number normalised to decimal
because the two printers differ on radix, and the text compared whole. A
per-program diff would say that something disagreed somewhere in four hundred
instructions. This names the opcode.

`llvm-mc 19.1.7` is used both ways. `--disassemble` takes raw bytes, so the
sweep reaches encodings no compiler will ever emit; `--assemble` turns the
question round, and is the arbiter wherever bpfdis and llvm-objdump differ. It
shares a backend with llvm-objdump, so it is not an independent second
opinion, but assembling our text back and requiring the original bytes is a
different question with a different failure mode.

`readelf 2.44` is GNU binutils and shares no code with LLVM. Authority for
section headers, symbols and relocations.

`bpftool 7.5.0` with `libbpf 1.5` is a third codebase. `bpftool btf dump file`
is the authority for BTF, compared line for line against our own `-b`. Its
`feature list_builtins` prints the helper, program-type and map-type names
in the order of the kernel's enumerations and needs no privilege, which
makes it the authority for the three name tables in `src`.

`libbpf 1.5` itself, through `t/libbpf_probe.c`, which `dlopen`s `libbpf.so.1`
and calls `bpf_object__open_file`. It is the authority for the map table, the
program list, and the program type each section name implies. Parsing needs no
privilege; it is `bpf_object__load` that does, and the probe never calls it. There are no
libbpf headers installed, so the seventeen entry points are declared from the
published API and resolved by name, and a missing symbol exits 2 rather than
producing an empty comparison.

`clang 19.1.7` builds the corpus, and `clang -mllvm -bpf-stack-size=N` is the
oracle for stack depth: the suite binary-searches the limit at which clang
refuses to compile a function and requires bpfdis's figure to sit between the
largest limit clang rejects and the smallest it accepts.

The corpus generator is the weakest of these, because we wrote it.

## The kernel verifier is out of reach, and that is a measurement

The only true authority for "would this program be rejected" is
`bpf(BPF_PROG_LOAD)`, and on this machine the syscall never reaches the
verifier. `t/verifier_probe.c` runs on every `make test` and prints:

```
VERIFIER: BLOCKED errno=1 Operation not permitted (a program the verifier
cannot reject gets the same errno as one it must reject, so the syscall did
not reach the verifier)
```

It loads two programs. One the verifier cannot reject (`r0 = 0; exit`) and one
it must (a single instruction with no `exit` after it). Both come back
`-1 EPERM`. Identical errnos for a valid and an invalid program is the proof
that the refusal happened in the privilege check before the verifier ran, so
it is not evidence about either program.

The missing capability is `CAP_BPF` in the initial user namespace.
`/proc/sys/kernel/unprivileged_bpf_disabled` is `2`, which means the syscall is
refused outright for anyone without it, and `CapEff` for this process is
`0000000000000000`. Running the same probe under `unshare -Ur` gives
`CapEff: 000001ffffffffff` inside the namespace and still `EPERM`, because the
kernel's `bpf_capable()` checks against `init_user_ns` and a nested namespace
cannot supply it.

Nothing in this repository counts an EPERM as a rejection. Everything the
analysis says about what the verifier would do is unverified here, and the
section at the end says so again in the terms that matter.

Two other oracles that look available and are not:

`bpftool prog dump xlated` needs a loaded program. It takes `id`, `tag`,
`name` or `pinned` and nothing else, so there is no file form, and loading is
what is blocked. `bpftool prog list` returns `Error: can't get next program:
Operation not permitted` for the same reason. Separately, `bpftool -p version`
on this machine reports `"libbfd": false, "llvm": false`: this build has no
instruction disassembler compiled into it at all, so even with privilege it
could not be an oracle for `-d`.

GNU binutils here cannot disassemble BPF. `objdump -d` on a BPF object prints
`can't disassemble for architecture UNKNOWN!`, `-m bpf` prints `can't use
supplied machine bpf`, and `objdump --info` lists only x86 targets. So there is
no second disassembler outside LLVM on this machine, and the per-instruction
agreement below has one vendor behind all of it. `readelf` from the same
binutils reads the container happily, which is why the ELF layer does have an
independent authority and the decoder does not.

## Numbers

Measured on 20 October 2026. `make test` prints all of them.

| what | measured |
|---|---|
| assertions | 82 passed, 0 failed |
| corpus objects built | 86 from 16 sources |
| instructions against llvm-objdump | 3,837 compared, 3,837 same, 0 differ |
| of those, bpfdis refused and llvm-objdump decoded | 0 |
| of those, refused by both | 0 |
| of those, llvm-objdump refused and bpfdis decoded | 3 |
| branch targets against llvm-objdump's symbol annotation | 477 agree, 0 differ |
| relocation placements inside the disassembly | 168 agree, 0 differ |
| function boundaries | 325 agree, 0 differ |
| deliberate divergences, allow-listed with their encoding | 48 |
| encodings swept against llvm-mc | 24,279 |
| ELF records against readelf | 2,282 sections, 1,632 symbols, 8,955 relocations, 0 differ |
| BTF against bpftool | 2,181 type records, 4,401 lines, 0 differ, all 19 kinds reached |
| maps and programs against libbpf | 88 maps, 282 programs, 0 differ |
| program types against libbpf | all 91 section-name rows reached, 0 differ |
| .BTF.ext func_info against bpftool and readelf | 347 records, 0 differ |
| .BTF.ext line_info against DWARF | 2,047 records, 0 differ |
| .BTF.ext core_relo records | 136, all 13 kinds reached |
| control-flow graphs against a second graph | 323 functions, 1,105 blocks, 1,188 edges, 0 differ |
| stack frames against clang | 22 nonzero and 125 empty, 0 wrong |
| functions of clang's own output with no finding against them | 315 |
| helper, program, map and attach type names against bpftool | 335, 0 differ |
| helper calls named in the corpus | 128, 0 differ |
| malformed inputs | 16,475 run, 0 crashed, 0 hung |
| of those, aimed at .BTF and .BTF.ext | 10,912, of which 321 refused |

Refusals are counted apart from disagreements everywhere, because the two need
different work. A disagreement is a bug in one of the two tools. A refusal
where the oracle has an answer is a decoder that is not finished, and there
are none of those in the corpus comparison.

### The encoding sweep, bucket by bucket

The corpus reaches the opcodes clang emits. The sweep reaches the ones it does
not, by feeding constructed encodings to `llvm-mc --disassemble`. Every one of
the 24,279 falls into exactly one bucket and each is printed with its own
count:

```
agree                                              8,127
both refuse                                       12,540
bpfdis refuses, llvm-mc decodes                      109
bpfdis decodes, llvm-mc refuses                    3,417
decode differently                                     0
deliberate divergence, allow-listed                   48
LLVM disagreeing with itself, proved by assembling    38
```

The suite fails on any entry in the "decode differently" row, and on any
over-acceptance that is not accounted for. A refusal is reported as a number
and never as a pass.

All 109 refusals are encodings where llvm-mc prints something that throws
information away, and each is required to be so before the suite accepts it.
34 of them are `call` with a `src_reg` other than 0, 1 or 2; llvm-mc prints
`call 1` for both `85 00 00 00 01 00 00 00` (helper 1) and
`85 10 00 00 01 00 00 00` (a relative call to another subprogram), so the text
cannot say which. bpfdis refuses the values that are not allocated rather than
printing one of them. The rest are wide loads with an undefined `src_reg` and
atomic immediates with no operation behind them.

Of the 3,417 over-acceptances, 3,400 are encodings with a field set that LLVM
requires to be zero, and each is confirmed by cleaning the dirty field and
checking that llvm-mc then decodes it the same way bpfdis did. The remaining
17 are all opcode `0xc3` and are described below.

## Where the oracles disagree

LLVM's BPF assembler emits bytes LLVM's BPF disassembler calls invalid. Three
instructions in the corpus and 17 encodings in the sweep, all of them 32-bit
atomic operations with the fetch bit set:

```
$ printf 'w2 = xchg32_32(r1 + 0, w2)\n' | llvm-mc -triple=bpfel --assemble --show-encoding
	w2 = xchg32_32(r1 + 0, w2)  # encoding: [0xc3,0x21,0x00,0x00,0xe1,0x00,0x00,0x00]

$ printf '0xc3 0x21 0x00 0x00 0xe1 0x00 0x00 0x00\n' | llvm-mc -triple=bpfel --disassemble
<stdin>:1:1: warning: invalid instruction encoding
```

`llvm-objdump` prints `<unknown>` for the same bytes. bpfdis decodes them, and
the suite accepts that only because llvm-mc assembles our text back to exactly
the bytes in the object, which is a round trip through LLVM's own encoder. The
three in the corpus are `atomic_fetch_or`, `xchg32_32` and `cmpxchg32_32` at
32-bit width, in `t/corpus/exotic.s`, and they are counted in their own bucket
rather than as agreement.

A second place where bpfdis says more than the oracle can confirm.
`bpf_program__expected_attach_type` returns 0 both for a section with no
attach type and for `cgroup_skb/ingress`, whose attach type genuinely is
zero. bpfdis records -1 for the first, the comparison maps it back to 0
before asking libbpf, and the distinction is asserted on its own instead:
`socket` must print `attach=-1 (-)` and `cgroup_skb/ingress` must print
`attach=0 (cgroup_inet_ingress)`. Without that the mutation which collapses
them survives the whole suite.

The other divergence is deliberate and runs the other way. `call` with
`src_reg = 1` is a relative call to another subprogram in the same object;
with `src_reg = 0` it is helper number `imm`. LLVM prints `call 1` for both.
bpfdis prints them differently, so 48 instructions in the corpus are in the
allow-list, and the allow-list will only accept an instruction whose actual
bytes carry `src_reg == 1`.

## Buffers larger than their data

The collection this lives in has found that shape eighteen times in C, where
the consequence is that the sanitizer stops being able to see an overread.
Rust has no sanitizer to switch off, so the shape does something else, and
`src` was swept for every place a buffer's size and the length that indexes
it come from different sources. Two were found and the rest are exact by
construction.

`prog.rs` builds a `slot_map` with one entry per 8-byte slot of a section.
One spare element turns an index past the end from an abort into a quiet
`None`, which every caller reads as "that slot is the tail of a 16-byte
load", so a jump one past the end of a section becomes a jump into a wide
load: a wrong answer with nothing to see. `make overread` rebuilds with that
read planted and requires it to abort with 134. bpfdis itself only ever
exits 0, 1, 2 or 3, so a report cannot be confused with a refusal. With one
spare element the planted read exits 0 instead, and the mutation run records
exactly that.

`maps.rs` read a legacy `struct bpf_map_def` into a five-word buffer from a
cursor that could run out. The leftover zeros then travelled into
`key_size` and `max_entries` as though they had been read, and a zero
`max_entries` looks like a map somebody declared that way. The buffer is
sized to what the section actually held now, and `t/corpus/shortmap.s` is a
12-byte definition with a symbol claiming 20: the suite requires the record
to say "only 3 of the 5 words" and to report the missing two as zero beside
that note. The mutation that pads to five words in silence is killed by it.

Neither of these was a crash and neither would have been found by running
anything. The second was found by the sweep and not by the suite, and the
honest summary is that the sweep found one real reporting defect in a tree
that was already careful about the first.

## Mutation testing

`make mutants` applies 64 named defects to the Rust source one at a time,
rebuilds, and runs the whole suite against each. It takes about half an hour
and is not part of `make test`. The defects are in `t/mutate.py`, each with a
sentence saying what it breaks, and a mutant whose pattern does not apply is
reported rather than counted as killed, because a no-op edit passes every
suite there is.

All 64 are killed by a named assertion.

Two were not, and what they were pointing at was worth more than the
mutation score.

Making a pointer the size of the thing it points at changed no output
anywhere. Every key and value in the BTF-map corpus was a pointer to an
integer or to a struct, where the size of the pointee is the right answer, so
the one place `size_of` is asked about a pointer was never reached. The
corpus now has a map whose key is `u32 **`, where the answer is 8 and the
mutant says 4, and libbpf agrees it is 8.

Reading the legacy `struct bpf_map_def` fields in the wrong order survived
because that reader had no oracle at all: libbpf 1.0 refuses `maps` sections,
and all five fields are the same width, so nothing else in the suite could
see the difference. They are now compared against the initialisers in
`t/corpus/maps.c`, which is weaker than an outside authority and is not
nothing: clang laid the struct out and bpfdis reads it back.

Three of the kills are not assertions and the harness says so rather than
letting them count as suite coverage. Two come from the `make overread`
gate: shrinking a symbol table entry to 16 bytes makes the planted read exit
1 instead of aborting, and giving the slot map one spare element makes it
exit 0, which is the silent wrong answer that gate exists for.

A fourth used to be killed by the compiler. Deleting the only push into
`back_edges`' result vector left its type unknown, so `rustc` rejected it and
the suite never ran; a mutant that cannot be built proves nothing about the
tests. The vector is annotated now and `flowcheck.py` kills it.

## What does not work

**The verifier's answer is not checked, anywhere.** Everything `-a` reports is
a property bpfdis computed from the instruction stream. Whether the kernel
agrees that the program would be rejected is unmeasured on this machine, for
the reason in the section above. The one check that is not self-referential is
the other direction: every function clang compiled must produce no rejection
at all, over 224 functions, and a false positive anywhere shows up there. That
is worth having and it is not the same as being right.

**The control-flow graph has no external authority.** The decoder has LLVM.
The graph has llvm-objdump's `<target>` annotations on branch instructions,
477 of them, and nothing else. Block boundaries, edges and reachability are
checked against a second graph in `t/cfgcmp.py`, built from llvm-objdump's
text rather than from our decode: 323 functions, 1,105 blocks and 1,188 edges
agree. That is a second implementation and not an authority, and it shares
the understanding of the ISA that both were written from. The loop report and
the stack figure are not in it at all. This is the place where an error would
be hardest to see.

**One vendor behind every instruction comparison.** llvm-objdump and llvm-mc
are the same backend. GNU binutils has no BPF target on this machine and
bpftool was built without a disassembler, so there is nothing to put beside
LLVM. A bug in LLVM's BPF tables is a bug bpfdis would be measured as correct
against, and the three `0xc3` encodings above are an example of how far apart
LLVM's own two halves can get.

**The legacy map form has no outside oracle.** libbpf 1.0 removed support
for `maps` sections holding `struct bpf_map_def` and refuses those objects
outright, 16 of the corpus. Those 16 are checked against the initialisers in
the C source they were compiled from instead, which crosses clang and
nothing else. An error both clang and bpfdis made in the same direction
would pass.

**The CO-RE relocation table has no outside reader.** No installed tool
prints a `core_relo` record, so unlike everything else here the 136 records
in the corpus are not compared with anybody. What is checked is that each
one points at things that exist: the type id is a record bpftool prints,
the kind is one of the 13 the decoder names, and the access string is the
colon-separated index list the format defines. All 13 kinds are reached by
`t/corpus/core.c`, so no row of that list is a guess nothing runs over, but
an off-by-one inside a record would pass every one of those checks.

**`-d` does not annotate instructions with their source line.** The line
numbers are read and checked; nothing joins them to the disassembly.

**CO-RE relocations are decoded, not resolved.** What a relocation would be
patched to depends on the BTF of a running kernel, which is not read.

**The BTF corruption sweep found nothing.** 10,912 inputs with a single
byte of `.BTF` or `.BTF.ext` set to 0x00 or 0xFF, plus 4-byte smashes at
random offsets inside them, over five base objects. 321 were refused,
10,591 were read, none crashed or hung. A negative result is still a
result: the sweep was written because the general corruption sweep strides
29 bytes through the whole file and so gives a 1 kB `.BTF.ext` about 35
single-byte edits, and those two sections are almost entirely offsets,
counts and record sizes.

**No big-endian BPF and no 32-bit ELF.** Both are refused at the header
check and both are stated non-goals. The big-endian refusal is tested the
way a missing feature should be: clang builds a `bpfeb` object, the suite
requires llvm-objdump to decode 96 instructions from it, and then requires
bpfdis to exit 1 with a message naming the endianness. A reader that
quietly swallowed the file would produce a plausible disassembly of
different instructions, which is a worse failure than no feature at all.
Nothing here builds a 32-bit BPF object, so that refusal is exercised only
by the byte-corruption sweep.

**The analysis fixtures are all cases somebody thought of.** `t/corpus/badflow.s`
has one function per defect, written by hand, and the suite asserts that each
of the seven findings is reached by one of them. A rejection the kernel makes
that is not in that file is a rejection bpfdis does not look for, and there is
no way to enumerate the set from here.

**The build is reproducible; one artefact beside it is not.** Checked with
`python3 unrepro/unrepro.py check ../bpfdis --cmd 'make -B'`, which builds
twice under different directories, time zones, locales, umasks, hostnames,
users, `SOURCE_DATE_EPOCH` and readdir order. `target/release/bpfdis` is
byte-identical across the two. `target/release/bpfdis.d` is not: it is the
dependency list cargo writes for make, and it holds the absolute path of
every source file, which is where the build ran rather than anything about
the source. Nothing reads it but cargo and it is not tracked. There is no
`make repro` target, because the checker lives in a sibling repository and
a suite that reads its neighbours fails for anyone who clones this one on
its own.

**One machine, one LLVM, one kernel.** Every number above comes from clang and
LLVM 19.1.7, binutils 2.44, bpftool 7.5.0 with libbpf 1.5, on one Linux box
running 7.2.11. Several of the measured behaviours are version-specific: which
atomic encodings LLVM's disassembler refuses, how llvm-objdump elides runs of
zero bytes, and whether `bpftool` has a disassembler compiled in at all.
