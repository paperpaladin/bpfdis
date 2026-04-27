# PLAN

## Contract

```
bpfdis [MODE...] FILE

  -S, --sections    the ELF section table
  -y, --symbols     the symbol table
  -r, --relocs      relocations, resolved against the symbol table
  -d, --disasm      every executable section, one line per instruction
      --raw         with -d, print the 8 or 16 raw bytes of each instruction
  -c, --cfg         basic blocks and control-flow edges, per function
  -a, --analyse     the verifier-relevant report, per function
      --strict      with -a, exit 3 if any finding would be a rejection
  -P, --progs       the programs libbpf would find: name, section, length
  -m, --maps        map definitions: legacy struct bpf_map_def and BTF-defined
  -b, --btf         the .BTF type section
  -x, --hex         decode hex-encoded instructions from stdin, one per line
  -A, --all         all of the above
  -h, --help        the usage text
```

`FILE` is an ELF64 relocatable object for `EM_BPF` (machine 247), little-endian,
as produced by `clang -target bpf -c`. Each `SHF_EXECINSTR` section holds a
sequence of 64-bit BPF instructions; a `BPF_LD | BPF_IMM | BPF_DW` instruction
occupies two of them.

`-d` prints one line per instruction:

```
<index>:\t<asm>
```

where `<index>` counts 8-byte instruction slots from the start of the section,
so a 16-byte load skips a number, exactly as `llvm-objdump` does. `<asm>` is
LLVM's BPF assembly syntax. An instruction bpfdis cannot decode prints
`(bad) 0x<opcode>` and is counted as a REFUSAL, never guessed at.

Exit status: 0 on a clean parse, 1 on malformed or unreadable input, 2 on a
usage error, 3 when `-a --strict` found a property that would make the kernel
verifier reject the program. All four are distinct because the harness asserts
on the difference.

Pure Rust 2021, no dependencies at all: not even for ELF. `std` only, and the
only `unsafe` in the tree is none.

## Hard invariant

**Every instruction bpfdis claims to decode decodes to the same instruction
LLVM's BPF disassembler decodes it to, compared one instruction at a time, and
anything bpfdis cannot decode is refused in a way the suite counts separately
from a wrong answer.**

Concretely, and checked by `make test`:

- For every instruction in every corpus object, the (mnemonic, operand) tuple
  parsed out of our `-d` output equals the tuple parsed out of
  `llvm-objdump -d --triple=bpf`. Compared per instruction, by index, as parsed
  values and not as text, because the two printers differ on radix.
- Over a systematic sweep of the encoding space fed to `llvm-mc --disassemble`,
  every encoding falls into exactly one of five buckets, each of which is
  printed with its own count: AGREE, BOTH-REFUSE, WE-REFUSE (LLVM decodes, we
  do not), WE-OVER-ACCEPT (we decode, LLVM does not), DISAGREE. The suite fails
  on any DISAGREE and on any WE-OVER-ACCEPT that is not in a written-down
  allow-list with a reason. WE-REFUSE is reported as a number, not as a pass.
- Relocation records, symbol table entries and section headers agree with
  `readelf`, which is binutils and shares no code with LLVM.
- BTF type records agree with `bpftool btf dump file`, which is libbpf.
- No input -- truncated at any offset, byte-corrupted anywhere, a directory,
  a non-ELF file, a section header pointing outside the file -- makes bpfdis
  exit above 1. No panic, no hang. Rust turns a bad index into a panic rather
  than a wild read, and a panic is exit 101 (or, with `panic = "abort"`,
  SIGABRT), which the sweep treats as a failure.
- Every comparison asserts a nonzero count of the thing it compared. A
  comparison over zero instructions agrees with everything.

## Oracle

Ranked by how little of it we control.

1. **The kernel verifier**, via `bpf(BPF_PROG_LOAD)`. This is the only true
   authority for "would this be rejected", and on this machine it is
   **BLOCKED**. Measured, not assumed: `t/verifier_probe.c` loads two programs
   as `BPF_PROG_TYPE_SOCKET_FILTER`, one the verifier cannot reject
   (`r0 = 0; exit`) and one it must (a single instruction with no `exit`
   after it). Both return `-1 EPERM`. Identical errnos for a valid and an
   invalid program is the proof that the refusal happened before the verifier
   ran. `/proc/sys/kernel/unprivileged_bpf_disabled` is `2` and
   `CapEff` is `0000000000000000`. Repeated inside `unshare -Ur`: still EPERM.
   An EPERM is a refusal by the privilege check before the verifier runs, so it
   is not evidence about any program, and nothing in this repo may count it as
   a rejection. The probe is part of the suite so the blockage is re-measured
   rather than remembered.
2. **`llvm-objdump -d --triple=bpf`** (LLVM 19.1.7). An independent BPF
   disassembler maintained by the people who also write the encoder. Compared
   per instruction.
3. **`llvm-mc --disassemble -triple=bpfel`** (LLVM 19.1.7). The same backend as
   2, so not an independent second opinion, but it takes raw bytes, which
   reaches encodings no compiler will ever emit. Per instruction by
   construction. Its radix differs from llvm-objdump's, which is itself a small
   check that the comparison parses rather than diffs.
4. **`readelf`** (GNU binutils 2.44). Shares no code with LLVM. Authority for
   section headers, symbols and relocations.
5. **`/usr/sbin/bpftool btf dump file`** (bpftool 7.5.0, libbpf 1.5). A third
   codebase again. Authority for BTF. Note that this bpftool was built with
   `libbfd: false, llvm: false`, so it has no instruction disassembler compiled
   in at all and cannot be an oracle for `-d` even with privilege.
6. **libbpf 1.5 itself**, through `t/libbpf_probe.c`, which `dlopen`s
   `libbpf.so.1` and calls `bpf_object__open_file`. Parsing needs no
   privilege; it is `bpf_object__load` that does, and the probe never calls
   it. There are no libbpf headers installed, so the fourteen entry points are
   declared from the published API and resolved by name, and a missing
   symbol exits 2 rather than producing an empty comparison. Authority for
   the map table and the program list.
7. **`clang -target bpf -O2 -c`** (clang 19.1.7) and `llvm-mc` as an assembler,
   for the corpus. The corpus is hermetic: no `linux/bpf.h`, no libbpf headers,
   because neither is installed for the BPF target here.
8. **Deliberate defects in bpfdis itself.** Each expected to turn a *named*
   assertion red, with the survivors written down in the README.

## Non-goals

- Running BPF. No interpreter, no JIT.
- Loading anything into the kernel. See oracle 1.
- Reimplementing the verifier. bpfdis reports properties the verifier cares
  about; it does not claim to predict the verifier's answer, and with the
  verifier unreachable here it could not honestly claim to.
- Big-endian BPF (`bpfeb`) and 32-bit ELF. Refused at the header check.
- Writing or assembling BPF.
- CO-RE relocation resolution against a running kernel's BTF. The relocation
  records are decoded and printed; what they would be patched to depends on a
  kernel we cannot read.
- Being a library.

## Commit sequence

### Milestone 0: the floor

- [x] ELF64 reader with a bounds-checked cursor, `-S`
      why: every later stage reads attacker-controlled bytes. The cursor has to
      exist before anything that uses it, or the bounds checks get retrofitted
      and miss cases. Rust makes a missed check a panic rather than a read, but
      a panic is still a crash and the robustness sweep counts it as one.
- [x] Symbol table and relocations, `-y` and `-r`
      why: a BPF instruction stream is meaningless without them. `r1 = 0 ll`
      with an `R_BPF_64_64` against `mymap` is a map reference, and without
      the relocation it is the constant zero.
- [x] readelf comparison for sections, symbols and relocations
      why: the ELF layer is the one place a genuinely independent codebase
      (binutils) will check us, and it is cheap.
      done: 1624 section headers, 1048 symbols, 6264 relocation records over
      56 objects, field by field, 0 mismatches. It found three defects on its
      first run: STT_SECTION symbols printed as a dash rather than under the
      section name (664 of 1048 symbols), SHF_EXCLUDE missing from the flag
      string, and section type 0x6fff4c03 printed as UNKNOWN.

### Milestone 1: the decoder, which is the point

- [x] Instruction decode: ALU64, ALU32, the jump classes, LD/LDX/ST/STX
      why: the core. Written from the kernel ISA document, then corrected
      against the oracle, in that order, so the oracle is measuring something.
- [x] LLVM-syntax printing, and the per-instruction comparison against
      `llvm-objdump` over the corpus
      done: 3114 instructions over 168 sections of 56 objects agree, compared
      by (section, slot index) with the raw bytes checked too, so a
      misalignment cannot hide as agreement. 32 deliberate divergences, all
      of them the local-call case below, each one required to carry src_reg
      == 1 in its actual bytes before the allow-list will accept it.
      why: a per-program diff says something disagreed somewhere in 400
      instructions. A per-instruction comparison names the opcode.
- [x] The 16-byte `lddw` forms, including the six `src_reg` pseudo variants
      why: this is the only instruction whose length is not 8, so every loop
      in the program has to agree about it, and `src_reg` selects between a
      map fd, a map value, a BTF id and a plain 64-bit constant.
- [x] Atomic operations: the `imm`-selected `BPF_ATOMIC` family
      why: `0xdb` with `imm` 0x00/0x40/0x50/0xa0/0xa1/0xf1 are six different
      instructions sharing one opcode byte, and the fetch bit changes whether
      a register is written.
- [x] ISA v4: `movsx`, `ldsx`, signed div/mod, `bswap`, `gotol`, `may_goto`,
      and `addr_space_cast`, which the sweep found and nothing else would
      have: it is the 64-bit register move with `off` set to 1
      why: clang 19 emits these at `-mcpu=v4` and they reuse the `off` field
      of instructions that previously required it to be zero. A decoder that
      ignores `off` silently prints the v3 meaning.
- [x] The opcode sweep: enumerate the encoding space against `llvm-mc`
      why: the corpus reaches the opcodes clang emits. The sweep reaches the
      ones it does not, which is where a decoder is actually wrong. Five
      buckets, each counted separately; a refusal is not a pass.
- [x] Register-number and reserved-field validation
      why: LLVM refuses `dst = r14`. Measured: `b7 fe 00 00 01 00 00 00` is
      `invalid instruction encoding`. If we print `r14 = 1` we have
      over-accepted, and over-acceptance in a disassembler is how a reader
      hides a malformed object.
- [x] `call` with `src_reg = 1`, where we disagree with the oracle on purpose
      why: measured, `llvm-mc` prints `85 10 00 00 01 00 00 00` as `call 1`,
      identical to `85 00 00 00 01 00 00 00`. The first is a relative call to
      another subprogram and the second is helper 1. The oracle erases the
      distinction; bpfdis must not, so this goes in the allow-list with the
      encoding that proves it.

### Milestone 1a: the second direction

- [x] Use `llvm-mc` as an ASSEMBLER as well, and make it the arbiter of every
      divergence
      why: a disassembler checked only against another disassembler shares
      that disassembler's blind spots. Assembling our text back and requiring
      the original bytes is a different question with a different failure
      mode, and it turned 38 unexplained divergences and 17 unexplained
      over-acceptances into LLVM disagreeing with itself.

### Milestone 2: structure

- [x] Relocation application: name the map or symbol inside the disassembly
      why: it is what makes the output readable, and it is the first place the
      ELF layer and the decoder have to agree about offsets.
- [x] Program type from the section name, against libbpf's own table
      done: 91 rows, every one reached by a program in t/corpus/sections.c
      and every one agreeing with `bpf_program__type`. The first run found
      the rule wrong: libbpf matches some section names exactly and lets
      others carry a suffix, so `kprobe/do_sys_open` is a KPROBE while
      `socket/ingress` is nothing at all and only a bare `socket` is a
      socket filter. Which is which was measured by compiling both forms of
      every name, not inferred.
      why: it is the first thing a loader decides about a program, and
      libbpf will say whether we got it right without any privilege.
- [x] Map definitions, both legacy `bpf_map_def` and BTF-defined `.maps`,
      plus the maps a loader creates for `.data`, `.rodata` and `.bss`
      done: 80 map records and 152 programs agree with libbpf itself, which
      parses an object without any privilege. The legacy form has NO oracle:
      libbpf 1.0 removed support for it and refuses those objects outright.
      why: the modern form is a BTF type with pointer-to-array members encoding
      integers in array lengths, which is unreadable without a BTF decoder, and
      it is the form every current program uses.
- [x] BTF decoding, compared against `bpftool btf dump file`
      done: all 19 BTF kinds, 1648 type records and 3424 lines over 64
      objects, byte for byte identical to bpftool's own output. Four
      renderings had to be measured rather than guessed: bpftool prints
      bitfield_size only when it is nonzero, the ENUM kind flag means SIGNED
      and not UNSIGNED, FUNC keeps its linkage in vlen rather than in a
      trailing word, and a DATASEC entry names the variable it points at.
      why: a third codebase, and the only oracle for the `.maps` section.
- [x] `.BTF.ext`: func_info, line_info and the CO-RE relocation table, `-e`
      done: 315 func_info records over 73 objects, each one's BTF type id
      resolved against bpftool's dump and required to name the ELF symbol
      readelf puts at that instruction; and 1903 line_info records against
      the DWARF line table that `llvm-objdump -dl` prints, which clang emits
      through a different back end into a different section. 315 function
      entries are counted separately, because BTF.ext records the line of
      the declaration there and DWARF the line of the opening brace. No
      corpus object has a CO-RE relocation, so that table is decoded and
      unexercised, and the count sits in the output at zero.
      why: `insn_off` is a byte offset and everything else in this tree
      counts slots, which is the kind of mistake that is invisible at the
      first instruction of every function and wrong everywhere else.
- [x] Function boundaries from the symbol table
      done: 226 function (start, end, name) triples agree. Starts come from
      the labels llvm-objdump prints; ends are derived in the harness from
      readelf's symbol sizes and section sizes, which is a second
      implementation rather than an authority, because nothing installed
      here prints where a BPF function ends. The mutation that ignores
      st_size survived the whole compiled corpus and dies against
      t/corpus/padding.s. `BTF.ext` is not read.
      why: a `.text` section with four `STT_FUNC` symbols is four programs
      sharing an instruction stream, and every per-program number below is
      wrong if they are treated as one.

### Milestone 3: the control-flow graph

- [x] Basic-block construction and edges
      why: everything in milestone 4 is a question about this graph.
- [x] Reachability, and unreachable-code reporting
      why: the verifier rejects unreachable instructions outright, so this is
      the one finding that maps to a verifier message with no judgement.
- [x] Back-edge detection, and the loop report
      why: pre-5.3 kernels reject any back edge; current kernels accept
      bounded loops. Both answers are useful and they are different answers,
      so the report says which kernels would refuse it.
- [x] Termination: every path ends in `exit`
      why: falling off the end of the instruction stream is a rejection, and
      it is invisible in a linear dump.
- [x] CFG cross-check against an independent reconstruction in the harness
      done: 232 functions, 1014 blocks and 1188 edges agree with a second
      graph in t/cfgcmp.py, built from llvm-objdump's text. Two functions
      are skipped and counted: llvm-objdump elides a run of zero bytes with
      no instruction lines at all, and refuses three atomic encodings its
      own assembler emits. The mutation that measures a jump offset from
      the jump rather than from the instruction after it moves 123 of the
      232.
      why: the decoder has LLVM. The graph has nothing, and saying so is
      better than pretending otherwise. A second implementation in another
      language, from the oracle's decode rather than ours, is a weaker check
      than an external authority, and the README says so.

### Milestone 4: what the verifier cares about

- [x] Stack depth: the lowest `r10 + off` written or read, and the lowest
      frame address FORMED, which is the part that matters
      why: 512 bytes is a hard limit and exceeding it is a rejection with a
      message nobody can act on.
- [x] Helper call inventory, by number
      why: the first thing anyone asks of an unknown object, and the input to
      "which program types can this attach to".
- [x] Register liveness: reading an uninitialised register
      why: the single most common real rejection.
- [x] Jump-target validation: out of range, into the middle of a `lddw`
      why: both are rejections, and the second is a decoder bug in anything
      that walks instructions without tracking the 16-byte form.
- [x] The report, and `--strict`
      why: the exit status is the part a CI pipeline uses.

### Milestone 5: hostile input

- [x] Truncation sweep at every offset
- [x] Byte-corruption sweep inside each section
- [x] Section headers lying about their size, which is the half of this
      that can be two-sided: a clang object keeps its section table at the
      end of the file, so every truncation is refused at the header and
      the truncation sweep is one-sided by construction
      why: the three ways a reader walks off the end, and in Rust each one is
      a panic rather than a silent read, so each one is visible if and only if
      the sweep looks at the exit status rather than at stdout.
- [x] The oversized-buffer blindness, in its Rust form
      why: METHOD records eighteen instances of a buffer larger than its data
      turning the sanitizer off. Rust's equivalent is a `Vec` with spare
      capacity handed to code that indexes by a separate length, and
      `Vec::with_capacity(n)` followed by a length taken from the file is
      exactly that shape. The audit is to find every place a length and a
      buffer come from different sources.

### Milestone 6: honesty

- [ ] Mutation run: deliberate defects, each expected to kill a named check
- [ ] README with every measured number, and the list of what does not work
