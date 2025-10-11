# PLAN

## Contract

```
bpfdis [MODE...] FILE

  -S, --sections    the ELF section table
  -y, --symbols     the symbol table
  -r, --relocs      relocations, resolved against the symbol table
  -d, --disasm      every executable section, one line per instruction
  -m, --maps        map definitions: legacy struct bpf_map_def and BTF-defined
  -b, --btf         the .BTF type section
  -c, --cfg         basic blocks and control-flow edges, per program
  -a, --analyse     the verifier-relevant report
  -A, --all         all of the above
      --raw         with -d, print the 8 or 16 raw bytes of each instruction
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
   **BLOCKED**. Measured, not assumed: `t/verifier_probe.c` loads a program the
   verifier cannot reject (`r0 = 0; exit`) under six program types, and every
   one returns `-1 EPERM`, the same errno as a program that is obviously
   invalid. `/proc/sys/kernel/unprivileged_bpf_disabled` is `2` and
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
6. **`clang -target bpf -O2 -c`** (clang 19.1.7) and `llvm-mc` as an assembler,
   for the corpus. The corpus is hermetic: no `linux/bpf.h`, no libbpf headers,
   because neither is installed for the BPF target here.
7. **Deliberate defects in bpfdis itself.** Each expected to turn a *named*
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

- [ ] ELF64 reader with a bounds-checked cursor, `-S`
      why: every later stage reads attacker-controlled bytes. The cursor has to
      exist before anything that uses it, or the bounds checks get retrofitted
      and miss cases. Rust makes a missed check a panic rather than a read, but
      a panic is still a crash and the robustness sweep counts it as one.
- [ ] Symbol table and relocations, `-y` and `-r`
      why: a BPF instruction stream is meaningless without them. `r1 = 0 ll`
      with an `R_BPF_64_64` against `mymap` is a map reference, and without
      the relocation it is the constant zero.
- [ ] readelf comparison for sections, symbols and relocations
      why: the ELF layer is the one place a genuinely independent codebase
      (binutils) will check us, and it is cheap.

### Milestone 1: the decoder, which is the point

- [ ] Instruction decode: ALU64, ALU32, the jump classes, LD/LDX/ST/STX
      why: the core. Written from the kernel ISA document, then corrected
      against the oracle, in that order, so the oracle is measuring something.
- [ ] LLVM-syntax printing, and the per-instruction comparison against
      `llvm-objdump` over the corpus
      why: a per-program diff says something disagreed somewhere in 400
      instructions. A per-instruction comparison names the opcode.
- [ ] The 16-byte `lddw` forms, including the six `src_reg` pseudo variants
      why: this is the only instruction whose length is not 8, so every loop
      in the program has to agree about it, and `src_reg` selects between a
      map fd, a map value, a BTF id and a plain 64-bit constant.
- [ ] Atomic operations: the `imm`-selected `BPF_ATOMIC` family
      why: `0xdb` with `imm` 0x00/0x40/0x50/0xa0/0xa1/0xf1 are six different
      instructions sharing one opcode byte, and the fetch bit changes whether
      a register is written.
- [ ] ISA v4: `movsx`, `ldsx`, signed div/mod, `bswap`, `gotol`
      why: clang 19 emits these at `-mcpu=v4` and they reuse the `off` field
      of instructions that previously required it to be zero. A decoder that
      ignores `off` silently prints the v3 meaning.
- [ ] The opcode sweep: enumerate the encoding space against `llvm-mc`
      why: the corpus reaches the opcodes clang emits. The sweep reaches the
      ones it does not, which is where a decoder is actually wrong. Five
      buckets, each counted separately; a refusal is not a pass.
- [ ] Register-number and reserved-field validation
      why: LLVM refuses `dst = r14`. Measured: `b7 fe 00 00 01 00 00 00` is
      `invalid instruction encoding`. If we print `r14 = 1` we have
      over-accepted, and over-acceptance in a disassembler is how a reader
      hides a malformed object.
- [ ] `call` with `src_reg = 1`, where we disagree with the oracle on purpose
      why: measured, `llvm-mc` prints `85 10 00 00 01 00 00 00` as `call 1`,
      identical to `85 00 00 00 01 00 00 00`. The first is a relative call to
      another subprogram and the second is helper 1. The oracle erases the
      distinction; bpfdis must not, so this goes in the allow-list with the
      encoding that proves it.

### Milestone 2: structure

- [ ] Relocation application: name the map or symbol inside the disassembly
      why: it is what makes the output readable, and it is the first place the
      ELF layer and the decoder have to agree about offsets.
- [ ] Map definitions, both legacy `bpf_map_def` and BTF-defined `.maps`
      why: the modern form is a BTF type with pointer-to-array members encoding
      integers in array lengths, which is unreadable without a BTF decoder, and
      it is the form every current program uses.
- [ ] BTF decoding, compared against `bpftool btf dump file`
      why: a third codebase, and the only oracle for the `.maps` section.
- [ ] Function boundaries from the symbol table and from `BTF.ext`
      why: a `.text` section with four `STT_FUNC` symbols is four programs
      sharing an instruction stream, and every per-program number below is
      wrong if they are treated as one.

### Milestone 3: the control-flow graph

- [ ] Basic-block construction and edges
      why: everything in milestone 4 is a question about this graph.
- [ ] Reachability, and unreachable-code reporting
      why: the verifier rejects unreachable instructions outright, so this is
      the one finding that maps to a verifier message with no judgement.
- [ ] Back-edge detection, and the loop report
      why: pre-5.3 kernels reject any back edge; current kernels accept
      bounded loops. Both answers are useful and they are different answers,
      so the report says which kernels would refuse it.
- [ ] Termination: every path ends in `exit`
      why: falling off the end of the instruction stream is a rejection, and
      it is invisible in a linear dump.
- [ ] CFG cross-check against an independent reconstruction in the harness
      why: the decoder has LLVM. The graph has nothing, and saying so is
      better than pretending otherwise. A second implementation in another
      language, from the oracle's decode rather than ours, is a weaker check
      than an external authority, and the README says so.

### Milestone 4: what the verifier cares about

- [ ] Stack depth: the lowest `r10 + off` written or read
      why: 512 bytes is a hard limit and exceeding it is a rejection with a
      message nobody can act on.
- [ ] Helper call inventory, by number and by name
      why: the first thing anyone asks of an unknown object, and the input to
      "which program types can this attach to".
- [ ] Register liveness: reading an uninitialised register
      why: the single most common real rejection.
- [ ] Jump-target validation: out of range, into the middle of a `lddw`
      why: both are rejections, and the second is a decoder bug in anything
      that walks instructions without tracking the 16-byte form.
- [ ] The report, and `--strict`
      why: the exit status is the part a CI pipeline uses.

### Milestone 5: hostile input

- [ ] Truncation sweep at every offset
- [ ] Byte-corruption sweep inside each section
- [ ] A hand-assembled object with a section header lying about its size
      why: the three ways a reader walks off the end, and in Rust each one is
      a panic rather than a silent read, so each one is visible if and only if
      the sweep looks at the exit status rather than at stdout.
- [ ] The oversized-buffer blindness, in its Rust form
      why: METHOD records eighteen instances of a buffer larger than its data
      turning the sanitizer off. Rust's equivalent is a `Vec` with spare
      capacity handed to code that indexes by a separate length, and
      `Vec::with_capacity(n)` followed by a length taken from the file is
      exactly that shape. The audit is to find every place a length and a
      buffer come from different sources.

### Milestone 6: honesty

- [ ] Mutation run: deliberate defects, each expected to kill a named check
- [ ] README with every measured number, and the list of what does not work
