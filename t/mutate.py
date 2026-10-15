#!/usr/bin/env python3
"""Plant a defect, run the whole suite, and record whether it went red.

A test suite that has never been watched failing is not evidence. This
applies forty named defects one at a time, runs `make test` against each,
and prints which assertion caught it. A survivor is reported as a survivor,
with no attempt to decide whether it was equivalent: that judgement belongs
in the README next to the reason.

Run with `make mutants`. It edits the tree and restores it in a finally
block; if it is killed between the edit and the restore, `git status` will
show the file and `git checkout` that one file puts it back.
"""
import re
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (name, file, old, new). `old` must appear exactly once; a mutation that
# does not apply is reported rather than counted as killed, because a
# no-op edit passes every suite there is.
MUTANTS = [
    ("elf: section symbols lose their section's name", "src/elf.rs",
     "if nm.is_empty() && (info & 0xf) == STT_SECTION {",
     "if false && nm.is_empty() && (info & 0xf) == STT_SECTION {"),
    ("elf: SHF_EXCLUDE prints the wrong letter", "src/elf.rs",
     "        s.push('E');", "        s.push('Q');"),
    ("elf: relocation symbol index read from the low half of r_info", "src/elf.rs",
     "let symi = (info >> 32) as u32;", "let symi = (info & 0xffff_ffff) as u32;"),
    ("elf: symbol table entries read as 16 bytes", "src/elf.rs",
     "            let n = d.len() / 24;", "            let n = d.len() / 16;"),
    ("elf: section contents start one byte early", "src/elf.rs",
     "                let s = offset as usize;",
     "                let s = (offset as usize).saturating_sub(1);"),

    ("insn: jump condition 0xa0 decoded as greater-than", "src/insn.rs",
     "            0xa0 => Cond::Lt,", "            0xa0 => Cond::Gt,"),
    ("insn: the 16-byte load advances one slot", "src/insn.rs",
     "            ins.slots = 2;", "            ins.slots = 1;"),
    ("insn: memory offsets lose their sign", "src/insn.rs",
     "fn memoff(r: u8, off: i16) -> String {\n    if off < 0 {",
     "fn memoff(r: u8, off: i16) -> String {\n    if false {"),
    ("insn: 32-bit ALU names its destination r", "src/insn.rs",
     "                let d = if *wide { reg(self.dst) } else { reg32(self.dst) };\n"
     "                let rhs = if *isreg {\n                    if *wide {\n"
     "                        reg(self.src)\n                    } else {\n"
     "                        reg32(self.src)\n                    }\n"
     "                } else {\n                    simm(self.imm)\n                };\n"
     "                match a {",
     "                let d = reg(self.dst);\n"
     "                let rhs = if *isreg {\n                    if *wide {\n"
     "                        reg(self.src)\n                    } else {\n"
     "                        reg32(self.src)\n                    }\n"
     "                } else {\n                    simm(self.imm)\n                };\n"
     "                match a {"),
    ("insn: the atomic fetch bit is ignored", "src/insn.rs",
     "                let fetch = self.imm & 0x01 != 0;", "                let fetch = false;"),
    ("insn: callx moves back to the unallocated 0x9d", "src/insn.rs",
     "                if reg {\n                    // BPF_JMP | BPF_CALL | BPF_X is `callx`, an indirect call\n"
     "                    // through the destination register.",
     "                if false {\n                    //"),
    ("insn: addr_space_cast is read as a plain move", "src/insn.rs",
     "                (1, true) => {\n                    self.op = Some(Op::AddrSpaceCast);\n                    return;\n                }",
     "                (1, true) => {}"),
    ("insn: negate accepts the source bit", "src/insn.rs",
     "                if reg {\n                    self.bad = Some(\n"
     "                        \"negate with the source bit set is not allocated; BPF_NEG is BPF_K only\"\n"
     "                            .into(),\n                    );\n                    return;\n                }",
     "                if false {\n                    return;\n                }"),
    ("insn: 32-bit atomics name their value register r", "src/insn.rs",
     "                let v = |r: u8| if narrow { reg32(r) } else { reg(r) };",
     "                let v = |r: u8| if false && narrow { reg32(r) } else { reg(r) };"),
    ("insn: the atomic immediate is masked instead of matched", "src/insn.rs",
     "                let base = self.imm & !0x01;", "                let base = self.imm & 0xf0;"),
    ("insn: immediates printed unsigned", "src/insn.rs",
     "fn simm(v: i32) -> String {\n    if v < 0 {", "fn simm(v: i32) -> String {\n    if false {"),
    ("insn: load and store sizes swap halfword and byte", "src/insn.rs",
     "        BPF_H => \"u16\",\n        BPF_B => \"u8\",", "        BPF_H => \"u8\",\n        BPF_B => \"u16\","),
    ("insn: the sign-extending move width comes from imm", "src/insn.rs",
     "                (8, _) | (16, _) => sx = self.off as u8,",
     "                (8, _) | (16, _) => sx = self.imm as u8,"),
    ("insn: byte-swap width not validated", "src/insn.rs",
     "            let width = match self.imm {\n                16 | 32 | 64 => self.imm as u8,",
     "            let width = match self.imm {\n                _ if true => self.imm as u8,\n                16 | 32 | 64 => self.imm as u8,"),

    ("btf: bitfield offset and width left packed", "src/btf.rs",
     "                            (off & 0x00ff_ffff, (off >> 24) & 0xff)", "                            (off, 0)"),
    ("btf: enum signedness inverted", "src/btf.rs",
     "                    if self.kind_flag { \"SIGNED\" } else { \"UNSIGNED\" },\n                    self.size_or_type,\n                    self.vlen\n                );\n                for v in &self.values {\n                    if self.kind_flag {\n                        let _ = writeln!(o, \"\\t'{}' val={}\", disp(&v.name), v.val as i32);",
     "                    if self.kind_flag { \"UNSIGNED\" } else { \"SIGNED\" },\n                    self.size_or_type,\n                    self.vlen\n                );\n                for v in &self.values {\n                    if self.kind_flag {\n                        let _ = writeln!(o, \"\\t'{}' val={}\", disp(&v.name), v.val as i32);"),
    ("btf: FUNC linkage read from a trailing word", "src/btf.rs",
     "                KIND_FUNC => t.linkage = vlen,", "                KIND_FUNC => t.linkage = 1,"),
    ("btf: the two halves of an ENUM64 value swapped", "src/btf.rs",
     "                            val: ((hi << 32) | lo) as i64,", "                            val: ((lo << 32) | hi) as i64,"),
    ("btf: string offsets not based at hdr_len", "src/btf.rs",
     "        let sstart = hdr_len\n            .checked_add(str_off)", "        let sstart = (0usize)\n            .checked_add(str_off)"),
    ("btf: a pointer is sized like the thing it points at", "src/btf.rs",
     "            KIND_PTR => Some(8),", "            KIND_PTR => self.size_of_depth(t.size_or_type, depth + 1),"),

    ("maps: max_entries taken from the pointee size", "src/maps.rs",
     "                \"max_entries\" => match arr_len {", "                \"max_entries\" => match pointee_size.map(|v| v as u32) {"),
    ("maps: .rodata not marked read-only", "src/maps.rs",
     "            flags |= F_RDONLY_PROG;", "            flags |= 0;"),
    ("maps: every data section marked mmapable", "src/maps.rs",
     "        if has_datasec {", "        if true {"),
    ("maps: key and value sizes swapped", "src/maps.rs",
     "                        Some(v) => m.key_size = v as u32,",
     "                        Some(v) => m.value_size = v as u32,"),
    ("maps: any pinning value pins, not only the one libbpf defines",
     "src/maps.rs",
     "                        Some(1) => m.pin = format!(\"/sys/fs/bpf/{}\", var.name),",
     "                        Some(_) => m.pin = format!(\"/sys/fs/bpf/{}\", var.name),"),
    # Re-quoted against the match arm. The pinning handling moved into a
    # `match arr_len` and this entry still quoted the old if-statement form,
    # trailing semicolon and all, so it matched nothing and tested nothing.
    # The entry above it survived the same refactor only because it quotes
    # the arm rather than the statement. A dead entry is not a failing test,
    # it is an absent one, and the published claim that all 73 are killed
    # covered 72.
    ("maps: a pinned map takes the section's name, not its own", "src/maps.rs",
     "                        Some(1) => m.pin = format!(\"/sys/fs/bpf/{}\", var.name),",
     "                        Some(1) => m.pin = \"/sys/fs/bpf/.maps\".to_string(),"),
    ("maps: map_extra and numa_node read from each other", "src/maps.rs",
     "                \"map_extra\" => {\n                    if let Some(v) = arr_len {\n                        m.map_extra = v as u64;",
     "                \"map_extra\" => {\n                    if let Some(v) = arr_len {\n                        m.numa_node = v;"),

    ("maps: the BTF key type id is the member's own type, not the pointee",
     "src/maps.rs",
     "            let pointee_id = inner.filter(|t| t.kind == KIND_PTR).map(|t| t.size_or_type);",
     "            let pointee_id = Some(mem.type_id);"),
    ("maps: a data section's value type is the first DATASEC in the file",
     "src/maps.rs",
     "                .position(|t| t.kind == KIND_DATASEC && t.name == n)",
     "                .position(|t| t.kind == KIND_DATASEC)"),

    ("maps: a short legacy map def is padded to five words in silence",
     "src/maps.rs",
     "        if vals.len() < 5 {\n            m.notes.push(format!(",
     "        vals.resize(5, 0);\n        if false {\n            m.notes.push(format!("),
    ("maps: legacy fields read in the wrong order", "src/maps.rs",
     "        m.mtype = at(0);\n        m.key_size = at(1);",
     "        m.mtype = at(0);\n        m.key_size = at(2);"),

    ("prog: st_size ignored, functions run to the section end", "src/prog.rs",
     "            let end = if y.size > 0 {\n                start.saturating_add((y.size / 8) as usize)\n            } else {\n                slots\n            };",
     "            let end = slots;"),
    ("prog: relocation slot is the byte offset", "src/prog.rs",
     ".map(|r| ((r.offset / 8) as usize, r.clone()))", ".map(|r| (r.offset as usize, r.clone()))"),
    ("prog: every symbol in the section becomes a function", "src/prog.rs",
     ".filter(|y| y.stype() == STT_FUNC && y.shndx as usize == s.idx)",
     ".filter(|y| y.shndx as usize == s.idx)"),
    ("prog: the slot map gets one spare element", "src/prog.rs",
     "    let mut slot_map = vec![None; slots];", "    let mut slot_map = vec![None; slots + 1];"),
    ("prog: function start not clamped to the section", "src/prog.rs",
     "            let start = ((y.value / 8) as usize).min(slots);",
     "            let start = (y.value / 8) as usize;"),

    ("cfg: jump offsets measured from the jump itself", "src/cfg.rs",
     "    let next = (ins.idx + ins.slots) as i64;", "    let next = ins.idx as i64;"),
    ("cfg: the long jump reads off instead of imm", "src/cfg.rs",
     "        Some(Op::Ja { long }) => Some(if *long {\n            next + ins.imm as i64\n        } else {\n            next + ins.off as i64\n        }),",
     "        Some(Op::Ja { .. }) => Some(next + ins.off as i64),"),
    ("cfg: forming a frame address does not count", "src/cfg.rs",
     "                    materialise(v, deepest);\n                    st.set(ins.dst, v);\n                }\n                AluOp::Sub",
     "                    st.set(ins.dst, v);\n                }\n                AluOp::Sub"),
    ("cfg: a 32-bit move keeps the frame pointer", "src/cfg.rs",
     "                    let v = if *reg && *sx == 0 && *wide {", "                    let v = if *reg && *sx == 0 {"),
    ("cfg: stack offsets ignore the base register", "src/cfg.rs",
     "        let lo = k + off as i64;", "        let lo = off as i64;"),
    ("cfg: unreachable blocks not reported", "src/cfg.rs",
     "        if !cfg.reachable[b] {\n            let blk = &cfg.blocks[b];",
     "        if false && !cfg.reachable[b] {\n            let blk = &cfg.blocks[b];"),
    ("cfg: a jump into a wide load resolves to the whole load", "src/cfg.rs",
     "                match p.slot_map.get(t).copied().flatten() {\n                    Some(_) => leaders.push(t),\n                    None => cfg.problems.push(Problem::TargetMidWide {\n                        slot: ins.idx,\n                        target: t,\n                    }),\n                }",
     "                leaders.push(t);"),
    ("cfg: the uninitialised-register check never fires", "src/cfg.rs",
     "    if (r as usize) < NREG && !st.is_init(r) {", "    if false {"),
    ("cfg: every register is live on entry", "src/cfg.rs",
     "        s.init = 1 << 10 | 1 << 1;", "        s.init = 0xffff;"),
    ("cfg: register numbers indexed without a bounds check", "src/cfg.rs",
     "                        st.get(ins.src)", "                        st.fp[ins.src as usize]"),
    ("cfg: back edges not detected", "src/cfg.rs",
     "                GREY => found.push((b, s)),", "                GREY => {}"),

    ("sectype: every table row matches as a prefix", "src/prog.rs",
     "            || (!row.1\n", "            || (true\n"),
    ("sectype: kprobe sections typed as tracepoints", "src/prog.rs",
     "    (\"kprobe\", false, 2, \"KPROBE\", -1),",
     "    (\"kprobe\", false, 5, \"TRACEPOINT\", -1),"),
    ("sectype: an exact row is read as a prefix row", "src/prog.rs",
     "    (\"socket\", true, 1, \"SOCKET_FILTER\", -1),",
     "    (\"socket\", false, 1, \"SOCKET_FILTER\", -1),"),
    ("sectype: the cgroup ingress attach type becomes no attach type",
     "src/prog.rs",
     "    (\"cgroup_skb/ingress\", true, 8, \"CGROUP_SKB\", 0),",
     "    (\"cgroup_skb/ingress\", true, 8, \"CGROUP_SKB\", -1),"),
    ("sectype: connect4 and connect6 share an attach type", "src/prog.rs",
     "    (\"cgroup/connect6\", true, 18, \"CGROUP_SOCK_ADDR\", 11),",
     "    (\"cgroup/connect6\", true, 18, \"CGROUP_SOCK_ADDR\", 10),"),

    ("btfext: a missing .BTF is a warning rather than a refusal",
     "src/main.rs",
     "                eprintln!(\"bpfdis: {}: .BTF.ext with no .BTF: its strings are in .BTF\", path);\n                emit(&o);\n                return ExitCode::from(1);",
     "                eprintln!(\"bpfdis: {}: .BTF.ext with no .BTF: its strings are in .BTF\", path);"),

    ("btfext: insn_off read as an instruction index, not a byte offset",
     "src/btfext.rs",
     "                    \"line_info {} slot={} {}:{}:{}\",\n"
     "                    s.name,\n                    r.insn_off / 8,",
     "                    \"line_info {} slot={} {}:{}:{}\",\n"
     "                    s.name,\n                    r.insn_off,"),
    ("btfext: the line and column halves of line_col swapped", "src/btfext.rs",
     "                    line: line_col >> 10,\n                    col: line_col & 0x3ff,",
     "                    line: line_col & 0x3ff,\n                    col: line_col >> 10,"),
    ("btfext: records advanced by the fields read, not the declared size",
     "src/btfext.rs",
     "            let raw = c.take(rec_size as usize)?;",
     "            let raw = c.take(8)?;"),
    ("btfext: the file name and the source text strings swapped",
     "src/btfext.rs",
     "                let file = c.u32()?;\n                let text = c.u32()?;",
     "                let text = c.u32()?;\n                let file = c.u32()?;"),
    ("cfg: helper 5 is named as helper 6", "src/cfg.rs",
     "\"bpf_trace_printk\", \"bpf_get_prandom_u32\"",
     "\"bpf_get_prandom_u32\", \"bpf_trace_printk\""),
    ("cfg: helper names indexed from one", "src/cfg.rs",
     "    HELPERS.get(n as usize).copied()",
     "    HELPERS.get(n as usize - 1).copied()"),

    ("elf: a big-endian object is read as little-endian", "src/elf.rs",
     "        if file[5] != 1 {", "        if false {"),

    ("cfg: a call across sections is not followed", "src/cfg.rs",
     "                    None => find(p.sec_idx, *t as usize),",
     "                    None => find(p.sec_idx, *t as usize),\n                    Some(_) if true => None,"),
    ("cfg: a relocated call target misses the symbol's own offset",
     "src/cfg.rs",
     "                                let slot = base + imm + 1;",
     "                                let slot = imm + 1;"),

    ("cfg: a cycle in the call graph is not reported", "src/cfg.rs",
     "                if !cycles.contains(&(i, j)) {",
     "                if false && !cycles.contains(&(i, j)) {"),
    ("cfg: call depth counted from zero, so the limit is off by one",
     "src/cfg.rs",
     "        depth[i] = best + 1;", "        depth[i] = best;"),
    ("cfg: the call-depth limit is the kernel's frame count plus one",
     "src/cfg.rs",
     "pub const MAX_CALL_DEPTH: usize = 8;", "pub const MAX_CALL_DEPTH: usize = 9;"),

    ("cfg: subprogram call targets not checked", "src/cfg.rs",
     "                if p.reloc_at(ins.idx).is_none()",
     "                if false && p.reloc_at(ins.idx).is_none()"),
    ("cfg: a relocated call has its placeholder offset checked", "src/cfg.rs",
     "                if p.reloc_at(ins.idx).is_none()\n",
     "                if true\n"),

    ("btfext: func_info type id read from the offset field", "src/btfext.rs",
     "                Ok(FuncInfo {\n                    insn_off: c.u32()?,\n"
     "                    type_id: c.u32()?,\n                })",
     "                let v = c.u32()?;\n                let _ = c.u32()?;\n"
     "                Ok(FuncInfo {\n                    insn_off: v,\n"
     "                    type_id: v,\n                })"),
]


def run_suite():
    p = subprocess.run(["make", "test"], cwd=ROOT, capture_output=True, text=True)
    fails = [l for l in p.stdout.splitlines() if l.startswith("FAIL")]
    last = [l for l in p.stdout.splitlines() if re.match(r"^\d+ passed, \d+ failed$", l)]
    if p.returncode != 0 and not last:
        # The build itself failed, or `make overread` did. Both count as
        # killed, but say which so a mutant that merely fails to compile is
        # not mistaken for one the suite caught.
        why = "build or overread gate failed"
        for l in (p.stdout + p.stderr).splitlines():
            if "overread" in l and "FAIL" in l:
                why = l.strip()
            if l.startswith("error["):
                why = l.strip()
        return True, why, last[0] if last else "-"
    if not last:
        return True, "suite produced no total line", "-"
    killed = p.returncode != 0 or not last[0].endswith("0 failed")
    return killed, (fails[0][5:].strip() if fails else "exit %d" % p.returncode), last[0]


def check():
    """Every entry's pattern still appears exactly once in the file it names.

    The sweep itself reports a pattern that no longer applies, and counts it
    apart from a survivor, which is right. What it cannot do is be run: it
    takes about an hour, so it is not in `make test`, and between runs an
    entry can rot without anything saying so. One had, since the pinning
    refactor, and the README went on claiming all 73 were killed by a named
    assertion when the real figure was 72.

    This asks the same question about every entry in well under a second,
    which is cheap enough for the suite. It does not replace the sweep; it
    stops the sweep's table from decaying unnoticed between sweeps.
    """
    src, bad = {}, []
    for name, rel, old, _new in MUTANTS:
        if rel not in src:
            src[rel] = open(os.path.join(ROOT, rel)).read()
        n = src[rel].count(old)
        if n != 1:
            bad.append((name, rel, n, old.strip()[:60]))
    for name, rel, n, snip in bad:
        print("STALE %-50s %s: appears %d times, not once: %s"
              % (name, rel, n, snip))
    if bad:
        print("mutants: %d of %d entries no longer apply to the source"
              % (len(bad), len(MUTANTS)))
        return 1
    print("mutants: %d entries, every pattern applies exactly once"
          % len(MUTANTS))
    return 0


def main():
    if "--check" in sys.argv:
        return check()
    only = sys.argv[1] if len(sys.argv) > 1 else None
    killed = survived = notapplied = 0
    lines = []
    for name, rel, old, new in MUTANTS:
        if only and only not in name:
            continue
        path = os.path.join(ROOT, rel)
        orig = open(path).read()
        if orig.count(old) != 1:
            notapplied += 1
            lines.append("NOT-APPLIED  %s (pattern appears %d times)"
                         % (name, orig.count(old)))
            continue
        try:
            open(path, "w").write(orig.replace(old, new, 1))
            k, why, total = run_suite()
        finally:
            open(path, "w").write(orig)
        if k:
            killed += 1
            lines.append("killed    %-60s %s | %s" % (name, total, why))
        else:
            survived += 1
            lines.append("SURVIVED  %-60s %s" % (name, total))
    # Put the survivors and the misapplied ones first: a truncated report
    # that buries them under forty successes is a report nobody reads.
    lines.sort(key=lambda l: 0 if l.startswith(("SURVIVED", "NOT-APPLIED")) else 1)
    for l in lines:
        print(l)
    print()
    print("%d mutants, %d killed, %d survived, %d not applied"
          % (killed + survived + notapplied, killed, survived, notapplied))
    return 1 if (survived or notapplied) else 0


if __name__ == "__main__":
    sys.exit(main())
