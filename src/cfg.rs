//! The control-flow graph, and the properties the verifier cares about.
//!
//! One graph per function, because a `call` with `src_reg` 1 enters another
//! function and the verifier walks each one separately.
//!
//! Three things make building this harder than it looks. A jump offset is
//! counted in 8-byte slots from the instruction AFTER the jump, so a 16-byte
//! immediate load two instructions away moves the target by two and not by
//! one. A jump can land in the middle of a 16-byte load, which is a
//! rejection and is invisible to anything that walks instructions in order.
//! And a function's instructions are a window into a shared section, so an
//! edge that leaves the window is falling out of the function rather than
//! branching within it.

use crate::insn::{Insn, Op};
use crate::prog::{Func, Prog};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Term {
    /// `exit`: no successors at all.
    Exit,
    /// `goto` or `gotol`: one successor, not the next instruction.
    Jump,
    /// A conditional jump or `may_goto`: two successors.
    Cond,
    /// Runs into the next block.
    Fall,
    /// The last instruction of the function is not a jump and there is
    /// nothing after it.
    FallsOffEnd,
    /// The block ends at an instruction bpfdis could not decode, so where it
    /// goes next is unknown and no edge is invented.
    Undecodable,
}

pub struct Block {
    pub start: usize,
    pub end: usize,
    pub first_insn: usize,
    pub last_insn: usize,
    pub term: Term,
    pub succs: Vec<usize>,
    pub preds: Vec<usize>,
}

#[derive(Clone)]
pub enum Problem {
    /// Instructions no path reaches. The verifier rejects these outright.
    Unreachable { slot: usize, count: usize },
    /// A jump whose target is outside the function.
    TargetOutside { slot: usize, target: i64 },
    /// A jump that lands on the second half of a 16-byte immediate load.
    TargetMidWide { slot: usize, target: usize },
    /// The instruction stream runs off the end without an `exit`.
    FallsOffEnd { slot: usize },
    /// A back edge: the function contains a loop. Kernels before 5.3 reject
    /// any of these; current kernels accept bounded ones.
    BackEdge { from: usize, to: usize },
    /// An instruction that could not be decoded at all.
    Undecodable { slot: usize, code: u8 },
    /// A register the kernel does not have.
    BadRegister { slot: usize },
    /// A field the kernel requires to be zero and is not.
    DirtyField { slot: usize, what: &'static str },
    /// The stack frame is deeper than the kernel's 512-byte limit.
    StackTooDeep { bytes: u64 },
    /// A read of a register no path has written.
    UninitRead { slot: usize, reg: u8 },
}

impl Problem {
    pub fn severity(&self) -> &'static str {
        match self {
            // The kernel rejects all of these outright.
            Problem::Unreachable { .. }
            | Problem::TargetOutside { .. }
            | Problem::TargetMidWide { .. }
            | Problem::FallsOffEnd { .. }
            | Problem::Undecodable { .. }
            | Problem::BadRegister { .. }
            | Problem::StackTooDeep { .. }
            | Problem::UninitRead { .. } => "reject",
            // A loop is fine on a 5.3 kernel or later if the verifier can
            // bound it, and fine never otherwise, so it is not a verdict.
            Problem::BackEdge { .. } => "note",
            Problem::DirtyField { .. } => "reject",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Problem::Unreachable { slot, count } => format!(
                "{} instruction(s) starting at slot {} are not reachable from the entry",
                count, slot
            ),
            Problem::TargetOutside { slot, target } => format!(
                "the jump at slot {} targets slot {}, outside the function",
                slot, target
            ),
            Problem::TargetMidWide { slot, target } => format!(
                "the jump at slot {} targets slot {}, the second half of a 16-byte load",
                slot, target
            ),
            Problem::FallsOffEnd { slot } => format!(
                "the instruction at slot {} is the last one and is not an exit or a jump",
                slot
            ),
            Problem::BackEdge { from, to } => {
                format!("back edge from slot {} to slot {}: a loop", from, to)
            }
            Problem::Undecodable { slot, code } => format!(
                "the instruction at slot {} has opcode {:#04x}, which is not allocated",
                slot, code
            ),
            Problem::BadRegister { slot } => format!(
                "the instruction at slot {} names a register above r10",
                slot
            ),
            Problem::DirtyField { slot, what } => format!(
                "the instruction at slot {} has {}, which the kernel requires to be zero",
                slot, what
            ),
            Problem::StackTooDeep { bytes } => format!(
                "the stack frame is {} bytes; the kernel limit is 512",
                bytes
            ),
            Problem::UninitRead { slot, reg } => format!(
                "the instruction at slot {} reads r{}, which no path has written",
                slot, reg
            ),
        }
    }
}

pub struct Cfg {
    pub func: String,
    pub start: usize,
    pub end: usize,
    pub blocks: Vec<Block>,
    pub reachable: Vec<bool>,
    pub problems: Vec<Problem>,
    /// Deepest stack use found, as a positive byte count below `r10`.
    pub stack_bytes: u64,
    /// Helper numbers called, sorted and deduplicated.
    pub helpers: Vec<i32>,
    /// Slot numbers of subprogram calls, with the slot they call.
    pub calls: Vec<(usize, i64)>,
    /// Instructions reached by the walk, which is how a vacuous analysis is
    /// told from a clean one.
    pub insns_seen: usize,
}

/// Where a jump at `ins` goes, in section slots.
pub fn jump_target(ins: &Insn) -> Option<i64> {
    let next = (ins.idx + ins.slots) as i64;
    match &ins.op {
        Some(Op::Jmp { .. }) => Some(next + ins.off as i64),
        Some(Op::Ja { long }) => Some(if *long {
            next + ins.imm as i64
        } else {
            next + ins.off as i64
        }),
        Some(Op::MayGoto) => Some(next + ins.off as i64),
        _ => None,
    }
}

fn is_exit(ins: &Insn) -> bool {
    matches!(ins.op, Some(Op::Exit))
}

fn is_uncond(ins: &Insn) -> bool {
    matches!(ins.op, Some(Op::Ja { .. }))
}

fn is_cond(ins: &Insn) -> bool {
    matches!(ins.op, Some(Op::Jmp { .. }) | Some(Op::MayGoto))
}

pub fn build(p: &Prog, f: &Func) -> Cfg {
    let mut cfg = Cfg {
        func: f.name.clone(),
        start: f.start,
        end: f.end,
        blocks: Vec::new(),
        reachable: Vec::new(),
        problems: Vec::new(),
        stack_bytes: 0,
        helpers: Vec::new(),
        calls: Vec::new(),
        insns_seen: 0,
    };
    // Instruction indices belonging to this function.
    let idxs: Vec<usize> = (0..p.insns.len())
        .filter(|&i| p.insns[i].idx >= f.start && p.insns[i].idx < f.end)
        .collect();
    if idxs.is_empty() {
        return cfg;
    }
    cfg.insns_seen = idxs.len();

    // Leaders: the entry, every jump target, and whatever follows a
    // terminator.
    let mut leaders: Vec<usize> = vec![f.start];
    for &i in &idxs {
        let ins = &p.insns[i];
        if ins.op.is_none() {
            cfg.problems.push(Problem::Undecodable {
                slot: ins.idx,
                code: ins.code,
            });
        }
        if let Some(t) = jump_target(ins) {
            if t < f.start as i64 || t >= f.end as i64 {
                cfg.problems.push(Problem::TargetOutside {
                    slot: ins.idx,
                    target: t,
                });
            } else {
                let t = t as usize;
                match p.slot_map.get(t).copied().flatten() {
                    Some(_) => leaders.push(t),
                    None => cfg.problems.push(Problem::TargetMidWide {
                        slot: ins.idx,
                        target: t,
                    }),
                }
            }
        }
        if is_exit(ins) || is_uncond(ins) || is_cond(ins) {
            let next = ins.idx + ins.slots;
            if next < f.end {
                leaders.push(next);
            }
        }
    }
    leaders.sort_unstable();
    leaders.dedup();
    leaders.retain(|&l| p.slot_map.get(l).copied().flatten().is_some());

    // Blocks run from one leader to the next.
    for (bi, &l) in leaders.iter().enumerate() {
        let next_leader = leaders.get(bi + 1).copied().unwrap_or(f.end);
        let first = p.slot_map[l].unwrap();
        let mut last = first;
        while last + 1 < p.insns.len() && p.insns[last + 1].idx < next_leader {
            last += 1;
        }
        let term = {
            let ins = &p.insns[last];
            if ins.op.is_none() {
                Term::Undecodable
            } else if is_exit(ins) {
                Term::Exit
            } else if is_uncond(ins) {
                Term::Jump
            } else if is_cond(ins) {
                Term::Cond
            } else if ins.idx + ins.slots >= f.end {
                Term::FallsOffEnd
            } else {
                Term::Fall
            }
        };
        cfg.blocks.push(Block {
            start: l,
            end: next_leader,
            first_insn: first,
            last_insn: last,
            term,
            succs: Vec::new(),
            preds: Vec::new(),
        });
    }

    let block_of = |slot: usize, blocks: &Vec<Block>| -> Option<usize> {
        blocks.iter().position(|b| b.start == slot)
    };

    for bi in 0..cfg.blocks.len() {
        let last = cfg.blocks[bi].last_insn;
        let ins = &p.insns[last];
        let mut succs: Vec<usize> = Vec::new();
        match cfg.blocks[bi].term {
            Term::Exit | Term::Undecodable => {}
            Term::FallsOffEnd => {
                cfg.problems.push(Problem::FallsOffEnd { slot: ins.idx });
            }
            Term::Fall => {
                if let Some(s) = block_of(ins.idx + ins.slots, &cfg.blocks) {
                    succs.push(s);
                }
            }
            Term::Jump => {
                if let Some(t) = jump_target(ins) {
                    if let Some(s) = block_of(t.max(0) as usize, &cfg.blocks) {
                        succs.push(s);
                    }
                }
            }
            Term::Cond => {
                if let Some(s) = block_of(ins.idx + ins.slots, &cfg.blocks) {
                    succs.push(s);
                }
                if let Some(t) = jump_target(ins) {
                    if let Some(s) = block_of(t.max(0) as usize, &cfg.blocks) {
                        succs.push(s);
                    }
                }
            }
        }
        succs.dedup();
        for &s in &succs {
            cfg.blocks[s].preds.push(bi);
        }
        cfg.blocks[bi].succs = succs;
    }

    reachability(&mut cfg, p);
    back_edges(&mut cfg);
    collect(&mut cfg, p, &idxs);
    cfg
}

fn reachability(cfg: &mut Cfg, p: &Prog) {
    let n = cfg.blocks.len();
    cfg.reachable = vec![false; n];
    if n == 0 {
        return;
    }
    let mut stack = vec![0usize];
    cfg.reachable[0] = true;
    while let Some(b) = stack.pop() {
        for &s in &cfg.blocks[b].succs {
            if !cfg.reachable[s] {
                cfg.reachable[s] = true;
                stack.push(s);
            }
        }
    }
    // Report runs of unreachable blocks as one finding each, naming the
    // first slot and how many instructions it covers.
    for b in 0..n {
        if !cfg.reachable[b] {
            let blk = &cfg.blocks[b];
            let count = blk.last_insn - blk.first_insn + 1;
            cfg.problems.push(Problem::Unreachable {
                slot: p.insns[blk.first_insn].idx,
                count,
            });
        }
    }
}

/// Depth-first search with three colours. An edge to a grey node, one still
/// on the search stack, is a back edge, which is the definition of a loop in
/// a reducible or irreducible graph alike.
fn back_edges(cfg: &mut Cfg) {
    let n = cfg.blocks.len();
    if n == 0 {
        return;
    }
    const WHITE: u8 = 0;
    const GREY: u8 = 1;
    const BLACK: u8 = 2;
    let mut colour = vec![WHITE; n];
    let mut found = Vec::new();
    // Iterative, because a function can have more blocks than the stack has
    // frames and the input is a file.
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    colour[0] = GREY;
    while let Some((b, si)) = stack.pop() {
        if si < cfg.blocks[b].succs.len() {
            stack.push((b, si + 1));
            let s = cfg.blocks[b].succs[si];
            match colour[s] {
                WHITE => {
                    colour[s] = GREY;
                    stack.push((s, 0));
                }
                GREY => found.push((b, s)),
                _ => {}
            }
        } else {
            colour[b] = BLACK;
        }
    }
    for (from, to) in found {
        cfg.problems.push(Problem::BackEdge {
            from: cfg.blocks[from].start,
            to: cfg.blocks[to].start,
        });
    }
}

fn collect(cfg: &mut Cfg, p: &Prog, idxs: &[usize]) {
    for &i in idxs {
        let ins = &p.insns[i];
        if ins.defects.contains(&crate::insn::Defect::RegOutOfRange) {
            cfg.problems.push(Problem::BadRegister { slot: ins.idx });
        }
        for d in &ins.defects {
            if *d != crate::insn::Defect::RegOutOfRange {
                cfg.problems.push(Problem::DirtyField {
                    slot: ins.idx,
                    what: d.name(),
                });
            }
        }
        match &ins.op {
            Some(Op::Call { pseudo: 0 }) => cfg.helpers.push(ins.imm),
            Some(Op::Call { pseudo: 1 }) => {
                cfg.calls
                    .push((ins.idx, (ins.idx + ins.slots) as i64 + ins.imm as i64));
            }
            _ => {}
        }
    }
    cfg.helpers.sort_unstable();
    cfg.helpers.dedup();
}

// --------------------------------------------------------------- dataflow
//
// A small abstract interpretation over the graph, tracking two things the
// verifier also tracks: which registers hold a frame pointer plus a known
// constant, and which registers have been written on every path reaching
// this point.
//
// The first is what makes a stack-depth number worth printing. Programs do
// not address the stack through `r10` directly; clang emits `r2 = r10;
// r2 += -4` and then writes through `r2`, so a tool that only looks at
// `r10 + off` sees almost nothing. The verifier propagates the frame-pointer
// type the same way, which is why `r2` is a legal stack address at all.
//
// The second catches the single most common real rejection: reading a
// register no path has written.

const NREG: usize = 11;

#[derive(Clone, PartialEq)]
struct State {
    /// `Some(k)` when the register certainly holds the frame pointer plus
    /// `k` on every path here; `None` when it does not, or when the paths
    /// disagree.
    fp: [Option<i64>; NREG],
    /// Bit set when the register is written on every path here.
    init: u16,
}

impl State {
    fn bottom() -> State {
        State {
            fp: [None; NREG],
            init: 0,
        }
    }
    fn entry(is_subprog: bool) -> State {
        let mut s = State::bottom();
        s.fp[10] = Some(0);
        // r1 is the context pointer on entry to a program. A subprogram is
        // called with up to five arguments and the verifier knows which from
        // the callee's BTF, which bpfdis does not read, so all five are
        // treated as live to avoid inventing rejections.
        s.init = 1 << 10 | 1 << 1;
        if is_subprog {
            s.init |= 0b111110;
        }
        s
    }
    /// Meet: a fact survives only if it holds on every incoming path.
    fn meet(&mut self, other: &State) -> bool {
        let mut changed = false;
        for i in 0..NREG {
            if self.fp[i] != other.fp[i] && self.fp[i].is_some() {
                self.fp[i] = None;
                changed = true;
            }
        }
        let ni = self.init & other.init;
        if ni != self.init {
            self.init = ni;
            changed = true;
        }
        changed
    }
    fn is_init(&self, r: u8) -> bool {
        (r as usize) < NREG && self.init & (1 << r) != 0
    }
    fn set(&mut self, r: u8, fp: Option<i64>) {
        if (r as usize) < NREG {
            self.fp[r as usize] = fp;
            self.init |= 1 << r;
        }
    }
    fn clobber_args(&mut self) {
        for r in 1..=5u8 {
            self.fp[r as usize] = None;
            self.init &= !(1 << r);
        }
    }
}

fn width_of(size: u8) -> i64 {
    match size {
        crate::insn::BPF_W => 4,
        crate::insn::BPF_H => 2,
        crate::insn::BPF_B => 1,
        _ => 8,
    }
}

/// Run the dataflow to a fixed point and record what it found.
pub fn analyse(cfg: &mut Cfg, p: &Prog, is_subprog: bool) {
    let n = cfg.blocks.len();
    if n == 0 {
        return;
    }
    let mut entry: Vec<Option<State>> = vec![None; n];
    entry[0] = Some(State::entry(is_subprog));
    // Worklist to a fixed point. Each block is re-run when a predecessor's
    // exit state weakens the facts at its entry; the lattice only ever loses
    // facts, so this terminates.
    let mut work: Vec<usize> = vec![0];
    let mut rounds = 0usize;
    while let Some(b) = work.pop() {
        rounds += 1;
        if rounds > 200 * n + 1000 {
            // Cannot happen with a monotone transfer, and the input is a
            // file, so the guard stays.
            cfg.problems.push(Problem::Undecodable {
                slot: cfg.blocks[b].start,
                code: 0,
            });
            break;
        }
        let st = match &entry[b] {
            Some(s) => s.clone(),
            None => continue,
        };
        let out = run_block(cfg, p, b, st);
        for si in 0..cfg.blocks[b].succs.len() {
            let s = cfg.blocks[b].succs[si];
            match &mut entry[s] {
                None => {
                    entry[s] = Some(out.clone());
                    work.push(s);
                }
                Some(e) => {
                    if e.meet(&out) {
                        work.push(s);
                    }
                }
            }
        }
    }
    // Second pass with reporting on, now that the entry states are final.
    let mut deepest: i64 = 0;
    let mut problems = Vec::new();
    for b in 0..n {
        if !cfg.reachable[b] {
            continue;
        }
        let st = match &entry[b] {
            Some(s) => s.clone(),
            None => continue,
        };
        let (_out, d, mut ps) = run_block_report(cfg, p, b, st);
        deepest = deepest.min(d);
        problems.append(&mut ps);
    }
    cfg.stack_bytes = (-deepest).max(0) as u64;
    if cfg.stack_bytes > 512 {
        problems.push(Problem::StackTooDeep {
            bytes: cfg.stack_bytes,
        });
    }
    cfg.problems.append(&mut problems);
}

fn run_block(cfg: &Cfg, p: &Prog, b: usize, st: State) -> State {
    run_block_report(cfg, p, b, st).0
}

/// Interpret one block. Returns the exit state, the lowest stack offset
/// touched (zero or negative), and whatever it found worth reporting.
fn run_block_report(cfg: &Cfg, p: &Prog, b: usize, mut st: State) -> (State, i64, Vec<Problem>) {
    let blk = &cfg.blocks[b];
    let mut deepest: i64 = 0;
    let mut ps: Vec<Problem> = Vec::new();
    for i in blk.first_insn..=blk.last_insn {
        step(&mut st, &p.insns[i], &mut deepest, &mut ps);
    }
    (st, deepest, ps)
}

fn need(st: &State, slot: usize, r: u8, ps: &mut Vec<Problem>) {
    if (r as usize) < NREG && !st.is_init(r) {
        ps.push(Problem::UninitRead { slot, reg: r });
    }
}

/// A stack access through a register known to hold `fp + k`.
fn touch(st: &State, base: u8, off: i16, size: u8, deepest: &mut i64) {
    if let Some(k) = st.fp.get(base as usize).copied().flatten() {
        let lo = k + off as i64;
        // Reading below the frame pointer is what makes the frame deep; a
        // positive offset is into the caller's frame and is a rejection the
        // verifier reports separately, not a depth.
        if lo < *deepest {
            *deepest = lo;
        }
        let _ = size;
    }
}

/// Forming a stack address counts, not only dereferencing one.
///
/// This was measured, not assumed. `deep` in t/corpus/mem.c builds
/// `r4 = r10; r4 += -0x80; r4 += r2` and then writes through `r4`, so by the
/// time there is a dereference the offset is no longer known and a tool that
/// only watches dereferences reports a stack depth of zero for a function
/// with a 128-byte array. LLVM's own check is at the point the frame address
/// is materialised, which is why counting here agrees with it.
fn materialise(k: Option<i64>, deepest: &mut i64) {
    if let Some(k) = k {
        if k < *deepest {
            *deepest = k;
        }
    }
}

fn step(st: &mut State, ins: &Insn, deepest: &mut i64, ps: &mut Vec<Problem>) {
    use crate::insn::AluOp;
    let slot = ins.idx;
    let op = match &ins.op {
        Some(o) => o,
        None => return,
    };
    match op {
        Op::Alu {
            op: a,
            reg,
            sx,
            wide,
            ..
        } => {
            if *reg {
                need(st, slot, ins.src, ps);
            }
            match a {
                AluOp::Mov => {
                    // A move keeps the frame-pointer fact; a sign-extending
                    // move or a 32-bit move does not, because it truncates.
                    let v = if *reg && *sx == 0 && *wide {
                        st.fp[ins.src as usize]
                    } else {
                        None
                    };
                    st.set(ins.dst, v);
                }
                AluOp::Neg => {
                    need(st, slot, ins.dst, ps);
                    st.set(ins.dst, None);
                }
                AluOp::Add if !*reg && *wide => {
                    need(st, slot, ins.dst, ps);
                    let v = st.fp[ins.dst as usize].map(|k| k + ins.imm as i64);
                    materialise(v, deepest);
                    st.set(ins.dst, v);
                }
                AluOp::Sub if !*reg && *wide => {
                    need(st, slot, ins.dst, ps);
                    let v = st.fp[ins.dst as usize].map(|k| k - ins.imm as i64);
                    materialise(v, deepest);
                    st.set(ins.dst, v);
                }
                _ => {
                    need(st, slot, ins.dst, ps);
                    st.set(ins.dst, None);
                }
            }
        }
        Op::AddrSpaceCast => {
            need(st, slot, ins.src, ps);
            st.set(ins.dst, None);
        }
        Op::End { .. } => {
            need(st, slot, ins.dst, ps);
            st.set(ins.dst, None);
        }
        Op::Jmp { reg, .. } => {
            need(st, slot, ins.dst, ps);
            if *reg {
                need(st, slot, ins.src, ps);
            }
        }
        Op::Ja { .. } | Op::MayGoto => {}
        Op::Call { pseudo } => {
            // Helper and subprogram calls both return in r0 and clobber the
            // argument registers. Which arguments are read depends on the
            // callee's prototype, which bpfdis does not know, so no
            // uninitialised-argument finding is made here.
            let _ = pseudo;
            st.clobber_args();
            st.set(0, None);
        }
        Op::CallX => {
            need(st, slot, ins.dst, ps);
            st.clobber_args();
            st.set(0, None);
        }
        Op::Exit => {
            need(st, slot, 0, ps);
        }
        Op::Load { size, .. } => {
            need(st, slot, ins.src, ps);
            touch(st, ins.src, ins.off, *size, deepest);
            st.set(ins.dst, None);
        }
        Op::StoreImm { size } => {
            need(st, slot, ins.dst, ps);
            touch(st, ins.dst, ins.off, *size, deepest);
        }
        Op::StoreReg { size } => {
            need(st, slot, ins.dst, ps);
            need(st, slot, ins.src, ps);
            touch(st, ins.dst, ins.off, *size, deepest);
        }
        Op::Atomic { size, aop, fetch } => {
            need(st, slot, ins.dst, ps);
            need(st, slot, ins.src, ps);
            touch(st, ins.dst, ins.off, *size, deepest);
            if matches!(aop, crate::insn::AtomicOp::CmpXchg) {
                need(st, slot, 0, ps);
                st.set(0, None);
            } else if *fetch {
                st.set(ins.src, None);
            }
        }
        Op::LdImm64 { .. } => {
            st.set(ins.dst, None);
        }
        Op::LdAbs { .. } => {
            // The legacy packet accesses read the socket buffer out of r6
            // and clobber r1 through r5.
            need(st, slot, 6, ps);
            st.clobber_args();
            st.set(0, None);
        }
        Op::LdInd { .. } => {
            need(st, slot, 6, ps);
            need(st, slot, ins.src, ps);
            st.clobber_args();
            st.set(0, None);
        }
    }
}
