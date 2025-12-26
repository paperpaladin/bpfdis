//! Programs: an executable section cut into functions, with its relocations
//! attached to the instructions they patch.
//!
//! A `.text` section holding four `STT_FUNC` symbols is four programs sharing
//! one instruction stream, not one program. Every per-program number -- stack
//! depth, reachability, whether a path reaches `exit` -- is wrong if they are
//! treated as one, so the split happens here, once, and everything above
//! reads it.

use crate::elf::{Elf, Reloc, Section, STT_FUNC};
use crate::insn::{decode_all, Insn};

pub struct Func {
    pub name: String,
    /// First instruction slot, counted in 8-byte units from the section start.
    pub start: usize,
    /// One past the last slot.
    pub end: usize,
    pub global: bool,
    /// Index into `Prog::insns` of the first instruction, if the symbol's
    /// value lands on an instruction boundary at all.
    pub first: Option<usize>,
}

pub struct Prog {
    pub sec_idx: usize,
    pub name: String,
    pub slots: usize,
    pub insns: Vec<Insn>,
    /// `slot -> index into insns`, so a jump target can be resolved without
    /// a scan and a jump into the middle of a 16-byte load can be detected.
    pub slot_map: Vec<Option<usize>>,
    pub funcs: Vec<Func>,
    /// Relocations that fall inside this section, by instruction slot.
    pub relocs: Vec<(usize, Reloc)>,
    pub tail_err: Option<String>,
}

impl Prog {
    pub fn reloc_at(&self, slot: usize) -> Option<&Reloc> {
        self.relocs.iter().find(|(s, _)| *s == slot).map(|(_, r)| r)
    }

    /// The function containing a slot, if any.
    pub fn func_of(&self, slot: usize) -> Option<&Func> {
        self.funcs.iter().find(|f| slot >= f.start && slot < f.end)
    }
}

fn build_one(e: &Elf, s: &Section) -> Prog {
    let code = s.data(&e.file);
    let (insns, tail_err) = decode_all(code);
    let slots = code.len() / 8;
    let mut slot_map = vec![None; slots + 1];
    for (i, ins) in insns.iter().enumerate() {
        if ins.idx < slot_map.len() {
            slot_map[ins.idx] = Some(i);
        }
    }

    let mut funcs: Vec<Func> = e
        .syms
        .iter()
        .filter(|y| y.stype() == STT_FUNC && y.shndx as usize == s.idx)
        .map(|y| {
            let start = (y.value / 8) as usize;
            let end = if y.size > 0 {
                start + (y.size / 8) as usize
            } else {
                slots
            };
            Func {
                name: y.name.clone(),
                start,
                end: end.min(slots),
                global: y.bind() != 0,
                first: slot_map.get(start).copied().flatten(),
            }
        })
        .collect();
    funcs.sort_by_key(|f| f.start);
    // A symbol with no size runs to the start of the next one. clang emits
    // sizes, but a hand-written object need not, and a function that claims
    // the whole section would swallow its neighbours.
    for i in 0..funcs.len() {
        let next = funcs.get(i + 1).map(|f| f.start).unwrap_or(slots);
        if funcs[i].end > next {
            funcs[i].end = next;
        }
    }
    // A section with no function symbols is still one program.
    if funcs.is_empty() && slots > 0 {
        funcs.push(Func {
            name: s.name.clone(),
            start: 0,
            end: slots,
            global: true,
            first: slot_map.first().copied().flatten(),
        });
    }

    let relocs: Vec<(usize, Reloc)> = e
        .relocs
        .iter()
        .filter(|r| r.target_sec == s.idx)
        .map(|r| ((r.offset / 8) as usize, r.clone()))
        .collect();

    Prog {
        sec_idx: s.idx,
        name: s.name.clone(),
        slots,
        insns,
        slot_map,
        funcs,
        relocs,
        tail_err,
    }
}

pub fn programs(e: &Elf) -> Vec<Prog> {
    e.text_sections().into_iter().map(|s| build_one(e, s)).collect()
}
