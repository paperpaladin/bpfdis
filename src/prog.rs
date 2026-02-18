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
    // Exactly `slots` entries, not `slots + 1`.
    //
    // METHOD's oversized-buffer rule has a Rust form and this was its one
    // instance in the tree: a Vec one longer than the data it describes,
    // indexed by a length that comes from the file. Rust bounds-checks
    // every index, so the usual consequence of an off-by-one is a panic --
    // but only if the buffer ends where the data ends. One spare element
    // turns an index at `slots` into a quiet `None`, which every caller
    // here reads as "that slot is the tail of a 16-byte load", and a jump
    // one past the end of the section becomes a jump into a wide load.
    // Wrong answer, no crash, nothing to see. `make overread` plants that
    // read and requires it to abort.
    let mut slot_map = vec![None; slots];
    for (i, ins) in insns.iter().enumerate() {
        if ins.idx < slot_map.len() {
            slot_map[ins.idx] = Some(i);
        }
    }

    #[cfg(bpfdis_plant_overread)]
    {
        // One element past the last slot. With `slot_map` sized to `slots`
        // this is an out-of-bounds index and aborts; with one spare element
        // it returns None and the program carries on with a wrong answer.
        eprintln!("planted over-read: {:?}", slot_map[slots]);
    }

    let mut funcs: Vec<Func> = e
        .syms
        .iter()
        .filter(|y| y.stype() == STT_FUNC && y.shndx as usize == s.idx)
        .map(|y| {
            // A symbol value or size out of range is a corrupted object,
            // not an impossible one, and `end < start` underflows wherever
            // a caller computes a length. Both ends are clamped here, in
            // the one place that builds a Func, rather than in each of the
            // five places that subtract them.
            let start = ((y.value / 8) as usize).min(slots);
            let end = if y.size > 0 {
                start.saturating_add((y.size / 8) as usize)
            } else {
                slots
            };
            Func {
                name: y.name.clone(),
                start,
                end: end.clamp(start, slots),
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
            funcs[i].end = next.max(funcs[i].start);
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
