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

/// Section name, whether it must match exactly, program type, type name.
///
/// A loader picks a program's type from the name of the section it is in.
/// The numbers are the `bpf_prog_type` enumeration from the kernel's
/// published uapi header, which is not installed for any target here; the
/// names are libbpf's, and libbpf is the oracle for every row.
/// t/corpus/sections.c holds one program per row and the suite fails if a
/// row is not the one prog_type picks for one of them, because a row
/// nothing exercises has nothing checking it.
///
/// The second column is the part that cannot be guessed. libbpf matches
/// some names exactly and lets others carry a suffix, and which is which
/// does not follow from the name: `kprobe/do_sys_open` is a KPROBE but
/// `socket/ingress` is nothing at all, and `socket` alone is a socket
/// filter. It was measured by compiling a program into both forms of every
/// name and asking libbpf, not read off a pattern.
///
/// No two rows can match the same section name, so the first hit is the
/// answer and there is no tie to break. That is a property of the table
/// rather than of the lookup, so the harness asserts it over every section
/// in the corpus rather than this comment claiming it. A tiebreak was
/// written here first, and the mutation that removed it survived the whole
/// suite, which is how the dead branch was found.
pub const SEC_TYPES: &[(&str, bool, u32, &str)] = &[
    ("socket", true, 1, "SOCKET_FILTER"),
    ("sk_reuseport/migrate", true, 21, "SK_REUSEPORT"),
    ("sk_reuseport", true, 21, "SK_REUSEPORT"),
    ("kprobe", false, 2, "KPROBE"),
    ("kretprobe", false, 2, "KPROBE"),
    ("kprobe.multi", false, 2, "KPROBE"),
    ("kretprobe.multi", false, 2, "KPROBE"),
    ("kprobe.session", false, 2, "KPROBE"),
    ("uprobe", false, 2, "KPROBE"),
    ("uretprobe", false, 2, "KPROBE"),
    ("uprobe.s", false, 2, "KPROBE"),
    ("uretprobe.s", false, 2, "KPROBE"),
    ("uprobe.multi", false, 2, "KPROBE"),
    ("uretprobe.multi", false, 2, "KPROBE"),
    ("usdt", false, 2, "KPROBE"),
    ("usdt.s", false, 2, "KPROBE"),
    ("tracepoint", false, 5, "TRACEPOINT"),
    ("tp", false, 5, "TRACEPOINT"),
    ("raw_tracepoint", false, 17, "RAW_TRACEPOINT"),
    ("raw_tp", false, 17, "RAW_TRACEPOINT"),
    ("raw_tracepoint.w", false, 24, "RAW_TRACEPOINT_WRITABLE"),
    ("raw_tp.w", false, 24, "RAW_TRACEPOINT_WRITABLE"),
    ("xdp.frags/devmap", true, 6, "XDP"),
    ("xdp/devmap", true, 6, "XDP"),
    ("xdp.frags/cpumap", true, 6, "XDP"),
    ("xdp/cpumap", true, 6, "XDP"),
    ("xdp.frags", true, 6, "XDP"),
    ("xdp", true, 6, "XDP"),
    ("perf_event", true, 7, "PERF_EVENT"),
    ("lwt_in", true, 10, "LWT_IN"),
    ("lwt_out", true, 11, "LWT_OUT"),
    ("lwt_xmit", true, 12, "LWT_XMIT"),
    ("lwt_seg6local", true, 19, "LWT_SEG6LOCAL"),
    ("lirc_mode2", true, 20, "LIRC_MODE2"),
    ("cgroup_skb/ingress", true, 8, "CGROUP_SKB"),
    ("cgroup_skb/egress", true, 8, "CGROUP_SKB"),
    ("cgroup/skb", true, 8, "CGROUP_SKB"),
    ("cgroup/sock_create", true, 9, "CGROUP_SOCK"),
    ("cgroup/sock_release", true, 9, "CGROUP_SOCK"),
    ("cgroup/sock", true, 9, "CGROUP_SOCK"),
    ("cgroup/post_bind4", true, 9, "CGROUP_SOCK"),
    ("cgroup/post_bind6", true, 9, "CGROUP_SOCK"),
    ("cgroup/dev", true, 15, "CGROUP_DEVICE"),
    ("cgroup/sysctl", true, 23, "CGROUP_SYSCTL"),
    ("cgroup/getsockopt", true, 25, "CGROUP_SOCKOPT"),
    ("cgroup/setsockopt", true, 25, "CGROUP_SOCKOPT"),
    ("cgroup/bind4", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/bind6", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/connect4", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/connect6", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/connect_unix", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/sendmsg4", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/sendmsg6", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/recvmsg4", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/recvmsg6", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/getpeername4", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/getpeername6", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/getsockname4", true, 18, "CGROUP_SOCK_ADDR"),
    ("cgroup/getsockname6", true, 18, "CGROUP_SOCK_ADDR"),
    ("sockops", true, 13, "SOCK_OPS"),
    ("sk_skb/stream_parser", true, 14, "SK_SKB"),
    ("sk_skb/stream_verdict", true, 14, "SK_SKB"),
    ("sk_skb", true, 14, "SK_SKB"),
    ("sk_msg", true, 16, "SK_MSG"),
    ("classifier", true, 3, "SCHED_CLS"),
    ("tc/ingress", true, 3, "SCHED_CLS"),
    ("tc/egress", true, 3, "SCHED_CLS"),
    ("tc", true, 3, "SCHED_CLS"),
    ("tcx/ingress", true, 3, "SCHED_CLS"),
    ("tcx/egress", true, 3, "SCHED_CLS"),
    ("netkit/primary", true, 3, "SCHED_CLS"),
    ("netkit/peer", true, 3, "SCHED_CLS"),
    ("action", true, 4, "SCHED_ACT"),
    ("sk_lookup", true, 30, "SK_LOOKUP"),
    ("flow_dissector", true, 22, "FLOW_DISSECTOR"),
    ("syscall", true, 31, "SYSCALL"),
    ("netfilter", true, 32, "NETFILTER"),
    ("lsm", false, 29, "LSM"),
    ("lsm.s", false, 29, "LSM"),
    ("fentry", false, 26, "TRACING"),
    ("fexit", false, 26, "TRACING"),
    ("fmod_ret", false, 26, "TRACING"),
    ("fentry.s", false, 26, "TRACING"),
    ("fexit.s", false, 26, "TRACING"),
    ("fmod_ret.s", false, 26, "TRACING"),
    ("tp_btf", false, 26, "TRACING"),
    ("iter", false, 26, "TRACING"),
    ("iter.s", false, 26, "TRACING"),
    ("freplace", false, 28, "EXT"),
    ("struct_ops", false, 27, "STRUCT_OPS"),
    ("struct_ops.s", false, 27, "STRUCT_OPS"),
];


/// The program type a loader would give a section with this name.
///
/// Returns 0 UNSPEC for a name no row matches. That is not the same as
/// libbpf's behaviour, which refuses to open the object; bpfdis reads files
/// nothing will load, so it says what it knows and prints UNSPEC for the
/// rest.
pub fn prog_type(sec: &str) -> (u32, &'static str) {
    for row in SEC_TYPES {
        let hit = sec == row.0
            || (!row.1
                && sec.len() > row.0.len()
                && sec.starts_with(row.0)
                && sec.as_bytes()[row.0.len()] == b'/');
        if hit {
            return (row.2, row.3);
        }
    }
    (0, "UNSPEC")
}

pub fn programs(e: &Elf) -> Vec<Prog> {
    e.text_sections().into_iter().map(|s| build_one(e, s)).collect()
}
