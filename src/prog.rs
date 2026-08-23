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

/// Section name, whether it must match exactly, program type, type name,
/// expected attach type or -1 for none.
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
pub const SEC_TYPES: &[(&str, bool, u32, &str, i32)] = &[
    ("socket", true, 1, "SOCKET_FILTER", -1),
    ("sk_reuseport/migrate", true, 21, "SK_REUSEPORT", 40),
    ("sk_reuseport", true, 21, "SK_REUSEPORT", 39),
    ("kprobe", false, 2, "KPROBE", -1),
    ("kretprobe", false, 2, "KPROBE", -1),
    ("kprobe.multi", false, 2, "KPROBE", 42),
    ("kretprobe.multi", false, 2, "KPROBE", 42),
    ("kprobe.session", false, 2, "KPROBE", 56),
    ("uprobe", false, 2, "KPROBE", -1),
    ("uretprobe", false, 2, "KPROBE", -1),
    ("uprobe.s", false, 2, "KPROBE", -1),
    ("uretprobe.s", false, 2, "KPROBE", -1),
    ("uprobe.multi", false, 2, "KPROBE", 48),
    ("uretprobe.multi", false, 2, "KPROBE", 48),
    ("usdt", false, 2, "KPROBE", -1),
    ("usdt.s", false, 2, "KPROBE", -1),
    ("tracepoint", false, 5, "TRACEPOINT", -1),
    ("tp", false, 5, "TRACEPOINT", -1),
    ("raw_tracepoint", false, 17, "RAW_TRACEPOINT", -1),
    ("raw_tp", false, 17, "RAW_TRACEPOINT", -1),
    ("raw_tracepoint.w", false, 24, "RAW_TRACEPOINT_WRITABLE", -1),
    ("raw_tp.w", false, 24, "RAW_TRACEPOINT_WRITABLE", -1),
    ("xdp.frags/devmap", true, 6, "XDP", 33),
    ("xdp/devmap", true, 6, "XDP", 33),
    ("xdp.frags/cpumap", true, 6, "XDP", 35),
    ("xdp/cpumap", true, 6, "XDP", 35),
    ("xdp.frags", true, 6, "XDP", 37),
    ("xdp", true, 6, "XDP", 37),
    ("perf_event", true, 7, "PERF_EVENT", -1),
    ("lwt_in", true, 10, "LWT_IN", -1),
    ("lwt_out", true, 11, "LWT_OUT", -1),
    ("lwt_xmit", true, 12, "LWT_XMIT", -1),
    ("lwt_seg6local", true, 19, "LWT_SEG6LOCAL", -1),
    ("lirc_mode2", true, 20, "LIRC_MODE2", 16),
    ("cgroup_skb/ingress", true, 8, "CGROUP_SKB", 0),
    ("cgroup_skb/egress", true, 8, "CGROUP_SKB", 1),
    ("cgroup/skb", true, 8, "CGROUP_SKB", -1),
    ("cgroup/sock_create", true, 9, "CGROUP_SOCK", 2),
    ("cgroup/sock_release", true, 9, "CGROUP_SOCK", 34),
    ("cgroup/sock", true, 9, "CGROUP_SOCK", 2),
    ("cgroup/post_bind4", true, 9, "CGROUP_SOCK", 12),
    ("cgroup/post_bind6", true, 9, "CGROUP_SOCK", 13),
    ("cgroup/dev", true, 15, "CGROUP_DEVICE", 6),
    ("cgroup/sysctl", true, 23, "CGROUP_SYSCTL", 18),
    ("cgroup/getsockopt", true, 25, "CGROUP_SOCKOPT", 21),
    ("cgroup/setsockopt", true, 25, "CGROUP_SOCKOPT", 22),
    ("cgroup/bind4", true, 18, "CGROUP_SOCK_ADDR", 8),
    ("cgroup/bind6", true, 18, "CGROUP_SOCK_ADDR", 9),
    ("cgroup/connect4", true, 18, "CGROUP_SOCK_ADDR", 10),
    ("cgroup/connect6", true, 18, "CGROUP_SOCK_ADDR", 11),
    ("cgroup/connect_unix", true, 18, "CGROUP_SOCK_ADDR", 49),
    ("cgroup/sendmsg4", true, 18, "CGROUP_SOCK_ADDR", 14),
    ("cgroup/sendmsg6", true, 18, "CGROUP_SOCK_ADDR", 15),
    ("cgroup/recvmsg4", true, 18, "CGROUP_SOCK_ADDR", 19),
    ("cgroup/recvmsg6", true, 18, "CGROUP_SOCK_ADDR", 20),
    ("cgroup/getpeername4", true, 18, "CGROUP_SOCK_ADDR", 29),
    ("cgroup/getpeername6", true, 18, "CGROUP_SOCK_ADDR", 30),
    ("cgroup/getsockname4", true, 18, "CGROUP_SOCK_ADDR", 31),
    ("cgroup/getsockname6", true, 18, "CGROUP_SOCK_ADDR", 32),
    ("sockops", true, 13, "SOCK_OPS", 3),
    ("sk_skb/stream_parser", true, 14, "SK_SKB", 4),
    ("sk_skb/stream_verdict", true, 14, "SK_SKB", 5),
    ("sk_skb", true, 14, "SK_SKB", -1),
    ("sk_msg", true, 16, "SK_MSG", 7),
    ("classifier", true, 3, "SCHED_CLS", -1),
    ("tc/ingress", true, 3, "SCHED_CLS", 46),
    ("tc/egress", true, 3, "SCHED_CLS", 47),
    ("tc", true, 3, "SCHED_CLS", -1),
    ("tcx/ingress", true, 3, "SCHED_CLS", 46),
    ("tcx/egress", true, 3, "SCHED_CLS", 47),
    ("netkit/primary", true, 3, "SCHED_CLS", 54),
    ("netkit/peer", true, 3, "SCHED_CLS", 55),
    ("action", true, 4, "SCHED_ACT", -1),
    ("sk_lookup", true, 30, "SK_LOOKUP", 36),
    ("flow_dissector", true, 22, "FLOW_DISSECTOR", 17),
    ("syscall", true, 31, "SYSCALL", -1),
    ("netfilter", true, 32, "NETFILTER", 45),
    ("lsm", false, 29, "LSM", 27),
    ("lsm.s", false, 29, "LSM", 27),
    ("fentry", false, 26, "TRACING", 24),
    ("fexit", false, 26, "TRACING", 25),
    ("fmod_ret", false, 26, "TRACING", 26),
    ("fentry.s", false, 26, "TRACING", 24),
    ("fexit.s", false, 26, "TRACING", 25),
    ("fmod_ret.s", false, 26, "TRACING", 26),
    ("tp_btf", false, 26, "TRACING", 23),
    ("iter", false, 26, "TRACING", 28),
    ("iter.s", false, 26, "TRACING", 28),
    ("freplace", false, 28, "EXT", -1),
    ("struct_ops", false, 27, "STRUCT_OPS", -1),
    ("struct_ops.s", false, 27, "STRUCT_OPS", -1),
];



/// The program type a loader would give a section with this name.
///
/// Returns 0 UNSPEC for a name no row matches. That is not the same as
/// libbpf's behaviour, which refuses to open the object; bpfdis reads files
/// nothing will load, so it says what it knows and prints UNSPEC for the
/// rest.
pub fn prog_type(sec: &str) -> (u32, &'static str, i32) {
    for row in SEC_TYPES {
        let hit = sec == row.0
            || (!row.1
                && sec.len() > row.0.len()
                && sec.starts_with(row.0)
                && sec.as_bytes()[row.0.len()] == b'/');
        if hit {
            return (row.2, row.3, row.4);
        }
    }
    (0, "UNSPEC", -1)
}

/// Attach type names, indexed by number, from
/// `bpftool feature list_builtins attach_types`. Same provenance and same
/// check as HELPERS in cfg.rs.
pub const ATTACH_NAMES: &[&str] = &[
    "cgroup_inet_ingress", "cgroup_inet_egress", "cgroup_inet_sock_create",
    "cgroup_sock_ops", "sk_skb_stream_parser", "sk_skb_stream_verdict",
    "cgroup_device", "sk_msg_verdict", "cgroup_inet4_bind",
    "cgroup_inet6_bind", "cgroup_inet4_connect", "cgroup_inet6_connect",
    "cgroup_inet4_post_bind", "cgroup_inet6_post_bind", "cgroup_udp4_sendmsg",
    "cgroup_udp6_sendmsg", "lirc_mode2", "flow_dissector", "cgroup_sysctl",
    "cgroup_udp4_recvmsg", "cgroup_udp6_recvmsg", "cgroup_getsockopt",
    "cgroup_setsockopt", "trace_raw_tp", "trace_fentry", "trace_fexit",
    "modify_return", "lsm_mac", "trace_iter", "cgroup_inet4_getpeername",
    "cgroup_inet6_getpeername", "cgroup_inet4_getsockname",
    "cgroup_inet6_getsockname", "xdp_devmap", "cgroup_inet_sock_release",
    "xdp_cpumap", "sk_lookup", "xdp", "sk_skb_verdict", "sk_reuseport_select",
    "sk_reuseport_select_or_migrate", "perf_event", "trace_kprobe_multi",
    "lsm_cgroup", "struct_ops", "netfilter", "tcx_ingress", "tcx_egress",
    "trace_uprobe_multi", "cgroup_unix_connect", "cgroup_unix_sendmsg",
    "cgroup_unix_recvmsg", "cgroup_unix_getpeername",
    "cgroup_unix_getsockname", "netkit_primary", "netkit_peer",
    "trace_kprobe_session",
];

pub fn attach_name(a: i32) -> &'static str {
    if a < 0 {
        return "-";
    }
    ATTACH_NAMES.get(a as usize).copied().unwrap_or("?")
}

pub fn programs(e: &Elf) -> Vec<Prog> {
    e.text_sections().into_iter().map(|s| build_one(e, s)).collect()
}
