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
    /// A subprogram call whose target is not the first instruction of a
    /// function in the same section. The verifier rejects these: a
    /// BPF_PSEUDO_CALL may only enter a subprogram at its entry.
    CallTargetBad { slot: usize, target: i64 },
    /// A cycle in the subprogram call graph. The verifier has no stack to
    /// unwind and rejects recursion outright, direct or mutual.
    Recursion { from: String, to: String },
    /// More nested subprogram calls than the verifier's frame limit.
    CallTooDeep { depth: usize },
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
            | Problem::UninitRead { .. }
            | Problem::CallTargetBad { .. }
            | Problem::Recursion { .. }
            | Problem::CallTooDeep { .. } => "reject",
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
            Problem::Recursion { from, to } => {
                if from == to {
                    format!("the subprogram call graph has a cycle: {} calls itself", from)
                } else {
                    format!(
                        "the subprogram call graph has a cycle: {} calls {}, which \
                         reaches {} again",
                        from, to, from
                    )
                }
            }
            Problem::CallTooDeep { depth } => format!(
                "subprogram calls nest {} deep; the verifier allows {}",
                depth, MAX_CALL_DEPTH
            ),
            Problem::CallTargetBad { slot, target } => format!(
                "the subprogram call at slot {} targets slot {}, which is not the \
                 first instruction of a function in this section",
                slot, target
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
/// Helper function names, indexed by the number a `call` carries.
///
/// Transcribed from `bpftool feature list_builtins helpers`, which prints
/// the list bpftool was built with and needs no privilege at all. The
/// README used to say no such list existed on this machine, because
/// `linux/bpf.h` is not installed for any target here; it was wrong.
///
/// The suite compares this array against that command index by index on
/// every run, so the value of having it written down is that a bpftool
/// built against a newer kernel turns the comparison red instead of this
/// quietly naming the wrong function. Entry 0 is `bpf_unspec` and is not
/// callable.
pub const HELPERS: &[&str] = &[
    "bpf_unspec", "bpf_map_lookup_elem", "bpf_map_update_elem",
    "bpf_map_delete_elem", "bpf_probe_read", "bpf_ktime_get_ns",
    "bpf_trace_printk", "bpf_get_prandom_u32", "bpf_get_smp_processor_id",
    "bpf_skb_store_bytes", "bpf_l3_csum_replace", "bpf_l4_csum_replace",
    "bpf_tail_call", "bpf_clone_redirect", "bpf_get_current_pid_tgid",
    "bpf_get_current_uid_gid", "bpf_get_current_comm",
    "bpf_get_cgroup_classid", "bpf_skb_vlan_push", "bpf_skb_vlan_pop",
    "bpf_skb_get_tunnel_key", "bpf_skb_set_tunnel_key", "bpf_perf_event_read",
    "bpf_redirect", "bpf_get_route_realm", "bpf_perf_event_output",
    "bpf_skb_load_bytes", "bpf_get_stackid", "bpf_csum_diff",
    "bpf_skb_get_tunnel_opt", "bpf_skb_set_tunnel_opt",
    "bpf_skb_change_proto", "bpf_skb_change_type", "bpf_skb_under_cgroup",
    "bpf_get_hash_recalc", "bpf_get_current_task", "bpf_probe_write_user",
    "bpf_current_task_under_cgroup", "bpf_skb_change_tail",
    "bpf_skb_pull_data", "bpf_csum_update", "bpf_set_hash_invalid",
    "bpf_get_numa_node_id", "bpf_skb_change_head", "bpf_xdp_adjust_head",
    "bpf_probe_read_str", "bpf_get_socket_cookie", "bpf_get_socket_uid",
    "bpf_set_hash", "bpf_setsockopt", "bpf_skb_adjust_room",
    "bpf_redirect_map", "bpf_sk_redirect_map", "bpf_sock_map_update",
    "bpf_xdp_adjust_meta", "bpf_perf_event_read_value",
    "bpf_perf_prog_read_value", "bpf_getsockopt", "bpf_override_return",
    "bpf_sock_ops_cb_flags_set", "bpf_msg_redirect_map",
    "bpf_msg_apply_bytes", "bpf_msg_cork_bytes", "bpf_msg_pull_data",
    "bpf_bind", "bpf_xdp_adjust_tail", "bpf_skb_get_xfrm_state",
    "bpf_get_stack", "bpf_skb_load_bytes_relative", "bpf_fib_lookup",
    "bpf_sock_hash_update", "bpf_msg_redirect_hash", "bpf_sk_redirect_hash",
    "bpf_lwt_push_encap", "bpf_lwt_seg6_store_bytes",
    "bpf_lwt_seg6_adjust_srh", "bpf_lwt_seg6_action", "bpf_rc_repeat",
    "bpf_rc_keydown", "bpf_skb_cgroup_id", "bpf_get_current_cgroup_id",
    "bpf_get_local_storage", "bpf_sk_select_reuseport",
    "bpf_skb_ancestor_cgroup_id", "bpf_sk_lookup_tcp", "bpf_sk_lookup_udp",
    "bpf_sk_release", "bpf_map_push_elem", "bpf_map_pop_elem",
    "bpf_map_peek_elem", "bpf_msg_push_data", "bpf_msg_pop_data",
    "bpf_rc_pointer_rel", "bpf_spin_lock", "bpf_spin_unlock",
    "bpf_sk_fullsock", "bpf_tcp_sock", "bpf_skb_ecn_set_ce",
    "bpf_get_listener_sock", "bpf_skc_lookup_tcp", "bpf_tcp_check_syncookie",
    "bpf_sysctl_get_name", "bpf_sysctl_get_current_value",
    "bpf_sysctl_get_new_value", "bpf_sysctl_set_new_value", "bpf_strtol",
    "bpf_strtoul", "bpf_sk_storage_get", "bpf_sk_storage_delete",
    "bpf_send_signal", "bpf_tcp_gen_syncookie", "bpf_skb_output",
    "bpf_probe_read_user", "bpf_probe_read_kernel", "bpf_probe_read_user_str",
    "bpf_probe_read_kernel_str", "bpf_tcp_send_ack", "bpf_send_signal_thread",
    "bpf_jiffies64", "bpf_read_branch_records", "bpf_get_ns_current_pid_tgid",
    "bpf_xdp_output", "bpf_get_netns_cookie",
    "bpf_get_current_ancestor_cgroup_id", "bpf_sk_assign",
    "bpf_ktime_get_boot_ns", "bpf_seq_printf", "bpf_seq_write",
    "bpf_sk_cgroup_id", "bpf_sk_ancestor_cgroup_id", "bpf_ringbuf_output",
    "bpf_ringbuf_reserve", "bpf_ringbuf_submit", "bpf_ringbuf_discard",
    "bpf_ringbuf_query", "bpf_csum_level", "bpf_skc_to_tcp6_sock",
    "bpf_skc_to_tcp_sock", "bpf_skc_to_tcp_timewait_sock",
    "bpf_skc_to_tcp_request_sock", "bpf_skc_to_udp6_sock",
    "bpf_get_task_stack", "bpf_load_hdr_opt", "bpf_store_hdr_opt",
    "bpf_reserve_hdr_opt", "bpf_inode_storage_get",
    "bpf_inode_storage_delete", "bpf_d_path", "bpf_copy_from_user",
    "bpf_snprintf_btf", "bpf_seq_printf_btf", "bpf_skb_cgroup_classid",
    "bpf_redirect_neigh", "bpf_per_cpu_ptr", "bpf_this_cpu_ptr",
    "bpf_redirect_peer", "bpf_task_storage_get", "bpf_task_storage_delete",
    "bpf_get_current_task_btf", "bpf_bprm_opts_set",
    "bpf_ktime_get_coarse_ns", "bpf_ima_inode_hash", "bpf_sock_from_file",
    "bpf_check_mtu", "bpf_for_each_map_elem", "bpf_snprintf", "bpf_sys_bpf",
    "bpf_btf_find_by_name_kind", "bpf_sys_close", "bpf_timer_init",
    "bpf_timer_set_callback", "bpf_timer_start", "bpf_timer_cancel",
    "bpf_get_func_ip", "bpf_get_attach_cookie", "bpf_task_pt_regs",
    "bpf_get_branch_snapshot", "bpf_trace_vprintk", "bpf_skc_to_unix_sock",
    "bpf_kallsyms_lookup_name", "bpf_find_vma", "bpf_loop", "bpf_strncmp",
    "bpf_get_func_arg", "bpf_get_func_ret", "bpf_get_func_arg_cnt",
    "bpf_get_retval", "bpf_set_retval", "bpf_xdp_get_buff_len",
    "bpf_xdp_load_bytes", "bpf_xdp_store_bytes", "bpf_copy_from_user_task",
    "bpf_skb_set_tstamp", "bpf_ima_file_hash", "bpf_kptr_xchg",
    "bpf_map_lookup_percpu_elem", "bpf_skc_to_mptcp_sock",
    "bpf_dynptr_from_mem", "bpf_ringbuf_reserve_dynptr",
    "bpf_ringbuf_submit_dynptr", "bpf_ringbuf_discard_dynptr",
    "bpf_dynptr_read", "bpf_dynptr_write", "bpf_dynptr_data",
    "bpf_tcp_raw_gen_syncookie_ipv4", "bpf_tcp_raw_gen_syncookie_ipv6",
    "bpf_tcp_raw_check_syncookie_ipv4", "bpf_tcp_raw_check_syncookie_ipv6",
    "bpf_ktime_get_tai_ns", "bpf_user_ringbuf_drain", "bpf_cgrp_storage_get",
    "bpf_cgrp_storage_delete",
];

pub fn helper_name(n: i32) -> Option<&'static str> {
    if n <= 0 {
        return None;
    }
    HELPERS.get(n as usize).copied()
}

/// The verifier's limit on nested subprogram frames.
///
/// Written down from the kernel's MAX_CALL_FRAMES, which is not installed
/// here and so has no oracle; the verifier that would settle it is out of
/// reach on this machine. The README says so.
pub const MAX_CALL_DEPTH: usize = 8;

/// The subprogram call graph of a whole object, keyed by (program, function).
///
/// A call inside a section resolves by offset. A call to another section
/// carries a relocation, and the target is the symbol's own slot plus the
/// offset left in `imm`: llvm writes `imm = target_slot_in_section - 1` so
/// that the linker's `(S + A - P) / 8 - 1` comes out right, which means an
/// unlinked object already says where the call goes. That was measured
/// against t/corpus/calls.c, where `caller` calls `mix` at .text slot 0
/// with `imm` -1 and `fold` at .text slot 6 with `imm` 5.
///
/// Returns the depth of each function and the edges that close a cycle.
type FnKey = (usize, usize);

pub fn call_graph(
    e: &crate::elf::Elf,
    progs: &[Prog],
    all: &[Vec<Cfg>],
) -> (Vec<(FnKey, usize)>, Vec<(FnKey, FnKey)>) {
    // Where every function starts, so a target slot can be turned into a
    // function. A call landing anywhere else is already reported by
    // `collect` and contributes no edge.
    let mut entry: Vec<((usize, usize), FnKey)> = Vec::new();
    for (pi, p) in progs.iter().enumerate() {
        for (fi, f) in p.funcs.iter().enumerate() {
            entry.push(((p.sec_idx, f.start), (pi, fi)));
        }
    }
    let find = |sec: usize, slot: usize| -> Option<FnKey> {
        entry.iter().find(|(k, _)| *k == (sec, slot)).map(|(_, v)| *v)
    };

    let mut keys: Vec<FnKey> = Vec::new();
    let mut edges: Vec<Vec<usize>> = Vec::new();
    for (pi, p) in progs.iter().enumerate() {
        for fi in 0..p.funcs.len() {
            keys.push((pi, fi));
            edges.push(Vec::new());
        }
    }
    let index_of = |k: FnKey| keys.iter().position(|&x| x == k);

    for (pi, p) in progs.iter().enumerate() {
        for (fi, c) in all[pi].iter().enumerate() {
            let me = match index_of((pi, fi)) {
                Some(i) => i,
                None => continue,
            };
            for (slot, t) in &c.calls {
                let target = match p.reloc_at(*slot) {
                    None => find(p.sec_idx, *t as usize),
                    Some(r) => {
                        // `imm` back out of the target the decoder computed.
                        let imm = *t - (*slot as i64) - 1;
                        e.syms
                            .iter()
                            .find(|y| y.idx as u32 == r.sym)
                            .and_then(|y| {
                                let base = (y.value / 8) as i64;
                                let slot = base + imm + 1;
                                if slot < 0 {
                                    None
                                } else {
                                    find(y.shndx as usize, slot as usize)
                                }
                            })
                    }
                };
                if let Some(k) = target.and_then(index_of) {
                    if !edges[me].contains(&k) {
                        edges[me].push(k);
                    }
                }
            }
        }
    }

    let n = keys.len();
    let mut depth = vec![0usize; n];
    let mut colour = vec![0u8; n];
    let mut cycles: Vec<(usize, usize)> = Vec::new();
    fn walk(
        i: usize,
        edges: &[Vec<usize>],
        colour: &mut Vec<u8>,
        depth: &mut Vec<usize>,
        cycles: &mut Vec<(usize, usize)>,
    ) -> usize {
        if colour[i] == 2 {
            return depth[i];
        }
        if colour[i] == 1 {
            return 0;
        }
        colour[i] = 1;
        let mut best = 0;
        for &j in &edges[i] {
            if colour[j] == 1 {
                if !cycles.contains(&(i, j)) {
                    cycles.push((i, j));
                }
                continue;
            }
            best = best.max(walk(j, edges, colour, depth, cycles));
        }
        colour[i] = 2;
        depth[i] = best + 1;
        depth[i]
    }
    for i in 0..n {
        walk(i, &edges, &mut colour, &mut depth, &mut cycles);
    }
    (
        keys.iter().copied().zip(depth).collect(),
        cycles.into_iter().map(|(a, b)| (keys[a], keys[b])).collect(),
    )
}

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
    // Annotated rather than inferred so that deleting the one push below
    // still compiles. t/mutate.py does exactly that, and a mutant the
    // compiler rejects says nothing about whether the suite would have
    // caught it.
    let mut found: Vec<(usize, usize)> = Vec::new();
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
                let t = (ins.idx + ins.slots) as i64 + ins.imm as i64;
                cfg.calls.push((ins.idx, t));
                // A call carrying a relocation has a placeholder in `imm`
                // and its real target is the symbol, so the offset says
                // nothing and checking it would reject every cross-section
                // call clang emits. Only the already-resolved ones are
                // checked here.
                if p.reloc_at(ins.idx).is_none()
                    && !p.funcs.iter().any(|f| f.start as i64 == t)
                {
                    cfg.problems.push(Problem::CallTargetBad {
                        slot: ins.idx,
                        target: t,
                    });
                }
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
    /// The frame offset a register holds, if any.
    ///
    /// Bounds-checked rather than indexed, because the register number
    /// comes out of a four-bit field in the file and the kernel has eleven
    /// registers. A corrupted object naming r15 reached three direct
    /// indexes here and aborted the program; the robustness sweep found all
    /// three on its first run.
    fn get(&self, r: u8) -> Option<i64> {
        self.fp.get(r as usize).copied().flatten()
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
    if let Some(k) = st.get(base) {
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
                        st.get(ins.src)
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
                    let v = st.get(ins.dst).map(|k| k + ins.imm as i64);
                    materialise(v, deepest);
                    st.set(ins.dst, v);
                }
                AluOp::Sub if !*reg && *wide => {
                    need(st, slot, ins.dst, ps);
                    let v = st.get(ins.dst).map(|k| k - ins.imm as i64);
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
