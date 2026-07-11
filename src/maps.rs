//! Map definitions, in both forms an object can carry them.
//!
//! The legacy form is a `maps` section holding five 32-bit words per map,
//! with a symbol naming each. libbpf 1.0 removed support for it, so an
//! object using it cannot be opened by any current loader -- and therefore
//! has no oracle here. bpfdis still reads it, because the objects exist.
//!
//! The modern form is a BTF struct in `.maps` whose members are pointers to
//! arrays, where the array's element count IS the value:
//!
//! ```c
//!     struct {
//!         int (*type)[BPF_MAP_TYPE_HASH];
//!         int (*max_entries)[4096];
//!         u32 *key;
//!         u64 *value;
//!     } events SEC(".maps");
//! ```
//!
//! `type` is 1 because the array has one element, `max_entries` is 4096 for
//! the same reason, and the key and value sizes are the sizes of the types
//! the pointers point at. None of that is readable without BTF.

use crate::btf::{Btf, KIND_ARRAY, KIND_DATASEC, KIND_PTR, KIND_STRUCT, KIND_VAR};
use crate::elf::{Cur, Elf, SHF_ALLOC, STT_OBJECT};

/// `BPF_F_RDONLY_PROG`: the program may read the map but not write it.
const F_RDONLY_PROG: u32 = 1 << 7;
/// `BPF_F_MMAPABLE`: userspace gets at the contents with `mmap`.
const F_MMAPABLE: u32 = 1 << 10;

#[derive(Clone, Default)]
pub struct MapDef {
    pub name: String,
    pub source: &'static str,
    pub mtype: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
    pub notes: Vec<String>,
}

pub fn map_type_name(t: u32) -> &'static str {
    match t {
        0 => "UNSPEC",
        1 => "HASH",
        2 => "ARRAY",
        3 => "PROG_ARRAY",
        4 => "PERF_EVENT_ARRAY",
        5 => "PERCPU_HASH",
        6 => "PERCPU_ARRAY",
        7 => "STACK_TRACE",
        8 => "CGROUP_ARRAY",
        9 => "LRU_HASH",
        10 => "LRU_PERCPU_HASH",
        11 => "LPM_TRIE",
        12 => "ARRAY_OF_MAPS",
        13 => "HASH_OF_MAPS",
        14 => "DEVMAP",
        15 => "SOCKMAP",
        16 => "CPUMAP",
        17 => "XSKMAP",
        18 => "SOCKHASH",
        19 => "CGROUP_STORAGE",
        20 => "REUSEPORT_SOCKARRAY",
        21 => "PERCPU_CGROUP_STORAGE",
        22 => "QUEUE",
        23 => "STACK",
        24 => "SK_STORAGE",
        25 => "DEVMAP_HASH",
        26 => "STRUCT_OPS",
        27 => "RINGBUF",
        28 => "INODE_STORAGE",
        29 => "TASK_STORAGE",
        30 => "BLOOM_FILTER",
        31 => "USER_RINGBUF",
        32 => "CGRP_STORAGE",
        33 => "ARENA",
        _ => "UNKNOWN",
    }
}

/// The legacy `struct bpf_map_def`: five 32-bit words, in this order.
fn legacy(e: &Elf, out: &mut Vec<MapDef>) {
    let sec = match e.section_by_name("maps") {
        Some(s) => s,
        None => return,
    };
    let data = sec.data(&e.file);
    let mut syms: Vec<_> = e
        .syms
        .iter()
        .filter(|y| y.shndx as usize == sec.idx && y.stype() == STT_OBJECT)
        .collect();
    syms.sort_by_key(|y| y.value);
    for y in syms {
        let mut m = MapDef {
            name: y.name.clone(),
            source: "legacy",
            ..Default::default()
        };
        // Exactly as many words as the section actually held, not five.
        //
        // METHOD's oversized-buffer rule in its Rust form. A `[0u32; 5]`
        // filled from a cursor that runs out leaves zeros behind, and those
        // zeros then travel into `key_size` and `max_entries` as though
        // they had been read. Nothing crashes, nothing is uninitialised by
        // Rust's rules, and the output is a map record made half of file
        // and half of padding. Sizing the buffer to the data means the
        // missing fields are missing, and the note below says how many.
        let mut c = Cur::at(data, y.value as usize);
        let mut vals: Vec<u32> = Vec::new();
        while vals.len() < 5 {
            match c.u32() {
                Ok(x) => vals.push(x),
                Err(_) => break,
            }
        }
        if vals.len() < 5 {
            m.notes.push(format!(
                "symbol at {:#x} has only {} of the 5 words of a struct \
                 bpf_map_def behind it; the rest are reported as zero",
                y.value,
                vals.len()
            ));
        }
        let at = |i: usize| vals.get(i).copied().unwrap_or(0);
        m.mtype = at(0);
        m.key_size = at(1);
        m.value_size = at(2);
        m.max_entries = at(3);
        m.flags = at(4);
        if y.size != 0 && y.size != 20 {
            m.notes.push(format!(
                "symbol size is {}, not the 20 bytes of a struct bpf_map_def",
                y.size
            ));
        }
        out.push(m);
    }
}

/// The BTF form: a DATASEC named `.maps`, one VAR per map, each a STRUCT
/// whose members encode the attributes.
fn btf_maps(b: &Btf, out: &mut Vec<MapDef>) {
    let ds = match b
        .types
        .iter()
        .find(|t| t.kind == KIND_DATASEC && t.name == ".maps")
    {
        Some(t) => t,
        None => return,
    };
    for si in &ds.secinfo {
        let var = match b.by_id(si.type_id) {
            Some(v) if v.kind == KIND_VAR => v,
            _ => continue,
        };
        let st = match b.strip(var.size_or_type) {
            Some(s) if s.kind == KIND_STRUCT => s,
            _ => {
                out.push(MapDef {
                    name: var.name.clone(),
                    source: "btf",
                    notes: vec!["the variable's type is not a struct".into()],
                    ..Default::default()
                });
                continue;
            }
        };
        let mut m = MapDef {
            name: var.name.clone(),
            source: "btf",
            ..Default::default()
        };
        for mem in &st.members {
            // Every attribute but `key` and `value` is a pointer to an array
            // whose length carries the number.
            let inner = b.strip(mem.type_id);
            let arr_len = inner
                .filter(|t| t.kind == KIND_PTR)
                .and_then(|t| b.strip(t.size_or_type))
                .filter(|t| t.kind == KIND_ARRAY)
                .map(|t| t.array_nelems);
            let pointee_size = inner
                .filter(|t| t.kind == KIND_PTR)
                .and_then(|t| b.size_of(t.size_or_type));
            match mem.name.as_str() {
                "type" => match arr_len {
                    Some(v) => m.mtype = v,
                    None => m.notes.push("type is not a pointer to an array".into()),
                },
                "max_entries" => match arr_len {
                    Some(v) => m.max_entries = v,
                    None => m
                        .notes
                        .push("max_entries is not a pointer to an array".into()),
                },
                "map_flags" => match arr_len {
                    Some(v) => m.flags = v,
                    None => m.notes.push("map_flags is not a pointer to an array".into()),
                },
                "key_size" => {
                    if let Some(v) = arr_len {
                        m.key_size = v;
                    }
                }
                "value_size" => {
                    if let Some(v) = arr_len {
                        m.value_size = v;
                    }
                }
                "key" => match pointee_size {
                    Some(v) => m.key_size = v as u32,
                    None => m.notes.push("key type has no size".into()),
                },
                "value" => match pointee_size {
                    Some(v) => m.value_size = v as u32,
                    None => m.notes.push("value type has no size".into()),
                },
                // `values` is an array of pointers, used for maps of maps and
                // program arrays; its length is the entry count.
                "values" => {
                    // A `values` member means the entries are file
                    // descriptors: an inner map for a map of maps, a program
                    // for a program array. libbpf gives those a value size
                    // of four whatever the declared element type is, since
                    // what the kernel stores is an fd.
                    if m.value_size == 0 {
                        m.value_size = 4;
                    }
                    if let Some(t) = inner.and_then(|t| b.strip(t.size_or_type)) {
                        if t.kind == KIND_ARRAY && m.max_entries == 0 {
                            m.max_entries = t.array_nelems;
                        }
                    }
                }
                other => m.notes.push(format!("member {} not interpreted", other)),
            }
        }
        out.push(m);
    }
}

/// The maps a loader creates for the object's own data sections.
///
/// These are not written down anywhere in the object: `.data`, `.rodata` and
/// `.bss`, and any section with one of those as a prefix, each become a
/// single-entry array map holding the whole section, because that is how a
/// BPF program reaches a global variable. The attributes below were measured
/// against libbpf rather than reasoned about, including the two flag rules:
/// read-only for `.rodata*`, and mmapable only when the object's BTF has a
/// DATASEC for the section. A string-literal section such as
/// `.rodata.str1.1` has no DATASEC and is not mmapable, which is the case
/// that showed the rule was about BTF and not about the section name.
///
/// The NAME libbpf gives these is not reproduced. It builds one from the
/// path the object was opened from, truncated to fit a 16-byte field, so
/// `btfmap.v3.O2.o` yields `btfmap.data`. That is a fact about the file
/// name, not about the object, and bpfdis prints the section name instead.
fn section_maps(e: &Elf, btf: Option<&Btf>, out: &mut Vec<MapDef>) {
    for s in &e.sections {
        if s.flags & SHF_ALLOC == 0 || s.size == 0 {
            continue;
        }
        let n = s.name.as_str();
        let rodata = n == ".rodata" || n.starts_with(".rodata.");
        let is_data = n == ".data" || n.starts_with(".data.");
        let is_bss = n == ".bss" || n.starts_with(".bss.");
        if !rodata && !is_data && !is_bss {
            continue;
        }
        let has_datasec = btf
            .map(|b| {
                b.types
                    .iter()
                    .any(|t| t.kind == KIND_DATASEC && t.name == n)
            })
            .unwrap_or(false);
        let mut flags = 0;
        if rodata {
            flags |= F_RDONLY_PROG;
        }
        if has_datasec {
            flags |= F_MMAPABLE;
        }
        out.push(MapDef {
            name: s.name.clone(),
            source: "section",
            mtype: 2,
            key_size: 4,
            value_size: s.size as u32,
            max_entries: 1,
            flags,
            notes: Vec::new(),
        });
    }
}

pub fn maps(e: &Elf) -> Vec<MapDef> {
    let mut out = Vec::new();
    legacy(e, &mut out);
    let btf = e
        .section_by_name(".BTF")
        .and_then(|s| Btf::parse(s.data(&e.file)).ok());
    if let Some(b) = &btf {
        btf_maps(b, &mut out);
    }
    section_maps(e, btf.as_ref(), &mut out);
    out
}
