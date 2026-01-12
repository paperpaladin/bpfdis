//! The `.BTF` section: BPF Type Format.
//!
//! BTF is what makes a modern BPF object readable. The `.maps` section holds
//! no map definition at all any more; it holds a BTF struct whose members are
//! pointers to arrays, and the numbers are in the array lengths. Without a
//! BTF decoder a current object's maps cannot be described.
//!
//! The text produced here is `bpftool btf dump file`'s own format, so the two
//! can be compared line for line. bpftool is libbpf, which is a third
//! codebase after binutils and LLVM.

use crate::elf::{Cur, R};
use std::fmt::Write as _;

pub const KIND_INT: u32 = 1;
pub const KIND_PTR: u32 = 2;
pub const KIND_ARRAY: u32 = 3;
pub const KIND_STRUCT: u32 = 4;
pub const KIND_UNION: u32 = 5;
pub const KIND_ENUM: u32 = 6;
pub const KIND_FWD: u32 = 7;
pub const KIND_TYPEDEF: u32 = 8;
pub const KIND_VOLATILE: u32 = 9;
pub const KIND_CONST: u32 = 10;
pub const KIND_RESTRICT: u32 = 11;
pub const KIND_FUNC: u32 = 12;
pub const KIND_FUNC_PROTO: u32 = 13;
pub const KIND_VAR: u32 = 14;
pub const KIND_DATASEC: u32 = 15;
pub const KIND_FLOAT: u32 = 16;
pub const KIND_DECL_TAG: u32 = 17;
pub const KIND_TYPE_TAG: u32 = 18;
pub const KIND_ENUM64: u32 = 19;

pub fn kind_name(k: u32) -> &'static str {
    match k {
        0 => "UNKN",
        KIND_INT => "INT",
        KIND_PTR => "PTR",
        KIND_ARRAY => "ARRAY",
        KIND_STRUCT => "STRUCT",
        KIND_UNION => "UNION",
        KIND_ENUM => "ENUM",
        KIND_FWD => "FWD",
        KIND_TYPEDEF => "TYPEDEF",
        KIND_VOLATILE => "VOLATILE",
        KIND_CONST => "CONST",
        KIND_RESTRICT => "RESTRICT",
        KIND_FUNC => "FUNC",
        KIND_FUNC_PROTO => "FUNC_PROTO",
        KIND_VAR => "VAR",
        KIND_DATASEC => "DATASEC",
        KIND_FLOAT => "FLOAT",
        KIND_DECL_TAG => "DECL_TAG",
        KIND_TYPE_TAG => "TYPE_TAG",
        KIND_ENUM64 => "ENUM64",
        _ => "UNKNOWN",
    }
}

#[derive(Clone)]
pub struct Member {
    pub name: String,
    pub type_id: u32,
    pub bit_offset: u32,
    pub bitfield_size: u32,
}

#[derive(Clone)]
pub struct EnumVal {
    pub name: String,
    pub val: i64,
}

#[derive(Clone)]
pub struct SecInfo {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(Clone)]
pub struct Type {
    pub id: u32,
    pub name: String,
    pub kind: u32,
    pub kind_flag: bool,
    pub vlen: u32,
    /// `size` for the kinds that have one, `type` for the kinds that refer.
    pub size_or_type: u32,
    // Per-kind payload.
    pub int_encoding: u8,
    pub int_offset: u8,
    pub int_bits: u8,
    pub array_elem: u32,
    pub array_index: u32,
    pub array_nelems: u32,
    pub members: Vec<Member>,
    pub values: Vec<EnumVal>,
    pub params: Vec<Member>,
    pub linkage: u32,
    pub secinfo: Vec<SecInfo>,
    pub component_idx: i32,
}

pub struct Btf {
    pub types: Vec<Type>,
    pub str_len: usize,
    pub type_len: usize,
    pub strings: Vec<u8>,
}

fn name_at(strings: &[u8], off: u32) -> String {
    let off = off as usize;
    if off == 0 || off >= strings.len() {
        return String::new();
    }
    let s = &strings[off..];
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).into_owned()
}

fn disp(n: &str) -> &str {
    if n.is_empty() {
        "(anon)"
    } else {
        n
    }
}

impl Btf {
    pub fn parse(sec: &[u8]) -> R<Btf> {
        let mut c = Cur::new(sec);
        let magic = c.u16()?;
        if magic != 0xeb9f {
            return Err(format!(
                ".BTF magic is {:#06x}, expected 0xeb9f (0x9feb byte-swapped means a \
                 big-endian object, which is not supported)",
                magic
            ));
        }
        let version = c.u8()?;
        if version != 1 {
            return Err(format!(".BTF version is {}, expected 1", version));
        }
        let _flags = c.u8()?;
        let hdr_len = c.u32()? as usize;
        let type_off = c.u32()? as usize;
        let type_len = c.u32()? as usize;
        let str_off = c.u32()? as usize;
        let str_len = c.u32()? as usize;

        let tstart = hdr_len
            .checked_add(type_off)
            .ok_or("BTF type offset overflows")?;
        let tend = tstart.checked_add(type_len).ok_or("BTF type length overflows")?;
        let sstart = hdr_len
            .checked_add(str_off)
            .ok_or("BTF string offset overflows")?;
        let send = sstart
            .checked_add(str_len)
            .ok_or("BTF string length overflows")?;
        if tend > sec.len() || send > sec.len() {
            return Err(format!(
                "BTF claims types at {}..{} and strings at {}..{} inside a {}-byte section",
                tstart,
                tend,
                sstart,
                send,
                sec.len()
            ));
        }
        let strings = sec[sstart..send].to_vec();
        let tbuf = &sec[tstart..tend];

        let mut types = Vec::new();
        let mut c = Cur::new(tbuf);
        let mut id = 1u32;
        while c.remaining() >= 12 {
            let name_off = c.u32()?;
            let info = c.u32()?;
            let size_or_type = c.u32()?;
            let vlen = info & 0xffff;
            let kind = (info >> 24) & 0x1f;
            let kind_flag = (info >> 31) & 1 == 1;
            let mut t = Type {
                id,
                name: name_at(&strings, name_off),
                kind,
                kind_flag,
                vlen,
                size_or_type,
                int_encoding: 0,
                int_offset: 0,
                int_bits: 0,
                array_elem: 0,
                array_index: 0,
                array_nelems: 0,
                members: Vec::new(),
                values: Vec::new(),
                params: Vec::new(),
                linkage: 0,
                secinfo: Vec::new(),
                component_idx: 0,
            };
            match kind {
                KIND_INT => {
                    let v = c.u32()?;
                    t.int_encoding = ((v >> 24) & 0x0f) as u8;
                    t.int_offset = ((v >> 16) & 0xff) as u8;
                    t.int_bits = (v & 0xff) as u8;
                }
                KIND_ARRAY => {
                    t.array_elem = c.u32()?;
                    t.array_index = c.u32()?;
                    t.array_nelems = c.u32()?;
                }
                KIND_STRUCT | KIND_UNION => {
                    for _ in 0..vlen {
                        let n = c.u32()?;
                        let ty = c.u32()?;
                        let off = c.u32()?;
                        // With the kind flag set, the offset word packs the
                        // bitfield width into its top byte.
                        let (bit_offset, bitfield_size) = if kind_flag {
                            (off & 0x00ff_ffff, (off >> 24) & 0xff)
                        } else {
                            (off, 0)
                        };
                        t.members.push(Member {
                            name: name_at(&strings, n),
                            type_id: ty,
                            bit_offset,
                            bitfield_size,
                        });
                    }
                }
                KIND_ENUM => {
                    for _ in 0..vlen {
                        let n = c.u32()?;
                        let v = c.u32()? as i32;
                        t.values.push(EnumVal {
                            name: name_at(&strings, n),
                            val: if kind_flag { v as u32 as i64 } else { v as i64 },
                        });
                    }
                }
                KIND_ENUM64 => {
                    for _ in 0..vlen {
                        let n = c.u32()?;
                        let lo = c.u32()? as u64;
                        let hi = c.u32()? as u64;
                        t.values.push(EnumVal {
                            name: name_at(&strings, n),
                            val: ((hi << 32) | lo) as i64,
                        });
                    }
                }
                KIND_FUNC_PROTO => {
                    for _ in 0..vlen {
                        let n = c.u32()?;
                        let ty = c.u32()?;
                        t.params.push(Member {
                            name: name_at(&strings, n),
                            type_id: ty,
                            bit_offset: 0,
                            bitfield_size: 0,
                        });
                    }
                }
                KIND_VAR => t.linkage = c.u32()?,
                KIND_DATASEC => {
                    for _ in 0..vlen {
                        let ty = c.u32()?;
                        let off = c.u32()?;
                        let sz = c.u32()?;
                        t.secinfo.push(SecInfo {
                            type_id: ty,
                            offset: off,
                            size: sz,
                        });
                    }
                }
                KIND_DECL_TAG => t.component_idx = c.u32()? as i32,
                // FUNC puts its linkage in vlen, not in a trailing word.
                KIND_FUNC => t.linkage = vlen,
                _ => {}
            }
            types.push(t);
            id += 1;
        }
        Ok(Btf {
            types,
            str_len,
            type_len,
            strings,
        })
    }

    pub fn dump(&self, o: &mut String) {
        for t in &self.types {
            t.dump(o, &self.types);
        }
    }

    pub fn by_id(&self, id: u32) -> Option<&Type> {
        if id == 0 {
            None
        } else {
            self.types.get(id as usize - 1)
        }
    }
}

fn int_encoding_name(e: u8) -> &'static str {
    // The encoding is a bitmask, and bpftool prints the first one it
    // recognises rather than the set.
    if e & 0x1 != 0 {
        "SIGNED"
    } else if e & 0x2 != 0 {
        "CHAR"
    } else if e & 0x4 != 0 {
        "BOOL"
    } else {
        "(none)"
    }
}

fn linkage_name(l: u32) -> &'static str {
    match l {
        0 => "static",
        1 => "global",
        2 => "extern",
        _ => "(unknown)",
    }
}

fn fwd_kind(flag: bool) -> &'static str {
    if flag {
        "union"
    } else {
        "struct"
    }
}

impl Type {
    pub fn dump(&self, o: &mut String, all: &[Type]) {
        let k = kind_name(self.kind);
        let n = disp(&self.name);
        match self.kind {
            KIND_INT => {
                let _ = writeln!(
                    o,
                    "[{}] INT '{}' size={} bits_offset={} nr_bits={} encoding={}",
                    self.id,
                    n,
                    self.size_or_type,
                    self.int_offset,
                    self.int_bits,
                    int_encoding_name(self.int_encoding)
                );
            }
            KIND_PTR | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
            | KIND_TYPE_TAG => {
                let _ = writeln!(o, "[{}] {} '{}' type_id={}", self.id, k, n, self.size_or_type);
            }
            KIND_ARRAY => {
                let _ = writeln!(
                    o,
                    "[{}] ARRAY '{}' type_id={} index_type_id={} nr_elems={}",
                    self.id, n, self.array_elem, self.array_index, self.array_nelems
                );
            }
            KIND_STRUCT | KIND_UNION => {
                let _ = writeln!(
                    o,
                    "[{}] {} '{}' size={} vlen={}",
                    self.id, k, n, self.size_or_type, self.vlen
                );
                for m in &self.members {
                    // bpftool prints the bitfield width only when there is
                    // one, even on a struct whose kind flag is set.
                    if m.bitfield_size != 0 {
                        let _ = writeln!(
                            o,
                            "\t'{}' type_id={} bits_offset={} bitfield_size={}",
                            disp(&m.name),
                            m.type_id,
                            m.bit_offset,
                            m.bitfield_size
                        );
                    } else {
                        let _ = writeln!(
                            o,
                            "\t'{}' type_id={} bits_offset={}",
                            disp(&m.name),
                            m.type_id,
                            m.bit_offset
                        );
                    }
                }
            }
            KIND_ENUM => {
                let _ = writeln!(
                    o,
                    "[{}] ENUM '{}' encoding={} size={} vlen={}",
                    self.id,
                    n,
                    if self.kind_flag { "SIGNED" } else { "UNSIGNED" },
                    self.size_or_type,
                    self.vlen
                );
                for v in &self.values {
                    if self.kind_flag {
                        let _ = writeln!(o, "\t'{}' val={}", disp(&v.name), v.val as i32);
                    } else {
                        let _ = writeln!(o, "\t'{}' val={}", disp(&v.name), v.val as u32);
                    }
                }
            }
            KIND_ENUM64 => {
                let _ = writeln!(
                    o,
                    "[{}] ENUM64 '{}' encoding={} size={} vlen={}",
                    self.id,
                    n,
                    if self.kind_flag { "SIGNED" } else { "UNSIGNED" },
                    self.size_or_type,
                    self.vlen
                );
                for v in &self.values {
                    if self.kind_flag {
                        let _ = writeln!(o, "\t'{}' val={}LL", disp(&v.name), v.val);
                    } else {
                        let _ = writeln!(o, "\t'{}' val={}ULL", disp(&v.name), v.val as u64);
                    }
                }
            }
            KIND_FWD => {
                let _ = writeln!(
                    o,
                    "[{}] FWD '{}' fwd_kind={}",
                    self.id,
                    n,
                    fwd_kind(self.kind_flag)
                );
            }
            KIND_FUNC => {
                let _ = writeln!(
                    o,
                    "[{}] FUNC '{}' type_id={} linkage={}",
                    self.id,
                    n,
                    self.size_or_type,
                    linkage_name(self.linkage)
                );
            }
            KIND_FUNC_PROTO => {
                let _ = writeln!(
                    o,
                    "[{}] FUNC_PROTO '{}' ret_type_id={} vlen={}",
                    self.id, n, self.size_or_type, self.vlen
                );
                for p in &self.params {
                    let _ = writeln!(o, "\t'{}' type_id={}", disp(&p.name), p.type_id);
                }
            }
            KIND_VAR => {
                let _ = writeln!(
                    o,
                    "[{}] VAR '{}' type_id={}, linkage={}",
                    self.id,
                    n,
                    self.size_or_type,
                    linkage_name(self.linkage)
                );
            }
            KIND_DATASEC => {
                let _ = writeln!(
                    o,
                    "[{}] DATASEC '{}' size={} vlen={}",
                    self.id, n, self.size_or_type, self.vlen
                );
                for si in &self.secinfo {
                    // bpftool names the variable the entry points at, which
                    // is the only thing that makes a DATASEC readable.
                    let who = all
                        .get(si.type_id.wrapping_sub(1) as usize)
                        .filter(|_| si.type_id != 0)
                        .map(|t| {
                            format!(" ({} '{}')", kind_name(t.kind), disp(&t.name))
                        })
                        .unwrap_or_default();
                    let _ = writeln!(
                        o,
                        "\ttype_id={} offset={} size={}{}",
                        si.type_id, si.offset, si.size, who
                    );
                }
            }
            KIND_FLOAT => {
                let _ = writeln!(o, "[{}] FLOAT '{}' size={}", self.id, n, self.size_or_type);
            }
            KIND_DECL_TAG => {
                let _ = writeln!(
                    o,
                    "[{}] DECL_TAG '{}' type_id={} component_idx={}",
                    self.id, n, self.size_or_type, self.component_idx
                );
            }
            _ => {
                let _ = writeln!(
                    o,
                    "[{}] {} '{}' info_kind={} size_or_type={} vlen={}",
                    self.id, k, n, self.kind, self.size_or_type, self.vlen
                );
            }
        }
    }
}
