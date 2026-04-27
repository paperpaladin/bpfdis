//! `.BTF.ext`: which BTF function a program is, which source line each
//! instruction came from, and which field each CO-RE relocation is about.
//!
//! The section is three tables with one shape. Each is a 4-byte record size
//! followed by a run of per-section groups, and each group is a string
//! offset naming the ELF section and a count, followed by that many records
//! of the declared size. The record size is read from the file rather than
//! assumed, because it is how the format grows: a longer record means
//! trailing fields this build does not know about, and the right response is
//! to skip them, not to misread the next record.
//!
//! The strings are in `.BTF`, not here. A `.BTF.ext` without its `.BTF` is
//! unreadable and says so rather than printing offsets.
//!
//! `insn_off` is a BYTE offset into the section, not an instruction index.
//! That is the one thing about this format that is easy to get wrong and
//! invisible afterwards, because dividing by eight twice and once give the
//! same answer for the first instruction of every function.

use crate::elf::{Cur, R};

pub struct FuncInfo {
    pub insn_off: u32,
    pub type_id: u32,
}

pub struct LineInfo {
    pub insn_off: u32,
    pub file_name: String,
    pub line_text: String,
    /// Source line number, the top 22 bits of the packed `line_col` word.
    pub line: u32,
    /// Source column, the bottom 10 bits.
    pub col: u32,
}

pub struct CoreRelo {
    pub insn_off: u32,
    pub type_id: u32,
    pub access: String,
    pub kind: u32,
}

pub struct Sec<T> {
    pub name: String,
    pub recs: Vec<T>,
}

pub struct BtfExt {
    pub funcs: Vec<Sec<FuncInfo>>,
    pub lines: Vec<Sec<LineInfo>>,
    pub relos: Vec<Sec<CoreRelo>>,
    pub func_rec_size: u32,
    pub line_rec_size: u32,
    pub relo_rec_size: u32,
}

/// The CO-RE relocation kinds, from the published `bpf_core_relo_kind`.
pub fn relo_kind_name(k: u32) -> &'static str {
    match k {
        0 => "FIELD_BYTE_OFFSET",
        1 => "FIELD_BYTE_SIZE",
        2 => "FIELD_EXISTS",
        3 => "FIELD_SIGNED",
        4 => "FIELD_LSHIFT_U64",
        5 => "FIELD_RSHIFT_U64",
        6 => "TYPE_ID_LOCAL",
        7 => "TYPE_ID_TARGET",
        8 => "TYPE_EXISTS",
        9 => "TYPE_SIZE",
        10 => "ENUMVAL_EXISTS",
        11 => "ENUMVAL_VALUE",
        12 => "TYPE_MATCHES",
        _ => "UNKNOWN",
    }
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

/// Walk one of the three tables. `read` gets a cursor positioned at the
/// start of a record and the declared record size, and must not read past
/// it; the caller advances by the declared size whatever `read` consumed.
fn table<T>(
    sec: &[u8],
    start: usize,
    len: usize,
    strings: &[u8],
    what: &str,
    read: impl Fn(&mut Cur, &[u8]) -> R<T>,
) -> R<(u32, Vec<Sec<T>>)> {
    if len == 0 {
        return Ok((0, Vec::new()));
    }
    let end = start
        .checked_add(len)
        .ok_or_else(|| format!(".BTF.ext {} length overflows", what))?;
    if end > sec.len() {
        return Err(format!(
            ".BTF.ext {} runs from {} to {} inside a {}-byte section",
            what,
            start,
            end,
            sec.len()
        ));
    }
    let body = &sec[start..end];
    let mut c = Cur::new(body);
    let rec_size = c.u32()?;
    if rec_size == 0 {
        return Err(format!(".BTF.ext {} record size is zero", what));
    }
    let mut out = Vec::new();
    while c.remaining() > 0 {
        let name_off = c.u32()?;
        let n = c.u32()? as usize;
        let mut recs = Vec::with_capacity(0);
        for _ in 0..n {
            let at = c.pos;
            let raw = c.take(rec_size as usize)?;
            let mut rc = Cur::new(raw);
            let _ = at;
            recs.push(read(&mut rc, strings)?);
        }
        out.push(Sec {
            name: name_at(strings, name_off),
            recs,
        });
    }
    Ok((rec_size, out))
}

impl BtfExt {
    pub fn parse(sec: &[u8], strings: &[u8]) -> R<BtfExt> {
        let mut c = Cur::new(sec);
        let magic = c.u16()?;
        if magic != 0xeb9f {
            return Err(format!(
                ".BTF.ext magic is {:#06x}, expected 0xeb9f",
                magic
            ));
        }
        let version = c.u8()?;
        if version != 1 {
            return Err(format!(".BTF.ext version is {}, expected 1", version));
        }
        let _flags = c.u8()?;
        let hdr_len = c.u32()? as usize;
        if hdr_len < 24 {
            return Err(format!(
                ".BTF.ext header is {} bytes, too short to hold the func and line \
                 offsets",
                hdr_len
            ));
        }
        let func_off = c.u32()? as usize;
        let func_len = c.u32()? as usize;
        let line_off = c.u32()? as usize;
        let line_len = c.u32()? as usize;
        // The CO-RE pair is the part added after the format shipped, so a
        // header shorter than 32 bytes has no relocations rather than
        // broken ones.
        let (relo_off, relo_len) = if hdr_len >= 32 {
            (c.u32()? as usize, c.u32()? as usize)
        } else {
            (0, 0)
        };

        let (func_rec_size, funcs) = table(
            sec,
            hdr_len.saturating_add(func_off),
            func_len,
            strings,
            "func_info",
            |c, _s| {
                Ok(FuncInfo {
                    insn_off: c.u32()?,
                    type_id: c.u32()?,
                })
            },
        )?;
        let (line_rec_size, lines) = table(
            sec,
            hdr_len.saturating_add(line_off),
            line_len,
            strings,
            "line_info",
            |c, s| {
                let insn_off = c.u32()?;
                let file = c.u32()?;
                let text = c.u32()?;
                let line_col = c.u32()?;
                Ok(LineInfo {
                    insn_off,
                    file_name: name_at(s, file),
                    line_text: name_at(s, text),
                    line: line_col >> 10,
                    col: line_col & 0x3ff,
                })
            },
        )?;
        let (relo_rec_size, relos) = table(
            sec,
            hdr_len.saturating_add(relo_off),
            relo_len,
            strings,
            "core_relo",
            |c, s| {
                let insn_off = c.u32()?;
                let type_id = c.u32()?;
                let access = c.u32()?;
                let kind = c.u32()?;
                Ok(CoreRelo {
                    insn_off,
                    type_id,
                    access: name_at(s, access),
                    kind,
                })
            },
        )?;
        Ok(BtfExt {
            funcs,
            lines,
            relos,
            func_rec_size,
            line_rec_size,
            relo_rec_size,
        })
    }

    pub fn dump(&self, o: &mut String, btf: &crate::btf::Btf) {
        use std::fmt::Write as _;
        let _ = writeln!(
            o,
            "btfext func_info rec_size={} sections={}",
            self.func_rec_size,
            self.funcs.len()
        );
        for s in &self.funcs {
            for r in &s.recs {
                let name = btf
                    .by_id(r.type_id)
                    .map(|t| t.name.clone())
                    .unwrap_or_default();
                let _ = writeln!(
                    o,
                    "func_info {} slot={} type_id={} {}",
                    s.name,
                    r.insn_off / 8,
                    r.type_id,
                    if name.is_empty() { "(no such type)" } else { &name }
                );
            }
        }
        let _ = writeln!(
            o,
            "btfext line_info rec_size={} sections={}",
            self.line_rec_size,
            self.lines.len()
        );
        for s in &self.lines {
            for r in &s.recs {
                let _ = writeln!(
                    o,
                    "line_info {} slot={} {}:{}:{}",
                    s.name,
                    r.insn_off / 8,
                    r.file_name,
                    r.line,
                    r.col
                );
            }
        }
        let _ = writeln!(
            o,
            "btfext core_relo rec_size={} sections={}",
            self.relo_rec_size,
            self.relos.len()
        );
        for s in &self.relos {
            for r in &s.recs {
                let _ = writeln!(
                    o,
                    "core_relo {} slot={} type_id={} kind={} ({}) access={}",
                    s.name,
                    r.insn_off / 8,
                    r.type_id,
                    r.kind,
                    relo_kind_name(r.kind),
                    r.access
                );
            }
        }
    }
}
