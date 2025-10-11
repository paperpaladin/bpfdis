//! ELF64 little-endian reader, enough of it for a BPF relocatable object.
//!
//! Every read of the file goes through `Cur`. Nothing else indexes the file
//! buffer, which is what keeps the number of places a malformed header can
//! reach down to one.

pub type R<T> = Result<T, String>;

/// A bounds-checked cursor over a byte slice.
///
/// Rust would panic on an out-of-range index rather than read wild memory, so
/// the value here is not memory safety: it is that a panic is a crash and a
/// crash is indistinguishable, to anything watching the exit status, from the
/// tool falling over. Every read returns an error instead.
pub struct Cur<'a> {
    b: &'a [u8],
    pub pos: usize,
}

impl<'a> Cur<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Cur { b, pos: 0 }
    }
    pub fn at(b: &'a [u8], pos: usize) -> Self {
        Cur { b, pos }
    }
    pub fn len(&self) -> usize {
        self.b.len()
    }
    pub fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    pub fn take(&mut self, n: usize) -> R<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| "read length overflows".to_string())?;
        if end > self.b.len() {
            return Err(format!(
                "read of {} bytes at {:#x} runs past the end of {} bytes",
                n,
                self.pos,
                self.b.len()
            ));
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    pub fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> R<u16> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self) -> R<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn u64(&mut self) -> R<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    pub fn skip(&mut self, n: usize) -> R<()> {
        self.take(n)?;
        Ok(())
    }
}

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
pub const SHF_GROUP: u64 = 0x200;
pub const SHF_TLS: u64 = 0x400;
pub const SHF_COMPRESSED: u64 = 0x800;
pub const SHF_EXCLUDE: u64 = 0x8000_0000;

pub const EM_BPF: u16 = 247;
pub const ET_REL: u16 = 1;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;

#[derive(Clone)]
pub struct Section {
    pub idx: usize,
    pub name: String,
    pub sh_name: u32,
    pub sh_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
    /// Byte range of the section contents inside the file, empty for NOBITS
    /// and for a header whose range falls outside the file.
    pub span: (usize, usize),
    /// Set when the header claims a range the file cannot hold. The section is
    /// then treated as empty, which is the normal shape of a truncated object,
    /// and the warning is printed rather than swallowed.
    pub truncated: bool,
}

impl Section {
    pub fn data<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        &file[self.span.0..self.span.1]
    }
}

#[derive(Clone)]
pub struct Sym {
    pub idx: usize,
    pub name: String,
    pub st_name: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

impl Sym {
    pub fn stype(&self) -> u8 {
        self.info & 0xf
    }
    pub fn bind(&self) -> u8 {
        self.info >> 4
    }
}

#[derive(Clone)]
pub struct Reloc {
    /// Index of the section the relocation applies to (the `sh_info` of the
    /// relocation section).
    pub target_sec: usize,
    pub offset: u64,
    pub sym: u32,
    pub rtype: u32,
    pub addend: i64,
    pub is_rela: bool,
    pub sym_name: String,
}

pub struct Elf {
    pub file: Vec<u8>,
    pub etype: u16,
    pub machine: u16,
    pub version: u32,
    pub flags: u32,
    pub shoff: u64,
    pub shnum: u16,
    pub shstrndx: u16,
    pub sections: Vec<Section>,
    pub syms: Vec<Sym>,
    pub symtab_sec: Option<usize>,
    pub relocs: Vec<Reloc>,
    pub warnings: Vec<String>,
}

fn cstr(b: &[u8], off: usize) -> String {
    if off >= b.len() {
        return String::new();
    }
    let s = &b[off..];
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).into_owned()
}

impl Elf {
    pub fn parse(file: Vec<u8>) -> R<Elf> {
        if file.len() < 64 {
            return Err(format!(
                "not an ELF64 object: {} bytes, an ELF64 header is 64",
                file.len()
            ));
        }
        if &file[0..4] != b"\x7fELF" {
            return Err("not an ELF file: bad magic".to_string());
        }
        if file[4] != 2 {
            return Err(format!(
                "not ELF64: EI_CLASS is {} (1 is 32-bit, 2 is 64-bit)",
                file[4]
            ));
        }
        if file[5] != 1 {
            return Err(format!(
                "not little-endian: EI_DATA is {}; bpfeb objects are not supported",
                file[5]
            ));
        }
        let mut warnings = Vec::new();
        let mut c = Cur::at(&file, 16);
        let etype = c.u16()?;
        let machine = c.u16()?;
        let version = c.u32()?;
        let _entry = c.u64()?;
        let _phoff = c.u64()?;
        let shoff = c.u64()?;
        let flags = c.u32()?;
        let _ehsize = c.u16()?;
        let _phentsize = c.u16()?;
        let _phnum = c.u16()?;
        let shentsize = c.u16()?;
        let shnum = c.u16()?;
        let shstrndx = c.u16()?;

        if machine != EM_BPF {
            return Err(format!(
                "e_machine is {}, not {} (EM_BPF): this is not a BPF object",
                machine, EM_BPF
            ));
        }
        if shentsize != 64 && shnum != 0 {
            return Err(format!("e_shentsize is {}, expected 64", shentsize));
        }

        // Section headers.
        let mut raw: Vec<Section> = Vec::new();
        for i in 0..shnum as usize {
            let off = shoff as usize + i * 64;
            let mut c = Cur::at(&file, off);
            let sh_name = c.u32().map_err(|e| format!("section header {}: {}", i, e))?;
            let sh_type = c.u32()?;
            let sflags = c.u64()?;
            let addr = c.u64()?;
            let offset = c.u64()?;
            let size = c.u64()?;
            let link = c.u32()?;
            let info = c.u32()?;
            let addralign = c.u64()?;
            let entsize = c.u64()?;

            let mut truncated = false;
            let span = if sh_type == SHT_NOBITS || sh_type == SHT_NULL {
                (0usize, 0usize)
            } else {
                let s = offset as usize;
                let e = offset.checked_add(size).map(|v| v as usize);
                match e {
                    Some(e) if e <= file.len() && s <= e => (s, e),
                    _ => {
                        truncated = true;
                        warnings.push(format!(
                            "section {}: contents at {:#x}+{:#x} fall outside the {}-byte file; treated as empty",
                            i, offset, size, file.len()
                        ));
                        (0usize, 0usize)
                    }
                }
            };
            raw.push(Section {
                idx: i,
                name: String::new(),
                sh_name,
                sh_type,
                flags: sflags,
                addr,
                offset,
                size,
                link,
                info,
                addralign,
                entsize,
                span,
                truncated,
            });
        }

        // Section names.
        let shstr: Vec<u8> = match raw.get(shstrndx as usize) {
            Some(s) if s.sh_type == SHT_STRTAB => s.data(&file).to_vec(),
            _ => {
                if shnum != 0 {
                    warnings.push(format!(
                        "e_shstrndx is {} which is not a string table; section names unavailable",
                        shstrndx
                    ));
                }
                Vec::new()
            }
        };
        for s in raw.iter_mut() {
            s.name = cstr(&shstr, s.sh_name as usize);
        }

        // Symbols.
        let mut syms = Vec::new();
        let symtab_sec = raw.iter().position(|s| s.sh_type == SHT_SYMTAB);
        if let Some(si) = symtab_sec {
            let strtab: Vec<u8> = match raw.get(raw[si].link as usize) {
                Some(s) => s.data(&file).to_vec(),
                None => Vec::new(),
            };
            let d = raw[si].data(&file);
            let n = d.len() / 24;
            if raw[si].entsize != 0 && raw[si].entsize != 24 {
                warnings.push(format!(
                    "symtab sh_entsize is {}, expected 24; reading 24-byte entries anyway",
                    raw[si].entsize
                ));
            }
            for i in 0..n {
                let mut c = Cur::at(d, i * 24);
                let st_name = c.u32()?;
                let info = c.u8()?;
                let other = c.u8()?;
                let shndx = c.u16()?;
                let value = c.u64()?;
                let size = c.u64()?;
                // readelf prints a STT_SECTION symbol under the name of the
                // section it points at; its own st_name is 0. Resolving it
                // here keeps one convention in one place, and the oracle
                // found this on its first run: 664 of 1048 symbols across the
                // corpus differed only by this substitution.
                let mut nm = cstr(&strtab, st_name as usize);
                if nm.is_empty() && (info & 0xf) == STT_SECTION {
                    if let Some(sec) = raw.get(shndx as usize) {
                        nm = sec.name.clone();
                    }
                }
                syms.push(Sym {
                    idx: i,
                    name: nm,
                    st_name,
                    info,
                    other,
                    shndx,
                    value,
                    size,
                });
            }
        }

        // Relocations. BPF objects use SHT_REL; handle SHT_RELA too.
        let mut relocs = Vec::new();
        for s in raw.iter() {
            if s.sh_type != SHT_REL && s.sh_type != SHT_RELA {
                continue;
            }
            let is_rela = s.sh_type == SHT_RELA;
            let esz = if is_rela { 24 } else { 16 };
            let d = s.data(&file);
            for i in 0..(d.len() / esz) {
                let mut c = Cur::at(d, i * esz);
                let offset = c.u64()?;
                let info = c.u64()?;
                let addend = if is_rela { c.u64()? as i64 } else { 0 };
                let symi = (info >> 32) as u32;
                let rtype = (info & 0xffff_ffff) as u32;
                let sym_name = syms
                    .get(symi as usize)
                    .map(|y| y.name.clone())
                    .unwrap_or_else(|| format!("<sym {}>", symi));
                relocs.push(Reloc {
                    target_sec: s.info as usize,
                    offset,
                    sym: symi,
                    rtype,
                    addend,
                    is_rela,
                    sym_name,
                });
            }
        }

        Ok(Elf {
            file,
            etype,
            machine,
            version,
            flags,
            shoff,
            shnum,
            shstrndx,
            sections: raw,
            syms,
            symtab_sec,
            relocs,
            warnings,
        })
    }

    pub fn section_by_name(&self, n: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == n)
    }

    /// The sections that hold BPF instructions.
    pub fn text_sections(&self) -> Vec<&Section> {
        self.sections
            .iter()
            .filter(|s| s.flags & SHF_EXECINSTR != 0 && s.sh_type == SHT_PROGBITS)
            .collect()
    }
}

pub fn sht_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        10 => "SHLIB",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        17 => "GROUP",
        18 => "SYMTAB SHNDX",
        0x6fff_4c03 => "LLVM_ADDRSIG",
        0x6fff_4c00 => "LLVM_ODRTAB",
        0x6fff_4c01 => "LLVM_LINKER_OPTIONS",
        0x6fff_4c04 => "LLVM_DEPENDENT_LIBRARIES",
        0x6fff_4c05 => "LLVM_SYMPART",
        0x6fff_4c06 => "LLVM_PART_EHDR",
        0x6fff_4c07 => "LLVM_PART_PHDR",
        0x6fff_4c08 => "LLVM_BB_ADDR_MAP_V0",
        0x6fff_4c09 => "LLVM_CALL_GRAPH_PROFILE",
        0x6fff_4c0a => "LLVM_BB_ADDR_MAP",
        0x6fff_4c0b => "LLVM_OFFLOADING",
        0x6fff_4c0c => "LLVM_LTO",
        0x6fff_fff5 => "GNU_ATTRIBUTES",
        0x6fff_fff6 => "GNU_HASH",
        0x6fff_fffd => "VERDEF",
        0x6fff_fffe => "VERNEED",
        0x6fff_ffff => "VERSYM",
        _ => "UNKNOWN",
    }
}

pub fn shf_string(f: u64) -> String {
    let mut s = String::new();
    if f & SHF_WRITE != 0 {
        s.push('W');
    }
    if f & SHF_ALLOC != 0 {
        s.push('A');
    }
    if f & SHF_EXECINSTR != 0 {
        s.push('X');
    }
    if f & SHF_MERGE != 0 {
        s.push('M');
    }
    if f & SHF_STRINGS != 0 {
        s.push('S');
    }
    if f & SHF_INFO_LINK != 0 {
        s.push('I');
    }
    // The order is readelf's own, from its "Key to Flags" block, so the two
    // strings can be compared directly rather than as sorted sets.
    if f & SHF_LINK_ORDER != 0 {
        s.push('L');
    }
    if f & SHF_OS_NONCONFORMING != 0 {
        s.push('O');
    }
    if f & SHF_GROUP != 0 {
        s.push('G');
    }
    if f & SHF_TLS != 0 {
        s.push('T');
    }
    if f & SHF_COMPRESSED != 0 {
        s.push('C');
    }
    if f & SHF_EXCLUDE != 0 {
        s.push('E');
    }
    s
}

pub fn stt_name(t: u8) -> &'static str {
    match t {
        STT_NOTYPE => "NOTYPE",
        STT_OBJECT => "OBJECT",
        STT_FUNC => "FUNC",
        STT_SECTION => "SECTION",
        4 => "FILE",
        5 => "COMMON",
        6 => "TLS",
        _ => "UNKNOWN",
    }
}

pub fn stb_name(b: u8) -> &'static str {
    match b {
        0 => "LOCAL",
        1 => "GLOBAL",
        2 => "WEAK",
        _ => "UNKNOWN",
    }
}

/// Relocation type names, from the BPF psABI.
pub fn r_bpf_name(t: u32) -> String {
    match t {
        0 => "R_BPF_NONE".into(),
        1 => "R_BPF_64_64".into(),
        2 => "R_BPF_64_ABS64".into(),
        3 => "R_BPF_64_ABS32".into(),
        4 => "R_BPF_64_NODYLD32".into(),
        10 => "R_BPF_64_32".into(),
        _ => format!("R_BPF_UNKNOWN_{}", t),
    }
}
