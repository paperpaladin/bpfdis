//! BPF instruction decoding.
//!
//! An instruction is eight bytes, little-endian:
//!
//! ```text
//!   code:8   regs:8   off:16   imm:32
//! ```
//!
//! with `regs` holding `dst` in its low nibble and `src` in its high one. The
//! single exception is `BPF_LD | BPF_IMM | BPF_DW`, which is sixteen bytes:
//! the second half contributes the high 32 bits of a 64-bit immediate and its
//! own code, regs and off fields must be zero.
//!
//! The text produced by `Insn::text` is LLVM's BPF assembly syntax, printed
//! with hexadecimal immediates the way `llvm-objdump` does. `llvm-mc` prints
//! the same syntax in decimal, so the comparison in `t/disasm_cmp.py`
//! normalises every number and can then compare the two strings whole.
//!
//! Decoding is deliberately separate from validation. `Insn::op` says which
//! instruction this is; `Insn::defects` says which fields the kernel requires
//! to be zero and are not. A disassembler that refuses to name an instruction
//! because a reserved field is dirty tells you less than one that names it
//! and says the field is dirty.

use std::fmt::Write as _;

// Instruction classes, the low three bits of `code`.
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

// The source bit for ALU and JMP: 0 means the immediate, 1 means `src`.
pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

// Load and store sizes, bits 3 and 4.
pub const BPF_W: u8 = 0x00;
pub const BPF_H: u8 = 0x08;
pub const BPF_B: u8 = 0x10;
pub const BPF_DW: u8 = 0x18;

// Load and store modes, the top three bits.
pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_MEMSX: u8 = 0x80;
pub const BPF_ATOMIC: u8 = 0xc0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AluOp {
    Add,
    Sub,
    Mul,
    Div,
    Or,
    And,
    Lsh,
    Rsh,
    Neg,
    Mod,
    Xor,
    Mov,
    Arsh,
}

impl AluOp {
    fn from_bits(b: u8) -> Option<AluOp> {
        Some(match b {
            0x00 => AluOp::Add,
            0x10 => AluOp::Sub,
            0x20 => AluOp::Mul,
            0x30 => AluOp::Div,
            0x40 => AluOp::Or,
            0x50 => AluOp::And,
            0x60 => AluOp::Lsh,
            0x70 => AluOp::Rsh,
            0x80 => AluOp::Neg,
            0x90 => AluOp::Mod,
            0xa0 => AluOp::Xor,
            0xb0 => AluOp::Mov,
            0xc0 => AluOp::Arsh,
            _ => return None,
        })
    }
    /// The infix operator LLVM prints, without the `=`.
    fn sym(self, signed: bool) -> &'static str {
        match self {
            AluOp::Add => "+",
            AluOp::Sub => "-",
            AluOp::Mul => "*",
            AluOp::Div => {
                if signed {
                    "s/"
                } else {
                    "/"
                }
            }
            AluOp::Or => "|",
            AluOp::And => "&",
            AluOp::Lsh => "<<",
            AluOp::Rsh => ">>",
            AluOp::Neg => "-",
            AluOp::Mod => {
                if signed {
                    "s%"
                } else {
                    "%"
                }
            }
            AluOp::Xor => "^",
            AluOp::Mov => "",
            AluOp::Arsh => "s>>",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cond {
    Eq,
    Gt,
    Ge,
    Set,
    Ne,
    Sgt,
    Sge,
    Lt,
    Le,
    Slt,
    Sle,
}

impl Cond {
    fn from_bits(b: u8) -> Option<Cond> {
        Some(match b {
            0x10 => Cond::Eq,
            0x20 => Cond::Gt,
            0x30 => Cond::Ge,
            0x40 => Cond::Set,
            0x50 => Cond::Ne,
            0x60 => Cond::Sgt,
            0x70 => Cond::Sge,
            0xa0 => Cond::Lt,
            0xb0 => Cond::Le,
            0xc0 => Cond::Slt,
            0xd0 => Cond::Sle,
            _ => return None,
        })
    }
    fn sym(self) -> &'static str {
        match self {
            Cond::Eq => "==",
            Cond::Gt => ">",
            Cond::Ge => ">=",
            Cond::Set => "&",
            Cond::Ne => "!=",
            Cond::Sgt => "s>",
            Cond::Sge => "s>=",
            Cond::Lt => "<",
            Cond::Le => "<=",
            Cond::Slt => "s<",
            Cond::Sle => "s<=",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AtomicOp {
    Add,
    Or,
    And,
    Xor,
    Xchg,
    CmpXchg,
}

impl AtomicOp {
    fn name(self) -> &'static str {
        match self {
            AtomicOp::Add => "add",
            AtomicOp::Or => "or",
            AtomicOp::And => "and",
            AtomicOp::Xor => "xor",
            AtomicOp::Xchg => "xchg",
            AtomicOp::CmpXchg => "cmpxchg",
        }
    }
    fn sym(self) -> &'static str {
        match self {
            AtomicOp::Add => "+=",
            AtomicOp::Or => "|=",
            AtomicOp::And => "&=",
            AtomicOp::Xor => "^=",
            AtomicOp::Xchg => "=",
            AtomicOp::CmpXchg => "=",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EndKind {
    Le,
    Be,
    Bswap,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Op {
    /// `dst op= src-or-imm`. `movsx` is a `Mov` with a nonzero `sx` width.
    Alu {
        op: AluOp,
        wide: bool,
        reg: bool,
        signed: bool,
        sx: u8,
    },
    End {
        kind: EndKind,
        width: u8,
    },
    /// Conditional jump. `wide` is false for the `BPF_JMP32` class.
    Jmp {
        cond: Cond,
        wide: bool,
        reg: bool,
    },
    /// `dst = addr_space_cast(src, dst_as, src_as)`: `BPF_ALU64 | BPF_MOV |
    /// BPF_X` with `off` 1, where `imm` holds the two address spaces.
    AddrSpaceCast,
    /// `goto +off`, or `gotol +imm` when `long`.
    Ja {
        long: bool,
    },
    MayGoto,
    /// `src` selects the kind: 0 is a helper, 1 a call to another subprogram
    /// at a relative instruction offset, 2 a kernel function (kfunc).
    Call {
        pseudo: u8,
    },
    CallX,
    Exit,
    /// `dst = *(size *)(src + off)`, sign-extending when `sx`.
    Load {
        size: u8,
        sx: bool,
    },
    /// `*(size *)(dst + off) = imm`.
    StoreImm {
        size: u8,
    },
    /// `*(size *)(dst + off) = src`.
    StoreReg {
        size: u8,
    },
    Atomic {
        size: u8,
        aop: AtomicOp,
        fetch: bool,
    },
    /// The 16-byte `dst = imm64`. `pseudo` is `src`, which selects what the
    /// 64 bits mean once the loader has rewritten them.
    LdImm64 {
        pseudo: u8,
    },
    /// Legacy packet access: `r0 = *(size *)skb[imm]`.
    LdAbs {
        size: u8,
    },
    /// Legacy packet access: `r0 = *(size *)skb[src + imm]`.
    LdInd {
        size: u8,
    },
}

/// A field the kernel requires to hold a particular value and which does not.
///
/// These never stop an instruction being decoded. They are what `-a` reports
/// and what `--strict` turns into a nonzero exit status, because an object
/// with a dirty reserved field is an object the verifier will refuse while
/// every disassembler prints it happily.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Defect {
    /// `off` must be zero for this instruction and is not.
    OffNotZero,
    /// `imm` must be zero for this instruction and is not.
    ImmNotZero,
    /// `src` must be zero for this instruction and is not.
    SrcNotZero,
    /// `dst` must be zero for this instruction and is not.
    DstNotZero,
    /// A register number above r10. The kernel has eleven registers; LLVM's
    /// disassembler also prints `r11`, which is the verifier's internal AX
    /// register and is not addressable by a loaded program.
    RegOutOfRange,
    /// The second half of a 16-byte load has a nonzero code, regs or off.
    WideTailDirty,
}

impl Defect {
    pub fn name(self) -> &'static str {
        match self {
            Defect::OffNotZero => "off-not-zero",
            Defect::ImmNotZero => "imm-not-zero",
            Defect::SrcNotZero => "src-not-zero",
            Defect::DstNotZero => "dst-not-zero",
            Defect::RegOutOfRange => "reg-above-r10",
            Defect::WideTailDirty => "wide-tail-dirty",
        }
    }
}

#[derive(Clone)]
pub struct Insn {
    /// Index of the 8-byte slot this instruction starts at.
    pub idx: usize,
    /// 1, or 2 for the wide immediate load.
    pub slots: usize,
    pub code: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
    /// The assembled 64-bit immediate of a wide load.
    pub imm64: i64,
    /// `None` when the encoding names no instruction; the string says why.
    pub op: Option<Op>,
    pub bad: Option<String>,
    pub defects: Vec<Defect>,
    /// The raw bytes, 8 or 16 of them.
    pub bytes: Vec<u8>,
}

fn reg(n: u8) -> String {
    format!("r{}", n)
}
fn reg32(n: u8) -> String {
    format!("w{}", n)
}

/// LLVM prints a 32-bit immediate as a signed value, and `llvm-objdump` puts
/// the sign outside the `0x`. Both tools agree on the number; only the radix
/// differs, which is why the comparison normalises rather than diffs.
fn simm(v: i32) -> String {
    if v < 0 {
        format!("-{:#x}", (v as i64).unsigned_abs())
    } else {
        format!("{:#x}", v)
    }
}

fn simm64(v: i64) -> String {
    if v < 0 {
        format!("-{:#x}", v.unsigned_abs())
    } else {
        format!("{:#x}", v)
    }
}

/// `(rN + 0x4)` or `(rN - 0x4)`: LLVM folds the sign into the operator.
fn memoff(r: u8, off: i16) -> String {
    if off < 0 {
        format!("({} - {:#x})", reg(r), (off as i32).unsigned_abs())
    } else {
        format!("({} + {:#x})", reg(r), off)
    }
}

fn joff(off: i32) -> String {
    if off < 0 {
        format!("-{:#x}", (off as i64).unsigned_abs())
    } else {
        format!("+{:#x}", off)
    }
}

fn size_name(sz: u8) -> &'static str {
    match sz {
        BPF_W => "u32",
        BPF_H => "u16",
        BPF_B => "u8",
        _ => "u64",
    }
}

fn size_name_signed(sz: u8) -> &'static str {
    match sz {
        BPF_W => "s32",
        BPF_H => "s16",
        BPF_B => "s8",
        _ => "s64",
    }
}

fn size_bits(sz: u8) -> u32 {
    match sz {
        BPF_W => 32,
        BPF_H => 16,
        BPF_B => 8,
        _ => 64,
    }
}

impl Insn {
    /// Decode one instruction starting at slot `idx` of `code_bytes`.
    ///
    /// Returns `None` only when there are fewer than eight bytes left, which
    /// is a truncated section rather than a bad instruction.
    pub fn decode(code_bytes: &[u8], idx: usize) -> Option<Insn> {
        let o = idx * 8;
        if o + 8 > code_bytes.len() {
            return None;
        }
        let b = &code_bytes[o..o + 8];
        let code = b[0];
        let dst = b[1] & 0xf;
        let src = b[1] >> 4;
        let off = i16::from_le_bytes([b[2], b[3]]);
        let imm = i32::from_le_bytes([b[4], b[5], b[6], b[7]]);

        let mut ins = Insn {
            idx,
            slots: 1,
            code,
            dst,
            src,
            off,
            imm,
            imm64: imm as i64,
            op: None,
            bad: None,
            defects: Vec::new(),
            bytes: b.to_vec(),
        };

        // The wide load is the one instruction whose length is not eight.
        if code == (BPF_LD | BPF_IMM | BPF_DW) {
            if o + 16 > code_bytes.len() {
                ins.bad = Some("truncated 16-byte immediate load".into());
                return Some(ins);
            }
            let t = &code_bytes[o + 8..o + 16];
            let hi = i32::from_le_bytes([t[4], t[5], t[6], t[7]]);
            ins.slots = 2;
            ins.bytes = code_bytes[o..o + 16].to_vec();
            ins.imm64 = ((hi as i64) << 32) | (imm as u32 as i64);
            if t[0] != 0 || t[1] != 0 || t[2] != 0 || t[3] != 0 {
                ins.defects.push(Defect::WideTailDirty);
            }
            if src > 6 {
                ins.bad = Some(format!("wide load with src {} (0..6 are defined)", src));
                return Some(ins);
            }
            ins.op = Some(Op::LdImm64 { pseudo: src });
            ins.check_regs();
            return Some(ins);
        }

        ins.classify();
        ins.check_regs();
        Some(ins)
    }

    fn check_regs(&mut self) {
        let uses_dst = !matches!(
            self.op,
            Some(Op::Exit) | Some(Op::Ja { .. }) | Some(Op::MayGoto) | Some(Op::Call { .. }) | None
        );
        let uses_src = match &self.op {
            Some(Op::Alu { reg, .. }) => *reg,
            Some(Op::Jmp { reg, .. }) => *reg,
            Some(Op::AddrSpaceCast)
            | Some(Op::Load { .. })
            | Some(Op::StoreReg { .. })
            | Some(Op::Atomic { .. })
            | Some(Op::LdInd { .. }) => true,
            _ => false,
        };
        if (uses_dst && self.dst > 10) || (uses_src && self.src > 10) {
            self.defects.push(Defect::RegOutOfRange);
        }
    }

    fn need_zero_off(&mut self) {
        if self.off != 0 {
            self.defects.push(Defect::OffNotZero);
        }
    }
    fn need_zero_imm(&mut self) {
        if self.imm != 0 {
            self.defects.push(Defect::ImmNotZero);
        }
    }
    fn need_zero_src(&mut self) {
        if self.src != 0 {
            self.defects.push(Defect::SrcNotZero);
        }
    }
    fn need_zero_dst(&mut self) {
        if self.dst != 0 {
            self.defects.push(Defect::DstNotZero);
        }
    }

    fn classify(&mut self) {
        let code = self.code;
        let class = code & 0x07;
        match class {
            BPF_ALU | BPF_ALU64 => self.classify_alu(class == BPF_ALU64),
            BPF_JMP | BPF_JMP32 => self.classify_jmp(class == BPF_JMP),
            BPF_LD => self.classify_ld(),
            BPF_LDX => self.classify_ldx(),
            BPF_ST => self.classify_st(),
            BPF_STX => self.classify_stx(),
            _ => unreachable!(),
        }
    }

    fn classify_alu(&mut self, wide: bool) {
        let code = self.code;
        let reg = code & BPF_X != 0;
        let bits = code & 0xf0;
        // BPF_END is 0xd0 and shares its bit pattern with nothing else.
        if bits == 0xd0 {
            let kind = match (wide, reg) {
                (false, false) => EndKind::Le,
                (false, true) => EndKind::Be,
                (true, false) => EndKind::Bswap,
                // ALU64 | END | BPF_X is not allocated. LLVM refuses it too.
                (true, true) => {
                    self.bad = Some("alu64 byte-swap with the source bit set is not allocated".into());
                    return;
                }
            };
            let width = match self.imm {
                16 | 32 | 64 => self.imm as u8,
                _ => {
                    self.bad = Some(format!(
                        "byte-swap width {} (16, 32 and 64 are the only widths)",
                        self.imm
                    ));
                    return;
                }
            };
            self.need_zero_off();
            self.op = Some(Op::End {
                kind,
                width: if width == 64 { 64 } else { width },
            });
            return;
        }
        let op = match AluOp::from_bits(bits) {
            Some(o) => o,
            None => {
                self.bad = Some(format!("no ALU operation for code {:#04x}", code));
                return;
            }
        };
        // Signed division and modulo reuse `off` as a one-bit selector; the
        // sign-extending move reuses it as a source width. Everything else
        // requires it to be zero.
        let mut signed = false;
        let mut sx = 0u8;
        match op {
            AluOp::Div | AluOp::Mod => match self.off {
                0 => {}
                1 => signed = true,
                _ => self.defects.push(Defect::OffNotZero),
            },
            AluOp::Mov if reg => match (self.off, wide) {
                (0, _) => {}
                // off == 1 on the 64-bit register move is not a move at all:
                // it is the address-space cast, and `imm` carries the two
                // address spaces rather than being required to be zero.
                (1, true) => {
                    self.op = Some(Op::AddrSpaceCast);
                    return;
                }
                (8, _) | (16, _) => sx = self.off as u8,
                (32, true) => sx = 32,
                _ => self.defects.push(Defect::OffNotZero),
            },
            AluOp::Neg => {
                if reg {
                    self.bad = Some(
                        "negate with the source bit set is not allocated; BPF_NEG is BPF_K only"
                            .into(),
                    );
                    return;
                }
                self.need_zero_off();
                self.need_zero_src();
                self.need_zero_imm();
            }
            _ => self.need_zero_off(),
        }
        if op != AluOp::Neg {
            if reg {
                self.need_zero_imm();
            } else {
                self.need_zero_src();
            }
        }
        self.op = Some(Op::Alu {
            op,
            wide,
            reg,
            signed,
            sx,
        });
    }

    fn classify_jmp(&mut self, wide: bool) {
        let code = self.code;
        let reg = code & BPF_X != 0;
        let bits = code & 0xf0;
        match bits {
            0x00 => {
                // BPF_JA. In the 64-bit class the target is `off`; in the
                // 32-bit class it is `imm`, which is the v4 long jump.
                if reg {
                    self.bad = Some("unconditional jump with the source bit set is not allocated".into());
                    return;
                }
                self.need_zero_dst();
                self.need_zero_src();
                if wide {
                    self.need_zero_imm();
                } else if self.off != 0 {
                    self.defects.push(Defect::OffNotZero);
                }
                self.op = Some(Op::Ja { long: !wide });
            }
            0x80 => {
                if !wide {
                    self.bad = Some(format!("no jump operation for code {:#04x}", code));
                    return;
                }
                if reg {
                    // BPF_JMP | BPF_CALL | BPF_X is `callx`, an indirect call
                    // through the destination register.
                    self.need_zero_off();
                    self.need_zero_imm();
                    self.need_zero_src();
                    self.op = Some(Op::CallX);
                    return;
                }
                // CALL. `src` selects helper, local subprogram, or kfunc.
                if self.src > 2 {
                    self.bad = Some(format!(
                        "call with src {} (0 helper, 1 subprogram, 2 kfunc)",
                        self.src
                    ));
                    return;
                }
                self.need_zero_dst();
                // A kfunc call carries the BTF fd in `off`; the other two
                // forms must leave it zero.
                if self.src != 2 {
                    self.need_zero_off();
                }
                self.op = Some(Op::Call { pseudo: self.src });
            }
            0x90 => {
                if !wide || reg {
                    self.bad = Some(format!("no jump operation for code {:#04x}", code));
                    return;
                }
                self.need_zero_dst();
                self.need_zero_src();
                self.need_zero_off();
                self.need_zero_imm();
                self.op = Some(Op::Exit);
            }
            0xe0 => {
                // may_goto, added for the bounded-loop helper.
                if reg || !wide {
                    self.bad = Some(format!("no jump operation for code {:#04x}", code));
                    return;
                }
                self.need_zero_dst();
                self.need_zero_src();
                self.need_zero_imm();
                self.op = Some(Op::MayGoto);
            }
            _ => {
                let cond = match Cond::from_bits(bits) {
                    Some(c) => c,
                    None => {
                        self.bad = Some(format!("no jump operation for code {:#04x}", code));
                        return;
                    }
                };
                if reg {
                    self.need_zero_imm();
                } else {
                    self.need_zero_src();
                }
                self.op = Some(Op::Jmp { cond, wide, reg });
            }
        }
    }

    fn classify_ld(&mut self) {
        let code = self.code;
        let mode = code & 0xe0;
        let size = code & 0x18;
        match mode {
            BPF_IMM => {
                // Only the DW form exists, and it was handled before this.
                self.bad = Some(format!(
                    "immediate load of size {} bits; only the 64-bit form is allocated",
                    size_bits(size)
                ));
            }
            BPF_ABS | BPF_IND => {
                if size == BPF_DW {
                    self.bad = Some("legacy packet access cannot be 64 bits wide".into());
                    return;
                }
                // The destination is always r0 and the other fields are
                // ignored by the kernel, but it requires them to be zero.
                self.need_zero_dst();
                self.need_zero_off();
                if mode == BPF_ABS {
                    self.need_zero_src();
                    self.op = Some(Op::LdAbs { size });
                } else {
                    self.op = Some(Op::LdInd { size });
                }
            }
            _ => {
                self.bad = Some(format!("no load mode {:#04x} in class BPF_LD", mode));
            }
        }
    }

    fn classify_ldx(&mut self) {
        let code = self.code;
        let mode = code & 0xe0;
        let size = code & 0x18;
        match mode {
            BPF_MEM => {
                self.need_zero_imm();
                self.op = Some(Op::Load { size, sx: false });
            }
            BPF_MEMSX => {
                if size == BPF_DW {
                    self.bad =
                        Some("a 64-bit load cannot sign-extend; BPF_MEMSX|BPF_DW is not allocated"
                            .into());
                    return;
                }
                self.need_zero_imm();
                self.op = Some(Op::Load { size, sx: true });
            }
            _ => self.bad = Some(format!("no load mode {:#04x} in class BPF_LDX", mode)),
        }
    }

    fn classify_st(&mut self) {
        let code = self.code;
        let mode = code & 0xe0;
        let size = code & 0x18;
        if mode != BPF_MEM {
            self.bad = Some(format!("no store mode {:#04x} in class BPF_ST", mode));
            return;
        }
        self.need_zero_src();
        self.op = Some(Op::StoreImm { size });
    }

    fn classify_stx(&mut self) {
        let code = self.code;
        let mode = code & 0xe0;
        let size = code & 0x18;
        match mode {
            BPF_MEM => {
                self.need_zero_imm();
                self.op = Some(Op::StoreReg { size });
            }
            BPF_ATOMIC => {
                if size != BPF_W && size != BPF_DW {
                    self.bad = Some(format!(
                        "atomic operations are 32 or 64 bits wide, not {}",
                        size_bits(size)
                    ));
                    return;
                }
                let fetch = self.imm & 0x01 != 0;
                let base = self.imm & !0x01;
                let aop = match base {
                    0x00 => AtomicOp::Add,
                    0x40 => AtomicOp::Or,
                    0x50 => AtomicOp::And,
                    0xa0 => AtomicOp::Xor,
                    0xe0 => AtomicOp::Xchg,
                    0xf0 => AtomicOp::CmpXchg,
                    _ => {
                        self.bad =
                            Some(format!("no atomic operation for imm {:#x}", self.imm));
                        return;
                    }
                };
                // Exchange and compare-exchange always fetch; the kernel
                // encodes that in the same bit and rejects it unset.
                if matches!(aop, AtomicOp::Xchg | AtomicOp::CmpXchg) && !fetch {
                    self.bad = Some(format!(
                        "atomic {} without the fetch bit is not allocated",
                        aop.name()
                    ));
                    return;
                }
                self.op = Some(Op::Atomic { size, aop, fetch });
            }
            _ => self.bad = Some(format!("no store mode {:#04x} in class BPF_STX", mode)),
        }
    }

    /// The instruction in LLVM's BPF assembly syntax.
    pub fn text(&self) -> String {
        let mut s = String::new();
        let op = match &self.op {
            Some(o) => o,
            None => {
                let _ = write!(s, "(bad) {:#04x}", self.code);
                return s;
            }
        };
        match op {
            Op::Alu {
                op: a,
                wide,
                reg: isreg,
                signed,
                sx,
            } => {
                let d = if *wide { reg(self.dst) } else { reg32(self.dst) };
                let rhs = if *isreg {
                    if *wide {
                        reg(self.src)
                    } else {
                        reg32(self.src)
                    }
                } else {
                    simm(self.imm)
                };
                match a {
                    AluOp::Neg => {
                        let _ = write!(s, "{} = -{}", d, d);
                    }
                    AluOp::Mov if *sx != 0 => {
                        let _ = write!(s, "{} = (s{}){}", d, sx, rhs);
                    }
                    AluOp::Mov => {
                        let _ = write!(s, "{} = {}", d, rhs);
                    }
                    _ => {
                        let _ = write!(s, "{} {}= {}", d, a.sym(*signed), rhs);
                    }
                }
            }
            Op::End { kind, width } => {
                let n = match kind {
                    EndKind::Le => "le",
                    EndKind::Be => "be",
                    EndKind::Bswap => "bswap",
                };
                let d = reg(self.dst);
                let _ = write!(s, "{} = {}{} {}", d, n, width, d);
            }
            Op::Jmp {
                cond,
                wide,
                reg: isreg,
            } => {
                let d = if *wide { reg(self.dst) } else { reg32(self.dst) };
                let rhs = if *isreg {
                    if *wide {
                        reg(self.src)
                    } else {
                        reg32(self.src)
                    }
                } else {
                    simm(self.imm)
                };
                let _ = write!(
                    s,
                    "if {} {} {} goto {}",
                    d,
                    cond.sym(),
                    rhs,
                    joff(self.off as i32)
                );
            }
            Op::Ja { long } => {
                if *long {
                    let _ = write!(s, "gotol {}", joff(self.imm));
                } else {
                    let _ = write!(s, "goto {}", joff(self.off as i32));
                }
            }
            Op::AddrSpaceCast => {
                let _ = write!(
                    s,
                    "{} = addr_space_cast({}, {}, {})",
                    reg(self.dst),
                    reg(self.src),
                    (self.imm as u32) >> 16,
                    (self.imm as u32) & 0xffff
                );
            }
            Op::MayGoto => {
                let _ = write!(s, "may_goto {}", joff(self.off as i32));
            }
            Op::Call { pseudo } => match pseudo {
                // A local call's immediate is a relative instruction offset,
                // not a helper number. LLVM's printer renders both as
                // `call N`, which erases the distinction; see the README.
                1 => {
                    let _ = write!(s, "call pc{}", joff(self.imm));
                }
                2 => {
                    let _ = write!(s, "callkf {}", simm(self.imm));
                }
                _ => {
                    let _ = write!(s, "call {}", simm(self.imm));
                }
            },
            Op::CallX => {
                let _ = write!(s, "callx {}", reg(self.dst));
            }
            Op::Exit => s.push_str("exit"),
            Op::Load { size, sx } => {
                let t = if *sx {
                    size_name_signed(*size)
                } else {
                    size_name(*size)
                };
                let _ = write!(
                    s,
                    "{} = *({} *){}",
                    reg(self.dst),
                    t,
                    memoff(self.src, self.off)
                );
            }
            Op::StoreImm { size } => {
                let _ = write!(
                    s,
                    "*({} *){} = {}",
                    size_name(*size),
                    memoff(self.dst, self.off),
                    simm(self.imm)
                );
            }
            Op::StoreReg { size } => {
                let _ = write!(
                    s,
                    "*({} *){} = {}",
                    size_name(*size),
                    memoff(self.dst, self.off),
                    reg(self.src)
                );
            }
            Op::Atomic { size, aop, fetch } => {
                // The 32-bit forms name their value register `w`, and their
                // exchanges are spelled xchg32_32 and cmpxchg32_32. Both are
                // taken from what `llvm-mc` ASSEMBLES, which disagrees with
                // what `llvm-objdump` prints for the same bytes; see the
                // round-trip section of the README.
                let t = size_name(*size);
                let narrow = *size == BPF_W;
                let v = |r: u8| if narrow { reg32(r) } else { reg(r) };
                let w = if narrow { "32_32" } else { "_64" };
                match aop {
                    AtomicOp::Xchg => {
                        let _ = write!(
                            s,
                            "{} = xchg{}({}{}, {})",
                            v(self.src),
                            w,
                            reg(self.dst),
                            offsuffix(self.off),
                            v(self.src)
                        );
                    }
                    AtomicOp::CmpXchg => {
                        let _ = write!(
                            s,
                            "{} = cmpxchg{}({}{}, {}, {})",
                            v(0),
                            w,
                            reg(self.dst),
                            offsuffix(self.off),
                            v(0),
                            v(self.src)
                        );
                    }
                    _ if *fetch => {
                        let _ = write!(
                            s,
                            "{} = atomic_fetch_{}(({} *){}, {})",
                            v(self.src),
                            aop.name(),
                            t,
                            memoff(self.dst, self.off),
                            v(self.src)
                        );
                    }
                    _ => {
                        let _ = write!(
                            s,
                            "lock *({} *){} {} {}",
                            t,
                            memoff(self.dst, self.off),
                            aop.sym(),
                            v(self.src)
                        );
                    }
                }
            }
            Op::LdImm64 { pseudo } => {
                if *pseudo == 0 {
                    let _ = write!(s, "{} = {} ll", reg(self.dst), simm64(self.imm64));
                } else {
                    // LLVM prints this as `ld_pseudo dst, src, imm`. Keep its
                    // text so the comparison stays exact, and name the kind
                    // in the annotation column instead.
                    let _ = write!(
                        s,
                        "ld_pseudo {}, {}, {}",
                        reg(self.dst),
                        pseudo,
                        self.imm
                    );
                }
            }
            Op::LdAbs { size } => {
                let _ = write!(s, "r0 = *({} *)skb[{}]", size_name(*size), simm(self.imm));
            }
            Op::LdInd { size } => {
                let _ = write!(
                    s,
                    "r0 = *({} *)skb[{}]",
                    size_name(*size),
                    reg(self.src)
                );
            }
        }
        s
    }
}

/// ` + 0x4` / ` - 0x4`, the form LLVM uses inside `xchg_64(r1 + 3, r2)`.
fn offsuffix(off: i16) -> String {
    if off < 0 {
        format!(" - {:#x}", (off as i32).unsigned_abs())
    } else {
        format!(" + {:#x}", off)
    }
}

/// Decode a whole instruction stream.
///
/// A trailing fragment shorter than eight bytes is reported rather than
/// ignored: it is the shape of a truncated section and the kernel refuses it.
pub fn decode_all(code: &[u8]) -> (Vec<Insn>, Option<String>) {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i * 8 + 8 <= code.len() {
        match Insn::decode(code, i) {
            Some(ins) => {
                i += ins.slots;
                out.push(ins);
            }
            None => break,
        }
    }
    let tail = code.len() - i * 8;
    let err = if tail != 0 {
        Some(format!(
            "{} trailing bytes: the section is not a whole number of instructions",
            tail
        ))
    } else {
        None
    };
    (out, err)
}
