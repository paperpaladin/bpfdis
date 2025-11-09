// Name tables exist in full even where only part of each is reached by the
// current modes; that is deliberate, they are the format written down.
#![allow(dead_code)]

mod elf;
mod insn;

use elf::Elf;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::ExitCode;

const USAGE: &str = "\
usage: bpfdis [MODE...] FILE

  -S, --sections    the ELF section table
  -y, --symbols     the symbol table
  -r, --relocs      relocations, resolved against the symbol table
  -d, --disasm      every executable section, one line per instruction
      --raw         with -d, also print the raw bytes of each instruction
  -x, --hex         read hex-encoded instructions from stdin, one per line,
                    and decode each on its own: the raw-encoding entry point
  -A, --all         every mode above
  -h, --help        this text

exit: 0 clean, 1 malformed input, 2 usage error
";

#[derive(Default)]
struct Modes {
    sections: bool,
    symbols: bool,
    relocs: bool,
    disasm: bool,
    raw: bool,
}

impl Modes {
    fn any(&self) -> bool {
        self.sections || self.symbols || self.relocs || self.disasm
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut m = Modes::default();
    let mut hexmode = false;
    let mut path: Option<String> = None;
    for a in &args {
        match a.as_str() {
            "-S" | "--sections" => m.sections = true,
            "-y" | "--symbols" => m.symbols = true,
            "-r" | "--relocs" => m.relocs = true,
            "-d" | "--disasm" => m.disasm = true,
            "-x" | "--hex" => hexmode = true,
            "--raw" => m.raw = true,
            "-A" | "--all" => {
                m.sections = true;
                m.symbols = true;
                m.relocs = true;
                m.disasm = true;
            }
            "-h" | "--help" => {
                print!("{}", USAGE);
                return ExitCode::from(0);
            }
            s if s.starts_with('-') && s.len() > 1 => {
                eprintln!("bpfdis: unknown option {}", s);
                eprint!("{}", USAGE);
                return ExitCode::from(2);
            }
            s => {
                if path.is_some() {
                    eprintln!("bpfdis: more than one FILE given");
                    return ExitCode::from(2);
                }
                path = Some(s.to_string());
            }
        }
    }
    if hexmode {
        return hex_mode();
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprint!("{}", USAGE);
            return ExitCode::from(2);
        }
    };
    if !m.any() {
        m.sections = true;
    }

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("bpfdis: {}: {}", path, e);
            return ExitCode::from(1);
        }
    };
    let e = match Elf::parse(data) {
        Ok(e) => e,
        Err(msg) => {
            eprintln!("bpfdis: {}: {}", path, msg);
            return ExitCode::from(1);
        }
    };
    for w in &e.warnings {
        eprintln!("bpfdis: {}: warning: {}", path, w);
    }
    let mut o = String::new();
    if m.sections {
        print_sections(&mut o, &e);
    }
    if m.symbols {
        print_symbols(&mut o, &e);
    }
    if m.relocs {
        print_relocs(&mut o, &e);
    }
    if m.disasm {
        print_disasm(&mut o, &e, m.raw);
    }
    emit(&o);
    ExitCode::from(0)
}

/// Write the whole report in one go.
///
/// Rust ignores SIGPIPE, so a closed stdout (`bpfdis -A x.o | head`) surfaces
/// as an `EPIPE` from `write_all` rather than as a signal. Treating it as a
/// clean exit matters here: with `panic = "abort"` the default behaviour is a
/// SIGABRT, and the robustness sweep reads exit statuses.
fn emit(s: &str) {
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    if h.write_all(s.as_bytes()).is_err() || h.flush().is_err() {
        std::process::exit(0);
    }
}

fn print_sections(o: &mut String, e: &Elf) {
    let _ = writeln!(o, "sections: {}", e.sections.len());
    for s in &e.sections {
        let _ = writeln!(
            o,
            "[{:2}] name={} type={} flags={} addr={:#x} off={:#x} size={:#x} \
             link={} info={} align={} entsize={}",
            s.idx,
            if s.name.is_empty() { "-" } else { &s.name },
            elf::sht_name(s.sh_type),
            {
                let f = elf::shf_string(s.flags);
                if f.is_empty() {
                    "-".to_string()
                } else {
                    f
                }
            },
            s.addr,
            s.offset,
            s.size,
            s.link,
            s.info,
            s.addralign,
            s.entsize
        );
    }
}

fn print_symbols(o: &mut String, e: &Elf) {
    let _ = writeln!(o, "symbols: {}", e.syms.len());
    for y in &e.syms {
        let _ = writeln!(
            o,
            "[{:3}] name={} type={} bind={} shndx={} value={:#x} size={:#x}",
            y.idx,
            if y.name.is_empty() { "-" } else { &y.name },
            elf::stt_name(y.stype()),
            elf::stb_name(y.bind()),
            match y.shndx {
                0 => "UND".to_string(),
                0xfff1 => "ABS".to_string(),
                0xfff2 => "COMMON".to_string(),
                n => n.to_string(),
            },
            y.value,
            y.size
        );
    }
}

fn print_relocs(o: &mut String, e: &Elf) {
    let _ = writeln!(o, "relocs: {}", e.relocs.len());
    for r in &e.relocs {
        let sec = e
            .sections
            .get(r.target_sec)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| format!("<sec {}>", r.target_sec));
        let _ = writeln!(
            o,
            "sec={} off={:#x} type={} sym={} addend={}",
            sec,
            r.offset,
            elf::r_bpf_name(r.rtype),
            if r.sym_name.is_empty() {
                "-"
            } else {
                &r.sym_name
            },
            r.addend
        );
    }
}

/// Disassembly, one line per instruction.
///
/// The index is the 8-byte slot number inside the section, so a 16-byte
/// immediate load makes the next index jump by two. `llvm-objdump` numbers
/// them the same way, which is what lets the two outputs be lined up
/// instruction by instruction rather than line by line.
fn print_disasm(o: &mut String, e: &Elf, raw: bool) {
    for s in e.text_sections() {
        let code = s.data(&e.file);
        let (ins, err) = insn::decode_all(code);
        let _ = writeln!(
            o,
            "section {} slots={} insns={}",
            s.name,
            code.len() / 8,
            ins.len()
        );
        for i in &ins {
            if raw {
                let mut hex = String::new();
                for b in &i.bytes {
                    let _ = write!(hex, "{:02x} ", b);
                }
                let _ = writeln!(o, "{:6}:\t{:<49}{}", i.idx, hex.trim_end(), i.text());
            } else {
                let _ = writeln!(o, "{:6}:\t{}", i.idx, i.text());
            }
        }
        if let Some(msg) = err {
            let _ = writeln!(o, "  ! {}", msg);
        }
    }
}

/// Decode instructions given as hex bytes on stdin, one instruction per line.
///
/// This is how the opcode sweep reaches encodings no compiler emits. Each
/// line is decoded in isolation, so nothing about the neighbouring lines can
/// change the answer, and the output has exactly one line per input line
/// whether the encoding decoded or not:
///
/// ```text
///   <lineno>\tOK\t<text>\t<defects or ->
///   <lineno>\tBAD\t<reason>\t-
/// ```
fn hex_mode() -> ExitCode {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut o = String::new();
    let mut lineno = 0usize;
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("bpfdis: stdin: {}", e);
                return ExitCode::from(1);
            }
        };
        lineno += 1;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut bytes = Vec::new();
        let mut okparse = true;
        for tok in t.split(|c: char| c == ',' || c.is_whitespace()) {
            if tok.is_empty() {
                continue;
            }
            let tok = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")).unwrap_or(tok);
            match u8::from_str_radix(tok, 16) {
                Ok(b) => bytes.push(b),
                Err(_) => {
                    okparse = false;
                    break;
                }
            }
        }
        if !okparse || bytes.len() < 8 {
            let _ = writeln!(o, "{}\tBAD\tnot 8 or 16 hex bytes\t-", lineno);
            continue;
        }
        match insn::Insn::decode(&bytes, 0) {
            Some(i) => {
                if i.slots * 8 != bytes.len() {
                    let _ = writeln!(
                        o,
                        "{}\tBAD\tline holds {} bytes, the instruction is {}\t-",
                        lineno,
                        bytes.len(),
                        i.slots * 8
                    );
                    continue;
                }
                match &i.bad {
                    Some(r) => {
                        let _ = writeln!(o, "{}\tBAD\t{}\t-", lineno, r);
                    }
                    None => {
                        let d = if i.defects.is_empty() {
                            "-".to_string()
                        } else {
                            let mut v: Vec<&str> = i.defects.iter().map(|d| d.name()).collect();
                            v.sort_unstable();
                            v.dedup();
                            v.join(",")
                        };
                        let _ = writeln!(o, "{}\tOK\t{}\t{}", lineno, i.text(), d);
                    }
                }
            }
            None => {
                let _ = writeln!(o, "{}\tBAD\tfewer than 8 bytes\t-", lineno);
            }
        }
    }
    emit(&o);
    ExitCode::from(0)
}
