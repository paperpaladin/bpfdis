// Name tables exist in full even where only part of each is reached by the
// current modes; that is deliberate, they are the format written down.
#![allow(dead_code)]

mod elf;

use elf::Elf;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::ExitCode;

const USAGE: &str = "\
usage: bpfdis [MODE...] FILE

  -S, --sections    the ELF section table
  -y, --symbols     the symbol table
  -r, --relocs      relocations, resolved against the symbol table
  -A, --all         every mode above
  -h, --help        this text

exit: 0 clean, 1 malformed input, 2 usage error
";

#[derive(Default)]
struct Modes {
    sections: bool,
    symbols: bool,
    relocs: bool,
}

impl Modes {
    fn any(&self) -> bool {
        self.sections || self.symbols || self.relocs
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut m = Modes::default();
    let mut path: Option<String> = None;
    for a in &args {
        match a.as_str() {
            "-S" | "--sections" => m.sections = true,
            "-y" | "--symbols" => m.symbols = true,
            "-r" | "--relocs" => m.relocs = true,
            "-A" | "--all" => {
                m.sections = true;
                m.symbols = true;
                m.relocs = true;
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
