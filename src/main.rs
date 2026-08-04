// Name tables exist in full even where only part of each is reached by the
// current modes; that is deliberate, they are the format written down.
#![allow(dead_code)]

mod elf;
mod insn;
mod prog;
mod btf;
mod btfext;
mod maps;
mod cfg;

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
  -c, --cfg         basic blocks and control-flow edges, per function
  -a, --analyse     the verifier-relevant report, per function
      --strict      with -a, exit 3 if any finding would be a rejection
  -P, --progs       the programs libbpf would find: name, section, length
  -m, --maps        map definitions, legacy and BTF-defined
  -b, --btf         the .BTF type section, in bpftool's own dump format
  -e, --btfext      the .BTF.ext section: func_info, line_info, CO-RE relocs
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
    btf: bool,
    btfext: bool,
    maps: bool,
    progs: bool,
    cfg: bool,
    analyse: bool,
    strict: bool,
}

impl Modes {
    fn any(&self) -> bool {
        self.sections || self.symbols || self.relocs || self.disasm || self.btf || self.btfext || self.maps || self.progs || self.cfg || self.analyse
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
            "-b" | "--btf" => m.btf = true,
            "-e" | "--btfext" => m.btfext = true,
            "-m" | "--maps" => m.maps = true,
            "-P" | "--progs" => m.progs = true,
            "-c" | "--cfg" => m.cfg = true,
            "-a" | "--analyse" | "--analyze" => m.analyse = true,
            "--strict" => m.strict = true,
            "-x" | "--hex" => hexmode = true,
            "--raw" => m.raw = true,
            "-A" | "--all" => {
                m.sections = true;
                m.symbols = true;
                m.relocs = true;
                m.disasm = true;
                m.btf = true;
                m.btfext = true;
                m.maps = true;
                m.progs = true;
                m.cfg = true;
                m.analyse = true;
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
    if m.progs {
        // A program is a function in an executable section other than
        // `.text`; `.text` holds the subprograms those entry points call.
        // That is libbpf's rule, and `t/libbpfcmp.py` holds it to it.
        let ps = prog::programs(&e);
        let mut n = 0;
        let mut body = String::new();
        for p in &ps {
            if p.name == ".text" {
                continue;
            }
            let (ty, tyname) = prog::prog_type(&p.name);
            for f in &p.funcs {
                n += 1;
                let _ = writeln!(
                    body,
                    "prog {} sec={} type={} ({}) insns={}",
                    f.name,
                    p.name,
                    ty,
                    tyname,
                    f.end - f.start
                );
            }
        }
        let _ = writeln!(o, "progs: {}", n);
        o.push_str(&body);
    }
    if m.maps {
        let ms = maps::maps(&e);
        let _ = writeln!(o, "maps: {}", ms.len());
        for d in &ms {
            let _ = writeln!(
                o,
                "map {} source={} type={} ({}) key_size={} value_size={} \
                 max_entries={} flags={} btf_key={} btf_value={}",
                d.name,
                d.source,
                d.mtype,
                maps::map_type_name(d.mtype),
                d.key_size,
                d.value_size,
                d.max_entries,
                d.flags,
                d.btf_key,
                d.btf_value
            );
            for n in &d.notes {
                let _ = writeln!(o, "  ! {}", n);
            }
        }
    }
    if m.btf {
        match e.section_by_name(".BTF") {
            Some(s) => match btf::Btf::parse(s.data(&e.file)) {
                Ok(b) => b.dump(&mut o),
                Err(msg) => {
                    eprintln!("bpfdis: {}: .BTF: {}", path, msg);
                    emit(&o);
                    return ExitCode::from(1);
                }
            },
            None => eprintln!("bpfdis: {}: no .BTF section", path),
        }
    }
    if m.btfext {
        // The strings .BTF.ext points at live in .BTF, so one without the
        // other is unreadable. Say that rather than printing offsets.
        match (e.section_by_name(".BTF.ext"), e.section_by_name(".BTF")) {
            (Some(x), Some(b)) => {
                let r = btf::Btf::parse(b.data(&e.file)).and_then(|btf| {
                    btfext::BtfExt::parse(x.data(&e.file), &btf.strings)
                        .map(|x| (btf, x))
                });
                match r {
                    Ok((btf, x)) => x.dump(&mut o, &btf),
                    Err(msg) => {
                        eprintln!("bpfdis: {}: .BTF.ext: {}", path, msg);
                        emit(&o);
                        return ExitCode::from(1);
                    }
                }
            }
            (Some(_), None) => {
                eprintln!("bpfdis: {}: .BTF.ext with no .BTF: its strings are in .BTF", path);
                emit(&o);
                return ExitCode::from(1);
            }
            (None, _) => eprintln!("bpfdis: {}: no .BTF.ext section", path),
        }
    }
    let mut rejects = 0usize;
    if m.cfg || m.analyse {
        rejects = print_analysis(&mut o, &e, m.cfg, m.analyse);
    }
    emit(&o);
    if m.strict && rejects > 0 {
        return ExitCode::from(3);
    }
    ExitCode::from(0)
}

/// The control-flow graph and the report, per function.
///
/// Returns the number of findings that would be a rejection, which is what
/// `--strict` turns into an exit status.
fn print_analysis(o: &mut String, e: &Elf, want_cfg: bool, want_report: bool) -> usize {
    let mut rejects = 0usize;
    for p in prog::programs(e) {
        for f in &p.funcs {
            // A function in `.text` is a subprogram: it is called rather
            // than entered, so its argument registers arrive live.
            let is_subprog = p.name == ".text";
            let mut c = cfg::build(&p, f);
            cfg::analyse(&mut c, &p, is_subprog);
            let nedges: usize = c.blocks.iter().map(|b| b.succs.len()).sum();
            let nreach = c.reachable.iter().filter(|&&r| r).count();
            if want_cfg {
                let _ = writeln!(
                    o,
                    "cfg {} {} blocks={} edges={} reachable={} insns={}",
                    p.name,
                    f.name,
                    c.blocks.len(),
                    nedges,
                    nreach,
                    c.insns_seen
                );
                for (bi, b) in c.blocks.iter().enumerate() {
                    let mut ss: Vec<String> =
                        b.succs.iter().map(|&s| c.blocks[s].start.to_string()).collect();
                    ss.dedup();
                    let _ = writeln!(
                        o,
                        "block {}..{} term={:?} reach={} succs={}",
                        b.start,
                        b.end,
                        b.term,
                        if c.reachable[bi] { 1 } else { 0 },
                        if ss.is_empty() { "-".into() } else { ss.join(",") }
                    );
                }
            }
            if want_report {
                let loops = c
                    .problems
                    .iter()
                    .filter(|x| matches!(x, cfg::Problem::BackEdge { .. }))
                    .count();
                // Number and name together: the number is what the
                // instruction holds and the name is what it means, and a
                // helper this build has no name for prints as the number
                // alone rather than as a guess.
                let helpers: Vec<String> = c
                    .helpers
                    .iter()
                    .map(|h| match cfg::helper_name(*h) {
                        Some(n) => format!("{}({})", h, n),
                        None => h.to_string(),
                    })
                    .collect();
                let _ = writeln!(
                    o,
                    "analysis {} {} insns={} blocks={} stack={} stack8={} loops={} \
                     calls={} helpers={}",
                    p.name,
                    f.name,
                    c.insns_seen,
                    c.blocks.len(),
                    c.stack_bytes,
                    (c.stack_bytes + 7) / 8 * 8,
                    loops,
                    c.calls.len(),
                    if helpers.is_empty() {
                        "-".to_string()
                    } else {
                        helpers.join(",")
                    }
                );
                for pr in &c.problems {
                    if pr.severity() == "reject" {
                        rejects += 1;
                    }
                    let _ = writeln!(o, "  {}: {}", pr.severity(), pr.describe());
                }
            }
        }
    }
    rejects
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
///
/// A relocation that lands on an instruction is printed after it as a
/// comment. Without it, the 16-byte load of a map is the constant zero.
fn print_disasm(o: &mut String, e: &Elf, raw: bool) {
    for p in prog::programs(e) {
        let _ = writeln!(
            o,
            "section {} slots={} insns={} funcs={}",
            p.name,
            p.slots,
            p.insns.len(),
            p.funcs.len()
        );
        let mut fi = 0usize;
        for i in &p.insns {
            while fi < p.funcs.len() && p.funcs[fi].start <= i.idx {
                let f = &p.funcs[fi];
                let _ = writeln!(
                    o,
                    "func {} {} slots={}..{}",
                    f.name,
                    if f.global { "global" } else { "local" },
                    f.start,
                    f.end
                );
                fi += 1;
            }
            // llvm-objdump annotates a jump with the symbol its target
            // falls inside and the byte offset into it. That annotation is
            // LLVM's own computation of the branch target, so printing the
            // same thing gives the control-flow graph an oracle for every
            // edge, which is otherwise the part of this program with no
            // outside authority at all.
            let tgt = match cfg::jump_target(i) {
                Some(t) if t >= 0 => p.func_of(t as usize).map(|f| {
                    let off = (t as usize - f.start) * 8;
                    if off == 0 {
                        format!(" <{}>", f.name)
                    } else {
                        format!(" <{}+{:#x}>", f.name, off)
                    }
                }),
                _ => None,
            };
            let tgt = tgt.unwrap_or_default();
            let ann = match p.reloc_at(i.idx) {
                Some(r) => format!("\t; {} {}", elf::r_bpf_name(r.rtype), r.sym_name),
                None => String::new(),
            };
            if raw {
                let mut hex = String::new();
                for b in &i.bytes {
                    let _ = write!(hex, "{:02x} ", b);
                }
                let _ = writeln!(
                    o,
                    "{:6}:\t{:<49}{}{}{}",
                    i.idx,
                    hex.trim_end(),
                    i.text(),
                    tgt,
                    ann
                );
            } else {
                let _ = writeln!(o, "{:6}:\t{}{}{}", i.idx, i.text(), tgt, ann);
            }
        }
        if let Some(msg) = &p.tail_err {
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
