mod process;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const EXPORTS: &[&str] = &[
    "cpuid_configure_profile",
    "cpuid_activate_dispatch_profile",
    "cpuid_get_fixed_reply",
    "cpuid_sigsegv_handler",
    "detect_cpu_vendor",
    "sigaction",
    "free",
    "unsetenv",
    "linuwux_setup_hooks",
    "forward_signal",
    "reflex_handle_cpuid",
    "reflex_route_syscall",
    "syscallhook",
    "kuser_apply_to_buffer",
    "patch_kuser_shared_data_profile",
    "patch_kuser_shared_data",
    "gettimeofday",
    "set_offset",
    "linuwux_setup_faketime",
    "setenv",
    "debug_enabled",
    "debug_runtime_activated",
    "debug_log",
    "debug_log_hex",
    "debug_log_dec",
];
const ANCHORS: &[&str] = &[
    "linuwux_setup_debug",
    "linuwux_setup_gamescope",
    "linuwux_setup_environment",
    "linuwux_setup_faketime",
    "linuwux_setup_hooks",
    "linuwux_setup_kuser",
];

struct Context {
    root: PathBuf,
    target: PathBuf,
    scratch: TempDir,
    debug: bool,
    cargo: OsString,
    cc: OsString,
}

impl Context {
    fn cargo(&self) -> Command {
        let mut cmd = Command::new(&self.cargo);
        cmd.current_dir(&self.root);
        cmd
    }

    fn archive(&self, features: Option<&str>) -> Result<PathBuf> {
        let mut cmd = self.cargo();
        cmd.args([
            "build",
            "--locked",
            "-p",
            "linuwux-runtime",
            "--message-format=json-render-diagnostics",
        ]);
        let target = if let Some(features) = features {
            cmd.args(["--no-default-features", "--features", features]);
            self.scratch.path().join("component-target")
        } else {
            self.target.clone()
        };
        cmd.arg("--target-dir").arg(&target);
        if !self.debug {
            cmd.arg("--release");
        }
        let output = process::checked(&mut cmd)?;
        for line in output.stdout.split(|&b| b == b'\n') {
            let Ok(message) = serde_json::from_slice::<serde_json::Value>(line) else {
                continue;
            };
            if message["reason"] == "compiler-artifact"
                && message["target"]["name"] == "linuwux_runtime"
                && let Some(files) = message["filenames"].as_array()
                && let Some(file) = files
                    .iter()
                    .filter_map(|v| v.as_str())
                    .find(|p| p.ends_with(".a"))
            {
                return Ok(PathBuf::from(file));
            }
        }
        Err("Cargo did not report the runtime static archive".into())
    }

    fn compiler(&self) -> Command {
        let mut cmd = Command::new(&self.cc);
        cmd.current_dir(&self.root).args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wl,-z,now",
        ]);
        cmd
    }

    fn finish_link(&self, cmd: &mut Command, output: &Path) -> Result<()> {
        cmd.args(["-ldl", "-lpthread", "-lm", "-o"]).arg(output);
        process::checked(cmd)?;
        Ok(())
    }

    fn export_map(&self) -> Result<PathBuf> {
        let map = self.scratch.path().join("exports.map");
        fs::write(
            &map,
            format!(
                "{{\n global:\n{} local: *;\n}};\n",
                EXPORTS
                    .iter()
                    .map(|name| format!(" {name};\n"))
                    .collect::<String>()
            ),
        )?;
        Ok(map)
    }

    fn build(&self, output: &Path) -> Result<()> {
        let archive = self.archive(None)?;
        let map = self.export_map()?;
        let library = self.scratch.path().join("LinUwUx.so");
        let mut cmd = self.compiler();
        cmd.args([
            "-shared",
            "-fPIC",
            "-Wl,--gc-sections",
            "-Wl,-z,relro,-z,now,-z,nodelete,-z,noexecstack,-z,defs",
        ]);
        for anchor in ANCHORS {
            cmd.arg(format!("-Wl,-u,{anchor}"));
        }
        cmd.arg(format!("-Wl,--version-script={}", map.display()))
            .arg(archive);
        self.finish_link(&mut cmd, &library)?;
        verify_constructors(&library)?;
        if !self.debug {
            process::checked(Command::new("strip").arg("--strip-unneeded").arg(&library))?;
        }
        verify_elf(&library)?;
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = tempfile::NamedTempFile::new_in(parent)?;
        fs::copy(&library, temporary.path())?;
        temporary.persist(output)?;
        println!(
            "Built {} ({} bytes, {} C ABI exports)",
            output.display(),
            fs::metadata(output)?.len(),
            EXPORTS.len()
        );
        Ok(())
    }
}

fn verify_elf(library: &Path) -> Result<()> {
    let output = process::checked(
        Command::new("nm")
            .args(["-D", "--defined-only"])
            .arg(library),
    )?;
    let text = String::from_utf8(output.stdout)?;
    let actual: BTreeSet<_> = text
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .collect();
    let expected: BTreeSet<_> = EXPORTS.iter().copied().collect();
    if actual != expected {
        return Err(format!(
            "export mismatch: missing {:?}, extra {:?}",
            expected.difference(&actual),
            actual.difference(&expected)
        )
        .into());
    }
    let output = process::checked(
        Command::new("readelf")
            .args(["-W", "-h", "-l", "-d"])
            .arg(library),
    )?;
    let elf = String::from_utf8(output.stdout)?;
    for required in [
        "ELF64",
        "DYN",
        "X86-64",
        "GNU_RELRO",
        "BIND_NOW",
        "NODELETE",
        "INIT_ARRAY",
    ] {
        if !elf.contains(required) {
            return Err(format!("ELF missing {required}").into());
        }
    }
    let stack = elf
        .lines()
        .find(|line| line.contains("GNU_STACK"))
        .ok_or("ELF missing stack policy")?;
    if stack.split_whitespace().any(|word| word.contains('E')) || elf.contains("TEXTREL") {
        return Err("executable stack or text relocation in preload artifact".into());
    }
    Ok(())
}

fn verify_constructors(library: &Path) -> Result<()> {
    let symbols = process::checked(Command::new("nm").arg("--defined-only").arg(library))?;
    let mut addresses = BTreeMap::new();
    for line in String::from_utf8(symbols.stdout)?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() == 3 && ANCHORS.contains(&fields[2]) {
            addresses.insert(fields[2].to_owned(), u64::from_str_radix(fields[0], 16)?);
        }
    }
    let sections = process::checked(Command::new("readelf").args(["-W", "-S"]).arg(library))?;
    let sections = String::from_utf8(sections.stdout)?;
    let row = sections
        .lines()
        .find(|line| line.contains(".init_array "))
        .ok_or("missing constructor section")?;
    let fields: Vec<_> = row.split_whitespace().collect();
    let index = fields
        .iter()
        .position(|&s| s == ".init_array")
        .ok_or("missing constructor section name")?;
    let start = u64::from_str_radix(fields.get(index + 2).ok_or("missing section address")?, 16)?;
    let size = u64::from_str_radix(fields.get(index + 4).ok_or("missing section size")?, 16)?;
    let relocations = process::checked(Command::new("readelf").args(["-W", "-r"]).arg(library))?;
    let mut constructors = BTreeMap::new();
    for line in String::from_utf8(relocations.stdout)?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let Ok(offset) = u64::from_str_radix(fields[0], 16) else {
            continue;
        };
        if offset < start || offset >= start + size {
            continue;
        }
        let value = match fields[2] {
            "R_X86_64_RELATIVE" | "R_X86_64_64" => u64::from_str_radix(fields[3], 16)?,
            kind => return Err(format!("unsupported constructor relocation {kind}").into()),
        };
        constructors.insert(offset, value);
    }
    let actual: Vec<_> = constructors
        .values()
        .filter_map(|address| {
            addresses
                .iter()
                .find(|(_, value)| *value == address)
                .map(|(name, _)| name.as_str())
        })
        .collect();
    if actual != ANCHORS {
        return Err(format!("constructor order mismatch: {actual:?}").into());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    if command == "help" || command == "--help" {
        println!("cargo xtask build [--debug] [--output PATH]");
        return Ok(());
    }
    if !cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu"
    )) {
        return Err("requires Linux x86-64 with glibc".into());
    }
    let mut debug = false;
    let mut output = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--debug") => debug = true,
            Some("--output") => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a path")?,
                ))
            }
            _ => return Err(format!("unknown argument {arg:?}").into()),
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("missing workspace root")?
        .to_owned();
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let metadata = process::checked(Command::new(&cargo).current_dir(&root).args([
        "metadata",
        "--format-version=1",
        "--no-deps",
    ]))?;
    let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or("missing Cargo target directory")?,
    );
    fs::create_dir_all(&target)?;
    let ctx = Context {
        root,
        scratch: tempfile::Builder::new()
            .prefix("audit-")
            .tempdir_in(&target)?,
        target,
        debug,
        cargo,
        cc: env::var_os("CC").unwrap_or_else(|| "cc".into()),
    };
    let destination = output.clone().unwrap_or_else(|| {
        ctx.target
            .join(if debug { "runtime-debug" } else { "runtime" })
            .join("LinUwUx.so")
    });
    match command.to_str() {
        Some("build") => ctx.build(&destination),
        _ => Err(format!(
            "unknown command or missing required option: {command:?}; run cargo xtask help"
        )
        .into()),
    }
}
