#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use x7q_secure::{
    BuildSection, V2BuildOptions, VERSION_V2, build_container, build_pdf_from_x7q,
    build_v2_from_pdf_with_key, build_v2_text_container_with_key, parse_secure,
    validate_v2_with_key,
};

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut args = args.into_iter();
    let command = args.next().ok_or_else(usage)?;
    match command.as_str() {
        "verify" => {
            let path = one_path(args)?;
            verify(Path::new(&path))
        }
        "inspect" => {
            let parsed = parse_file_key_args(args)?;
            inspect(Path::new(&parsed.input), parsed.key.as_deref())
        }
        "build" => {
            let path = one_path(args)?;
            build(Path::new(&path))
        }
        "validate-v2" => {
            let parsed = parse_file_key_args(args)?;
            validate_v2_file(Path::new(&parsed.input), parsed.key.as_deref())
        }
        "build-v2" => {
            let parsed = parse_io_key_args(args)?;
            build_v2_file(
                Path::new(&parsed.input),
                Path::new(&parsed.output),
                parsed.key.as_deref(),
            )
        }
        "pdf-x7q" | "pdf-to-x7q" => {
            let parsed = parse_io_key_args(args)?;
            pdf_to_x7q(
                Path::new(&parsed.input),
                Path::new(&parsed.output),
                parsed.key.as_deref(),
            )
        }
        "x7q-to-pdf" => {
            let parsed = parse_io_key_args(args)?;
            x7q_to_pdf(
                Path::new(&parsed.input),
                Path::new(&parsed.output),
                parsed.key.as_deref(),
            )
        }
        _ => Err(format!("unknown command: {command}\n{}", usage())),
    }
}

fn one_path(mut args: impl Iterator<Item = String>) -> Result<String, String> {
    let path = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(format!("too many arguments\n{}", usage()));
    }
    Ok(path)
}

struct ParsedFileArgs {
    input: String,
    key: Option<String>,
}

struct ParsedIoArgs {
    input: String,
    output: String,
    key: Option<String>,
}

fn parse_file_key_args(args: impl Iterator<Item = String>) -> Result<ParsedFileArgs, String> {
    let parsed = parse_positional_with_key(args)?;
    if parsed.positionals.len() != 1 {
        return Err(usage());
    }
    Ok(ParsedFileArgs {
        input: parsed.positionals[0].clone(),
        key: parsed.key,
    })
}

fn parse_io_key_args(args: impl Iterator<Item = String>) -> Result<ParsedIoArgs, String> {
    let parsed = parse_positional_with_key(args)?;
    if parsed.positionals.len() != 2 {
        return Err(usage());
    }
    Ok(ParsedIoArgs {
        input: parsed.positionals[0].clone(),
        output: parsed.positionals[1].clone(),
        key: parsed.key,
    })
}

struct ParsedKeyArgs {
    positionals: Vec<String>,
    key: Option<String>,
}

fn parse_positional_with_key(args: impl Iterator<Item = String>) -> Result<ParsedKeyArgs, String> {
    let mut positionals = Vec::new();
    let mut key = None;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if arg == "--key" {
            if key.is_some() {
                return Err("duplicate --key option".to_owned());
            }
            key = Some(
                args.next()
                    .ok_or_else(|| "--key requires a value".to_owned())?,
            );
        } else if let Some(value) = arg.strip_prefix("--key=") {
            if key.is_some() {
                return Err("duplicate --key option".to_owned());
            }
            key = Some(value.to_owned());
        } else if arg.starts_with("--") {
            return Err(format!("unknown option: {arg}"));
        } else {
            positionals.push(arg);
        }
    }
    Ok(ParsedKeyArgs { positionals, key })
}

fn verify(path: &Path) -> Result<(), String> {
    let bytes = read_file(path)?;
    let container = parse_secure(&bytes).map_err(|err| format!("verification failed: {err}"))?;
    println!(
        "x7q-secure verify ok: version=0x{:02x}, header_len={}, sections={}",
        container.version(),
        container.header_len(),
        container.sections().len()
    );
    Ok(())
}

fn inspect(path: &Path, key: Option<&str>) -> Result<(), String> {
    let bytes = read_file(path)?;
    if bytes.get(4).copied() == Some(VERSION_V2) {
        return inspect_v2(&bytes, key);
    }
    let container = parse_secure(&bytes).map_err(|err| format!("inspection failed: {err}"))?;
    println!("x7q-secure inspect");
    println!("version=0x{:02x}", container.version());
    println!("header_len={}", container.header_len());
    println!("section_count={}", container.sections().len());
    println!("content_hash={}", hex(container.content_hash()));
    println!("header_hash={}", hex(container.header_hash()));
    for (index, section) in container.sections().iter().enumerate() {
        println!(
            "section[{index}]: type=0x{:02x}, offset={}, length={}, flags=0x{:02x}",
            section.section_type(),
            section.offset(),
            section.length(),
            section.flags()
        );
    }
    Ok(())
}

fn inspect_v2(bytes: &[u8], key: Option<&str>) -> Result<(), String> {
    let container =
        validate_v2_with_key(bytes, key).map_err(|err| format!("v2 inspection failed: {err}"))?;
    println!("x7q-secure inspect v2");
    println!("version=0x{:02x}", container.container().version());
    println!("header_len={}", container.container().header_len());
    println!("section_count={}", container.container().sections().len());
    println!("canonical_hash={}", hex(container.canonical_hash()));
    println!("policy_contract=passive-only");
    for (index, section) in container.container().sections().iter().enumerate() {
        println!(
            "section[{index}]: type=0x{:02x}, offset={}, length={}, flags=0x{:02x}",
            section.section_type(),
            section.offset(),
            section.length(),
            section.flags()
        );
    }
    Ok(())
}

fn build(path: &Path) -> Result<(), String> {
    let manifest = fs::read_to_string(path)
        .map_err(|err| format!("failed to read manifest {}: {err}", path.display()))?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let plan = parse_manifest(&manifest, base_dir)?;
    let container = build_container(&plan.sections)
        .map_err(|err| format!("failed to build container: {err}"))?;
    fs::write(&plan.output, container)
        .map_err(|err| format!("failed to write {}: {err}", plan.output.display()))?;
    println!("x7q-secure build ok: output={}", plan.output.display());
    Ok(())
}

fn build_v2_file(input: &Path, output: &Path, key: Option<&str>) -> Result<(), String> {
    let text = fs::read_to_string(input)
        .map_err(|err| format!("failed to read text {}: {err}", input.display()))?;
    let options = V2BuildOptions::new("text", input.display().to_string());
    let container = build_v2_text_container_with_key(&text, &options, key)
        .map_err(|err| format!("failed to build v2 container: {err}"))?;
    fs::write(output, container)
        .map_err(|err| format!("failed to write {}: {err}", output.display()))?;
    println!("x7q-secure build-v2 ok: output={}", output.display());
    Ok(())
}

fn validate_v2_file(path: &Path, key: Option<&str>) -> Result<(), String> {
    let bytes = read_file(path)?;
    let container =
        validate_v2_with_key(&bytes, key).map_err(|err| format!("v2 validation failed: {err}"))?;
    println!("x7q-secure validate-v2 ok");
    println!("version=0x{:02x}", container.container().version());
    println!("section_count={}", container.container().sections().len());
    println!("canonical_hash={}", hex(container.canonical_hash()));
    println!("policy_contract=passive-only");
    Ok(())
}

fn pdf_to_x7q(input: &Path, output: &Path, key: Option<&str>) -> Result<(), String> {
    let bytes = read_file(input)?;
    let container = build_v2_from_pdf_with_key(&bytes, &input.display().to_string(), key)
        .map_err(|err| format!("failed to convert PDF to x7q: {err}"))?;
    fs::write(output, container)
        .map_err(|err| format!("failed to write {}: {err}", output.display()))?;
    println!("x7q-secure pdf-x7q ok: output={}", output.display());
    Ok(())
}

fn x7q_to_pdf(input: &Path, output: &Path, key: Option<&str>) -> Result<(), String> {
    let bytes = read_file(input)?;
    let pdf = build_pdf_from_x7q(&bytes, key)
        .map_err(|err| format!("failed to convert x7q to PDF: {err}"))?;
    fs::write(output, pdf).map_err(|err| format!("failed to write {}: {err}", output.display()))?;
    println!("x7q-secure x7q-to-pdf ok: output={}", output.display());
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

struct BuildPlan {
    output: PathBuf,
    sections: Vec<BuildSection>,
}

fn parse_manifest(input: &str, base_dir: &Path) -> Result<BuildPlan, String> {
    let mut output = None;
    let mut sections = Vec::new();

    for (line_index, raw_line) in input.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("manifest line {line_number}: expected key=value"));
        };
        match key.trim() {
            "output" => {
                let path = resolve_path(base_dir, value.trim());
                output = Some(path);
            }
            "section" => {
                let parts: Vec<&str> = value.split(',').map(str::trim).collect();
                if parts.len() != 3 {
                    return Err(format!(
                        "manifest line {line_number}: section requires type,flags,path"
                    ));
                }
                let section_type = parse_u8(parts[0], line_number, "section type")?;
                let flags = parse_u8(parts[1], line_number, "section flags")?;
                let payload_path = resolve_path(base_dir, parts[2]);
                let payload = fs::read(&payload_path).map_err(|err| {
                    format!(
                        "manifest line {line_number}: failed to read {}: {err}",
                        payload_path.display()
                    )
                })?;
                sections.push(BuildSection::new(section_type, flags, payload));
            }
            other => return Err(format!("manifest line {line_number}: unknown key {other}")),
        }
    }

    let output = output.ok_or_else(|| "manifest missing output=<path>".to_owned())?;
    Ok(BuildPlan { output, sections })
}

fn resolve_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn parse_u8(input: &str, line_number: usize, label: &str) -> Result<u8, String> {
    let parsed = if let Some(hex) = input.strip_prefix("0x") {
        u8::from_str_radix(hex, 16)
    } else {
        input.parse::<u8>()
    };
    parsed.map_err(|err| format!("manifest line {line_number}: invalid {label}: {err}"))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

fn usage() -> String {
    "usage: x7q-secure verify <file.x7q>\n       x7q-secure inspect <file.x7q> [--key <key>]\n       x7q-secure build <manifest>\n       x7q-secure validate-v2 <file.x7q> [--key <key>]\n       x7q-secure build-v2 <text-file> <output.x7q> [--key <key>]\n       x7q-secure pdf-to-x7q <input.pdf> <output.x7q> [--key <key>]\n       x7q-secure x7q-to-pdf <input.x7q> <output.pdf> [--key <key>]".to_owned()
}
