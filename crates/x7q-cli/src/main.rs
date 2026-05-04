#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use x7q_core::parse;

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
    if command != "parse" {
        return Err(format!("unknown command: {command}\n{}", usage()));
    }

    let file = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(format!("too many arguments\n{}", usage()));
    }

    parse_file(Path::new(&file))
}

fn parse_file(path: &Path) -> Result<(), String> {
    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let container = parse(&bytes).map_err(|err| format!("invalid x7q container: {err}"))?;

    println!(
        "x7q parse ok: version=0x{:02x}, header_len={}, sections={}",
        container.version(),
        container.header_len(),
        container.sections().len()
    );

    for (index, section) in container.sections().iter().enumerate() {
        println!(
            "section[{index}]: type=0x{:02x}, offset={}, length={}",
            section.section_type(),
            section.offset(),
            section.length()
        );
    }

    Ok(())
}

fn usage() -> String {
    "usage: x7q parse <file>".to_owned()
}
