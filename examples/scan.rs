//! Run with `cargo run --example scan -- path/to/scan`.
use keyspoor::scan::{ScanOptions, scan_paths};
use keyspoor::{Engine, EngineConfig};
use std::{error::Error, path::PathBuf, process::ExitCode};

fn main() -> Result<ExitCode, Box<dyn Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: scan <path>")?;
    let engine = Engine::new(EngineConfig::default())?;
    let report = scan_paths(&engine, &[path], &ScanOptions::default())?;
    println!(
        "complete={} findings={} errors={}",
        report.complete,
        report.findings.len(),
        report.errors.len()
    );
    for finding in &report.findings {
        println!(
            "{}:{} {} {}",
            finding.path, finding.line, finding.rule_id, finding.redacted
        );
    }
    // 0 means complete and clean, 1 means findings, 2 means incomplete/error.
    Ok(ExitCode::from(report.exit_code()))
}
