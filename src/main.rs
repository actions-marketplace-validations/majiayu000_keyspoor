use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use secret_scan::baseline::Baseline;
use secret_scan::engine::Confidence;
use secret_scan::report::{OutputFormat, write_report, write_scan_event, write_scan_summary};
use secret_scan::scan::{
    ScanControl, ScanOptions, scan_buffer, scan_history, scan_history_range,
    scan_history_range_stream, scan_history_stream, scan_paths, scan_paths_stream, scan_reader,
    scan_staged, scan_staged_stream,
};
use secret_scan::{Engine, EngineConfig, ScanReport};
use serde::Deserialize;

#[derive(Parser)]
#[command(
    version,
    about = "Independent offline secret scanning with redacted results"
)]
struct Cli {
    #[command(flatten)]
    engine: EngineArgs,
    #[command(subcommand)]
    command: Action,
}

#[derive(Args)]
struct EngineArgs {
    /// Additional rules in secret-scan JSON format.
    #[arg(long, global = true)]
    rules: Vec<PathBuf>,
    #[arg(long, global = true)]
    no_builtin: bool,
    #[arg(long, global = true, default_value = "medium", value_parser = ["low", "medium", "high"])]
    confidence: String,
    #[arg(long, global = true)]
    no_decode: bool,
    #[arg(long, global = true)]
    min_entropy: Option<f32>,
    /// File containing exactly 32 private bytes; never copied into reports.
    #[arg(long, global = true)]
    fingerprint_key_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Action {
    /// Scan paths, or '-' for stdin. Default exclusions respect ignore files.
    Scan(ScanArgs),
    /// Scan the full INDEX version of changed staged files, preserving context.
    Staged(ScanArgs),
    /// Scan local reachable Git history and report every commit/path occurrence.
    History(ScanArgs),
    /// List selected rule metadata as JSON, without secret patterns or examples.
    Rules,
    /// Persistent JSONL text scanner. Each request is {id,path,text}.
    Serve,
    /// MCP stdio server with read-only scanning constrained to a root directory.
    Mcp {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value_t = 67_108_864)]
        max_bytes: u64,
    },
}

#[derive(Args)]
struct ScanArgs {
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,
    #[arg(long, default_value = "json", value_parser = ["json", "jsonl", "sarif"])]
    format: String,
    #[arg(long, default_value_t = 4)]
    threads: usize,
    #[arg(long, default_value_t = 67_108_864)]
    max_bytes: u64,
    /// Include ignore-listed files; .git metadata is always excluded.
    #[arg(long)]
    no_ignore: bool,
    /// Show only findings absent from this baseline.
    #[arg(long, conflicts_with = "write_baseline")]
    baseline: Option<PathBuf>,
    /// Save a complete scan as baseline, retaining existing review labels.
    #[arg(long)]
    write_baseline: Option<PathBuf>,
    /// Git revision range, for history only (for example main..HEAD).
    #[arg(long)]
    range: Option<String>,
}

fn build_engine(args: EngineArgs) -> Result<Engine> {
    let fingerprint_key = if let Some(path) = args.fingerprint_key_file {
        let key = std::fs::read(path).context("cannot read fingerprint key file")?;
        Some(key.try_into().map_err(|_: Vec<u8>| {
            anyhow::anyhow!("fingerprint key must contain exactly 32 bytes")
        })?)
    } else {
        None
    };
    Engine::new(EngineConfig {
        builtin_rules: !args.no_builtin,
        custom_rule_paths: args.rules,
        min_confidence: match args.confidence.as_str() {
            "high" => Confidence::High,
            "low" => Confidence::Low,
            _ => Confidence::Medium,
        },
        enable_base64: !args.no_decode,
        min_entropy: args.min_entropy,
        fingerprint_key,
    })
}

fn output_format(format: &str) -> OutputFormat {
    match format {
        "jsonl" => OutputFormat::Jsonl,
        "sarif" => OutputFormat::Sarif,
        _ => OutputFormat::Json,
    }
}

fn read_baseline(path: &Path) -> Result<Baseline> {
    Baseline::read(std::fs::File::open(path).context("cannot open baseline")?)
}

fn save_baseline(path: &Path, report: &ScanReport) -> Result<()> {
    let old = if path.exists() {
        Some(read_baseline(path)?)
    } else {
        None
    };
    let baseline = Baseline::from_report(report, old.as_ref())?;
    // Validate and serialize before touching an existing baseline.
    let mut bytes = Vec::new();
    baseline.write(&mut bytes)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile_for_baseline(parent)?;
    if let Err(e) = (|| -> Result<()> {
        temporary.1.write_all(&bytes)?;
        temporary.1.sync_all()?;
        std::fs::rename(&temporary.0, path).context("cannot replace baseline")?;
        Ok(())
    })() {
        let _ = std::fs::remove_file(&temporary.0);
        return Err(e);
    }
    Ok(())
}

fn tempfile_for_baseline(parent: &Path) -> Result<(PathBuf, std::fs::File)> {
    for counter in 0..32 {
        let path = parent.join(format!(
            ".secret-scan-baseline-{}-{counter}.tmp",
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).context("cannot create temporary baseline"),
        }
    }
    bail!("cannot allocate temporary baseline name")
}

#[derive(Deserialize)]
struct TextRequest {
    id: serde_json::Value,
    #[serde(default = "stdin_name")]
    path: String,
    text: String,
}
fn stdin_name() -> String {
    "stdin".into()
}

fn serve(engine: &Engine) -> Result<()> {
    const LIMIT: usize = 8 * 1024 * 1024;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let size = io::Read::by_ref(&mut input)
            .take((LIMIT + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if size == 0 {
            break;
        }
        if line.len() > LIMIT {
            // Do not parse or echo an oversized payload, or process its suffix.
            serde_json::to_writer(
                &mut output,
                &serde_json::json!({"id":null,"error":"request exceeds 8 MiB limit"}),
            )?;
            writeln!(output)?;
            output.flush()?;
            bail!("oversized request terminated the input stream");
        }
        match serde_json::from_slice::<TextRequest>(&line) {
            Ok(request) => {
                let report =
                    scan_buffer(engine, &request.path, request.text.as_bytes(), LIMIT as u64);
                serde_json::to_writer(
                    &mut output,
                    &serde_json::json!({"id":request.id,"result":report}),
                )?;
            }
            Err(_) => serde_json::to_writer(
                &mut output,
                &serde_json::json!({"id":null,"error":"invalid request; expected id, optional path, and text"}),
            )?,
        }
        writeln!(output)?;
        output.flush()?;
    }
    Ok(())
}

fn run(cli: Cli) -> Result<u8> {
    let started = Instant::now();
    let engine = build_engine(cli.engine)?;
    let (mode, args) = match cli.command {
        Action::Rules => {
            serde_json::to_writer(io::stdout().lock(), &engine.rules())?;
            return Ok(0);
        }
        Action::Serve => {
            serve(&engine)?;
            return Ok(0);
        }
        Action::Mcp { root, max_bytes } => {
            secret_scan::mcp::serve(&engine, &root, max_bytes)?;
            return Ok(0);
        }
        Action::Scan(args) => ("files", args),
        Action::Staged(args) => ("staged", args),
        Action::History(args) => ("history", args),
    };
    let options = ScanOptions {
        threads: args.threads,
        max_bytes: args.max_bytes,
        respect_ignore: !args.no_ignore,
    };
    if args.range.is_some() && mode != "history" {
        bail!("--range is only supported by history");
    }
    if mode != "files" && args.paths.len() != 1 {
        bail!("Git modes require exactly one repository path");
    }
    // Baseline policy is finalized during traversal. Validate it before emitting
    // filtered results; the ordinary JSONL path streams directly to the writer.
    if args.format == "jsonl"
        && args.baseline.is_none()
        && args.write_baseline.is_none()
        && args.paths != [PathBuf::from("-")]
    {
        let control = ScanControl::default();
        let mut output = io::BufWriter::new(io::stdout().lock());
        let mut sink = |event| write_scan_event(&event, &mut output);
        let mut summary = match mode {
            "files" => scan_paths_stream(&engine, &args.paths, &options, &control, &mut sink)?,
            "staged" => scan_staged_stream(&engine, &args.paths[0], &options, &control, &mut sink)?,
            "history" => match args.range.as_deref() {
                Some(range) => scan_history_range_stream(
                    &engine,
                    &args.paths[0],
                    range,
                    &options,
                    &control,
                    &mut sink,
                )?,
                None => {
                    scan_history_stream(&engine, &args.paths[0], &options, &control, &mut sink)?
                }
            },
            _ => unreachable!(),
        };
        summary.stats.elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        write_scan_summary(&summary, &mut output)?;
        return Ok(if !summary.complete || summary.error_count != 0 {
            2
        } else if summary.finding_count != 0 {
            1
        } else {
            0
        });
    }
    let mut report = match mode {
        "files" if args.paths == [PathBuf::from("-")] => {
            scan_reader(&engine, "stdin", io::stdin().lock(), options.max_bytes)
        }
        "files" => scan_paths(&engine, &args.paths, &options)?,
        "staged" | "history" => {
            if args.paths.len() != 1 {
                bail!("Git modes require exactly one repository path");
            }
            if mode == "staged" {
                scan_staged(&engine, &args.paths[0], &options)?
            } else if let Some(range) = args.range.as_deref() {
                scan_history_range(&engine, &args.paths[0], range, &options)?
            } else {
                scan_history(&engine, &args.paths[0], &options)?
            }
        }
        _ => unreachable!(),
    };
    if let Some(path) = args.baseline {
        let baseline = read_baseline(&path)?;
        report.findings = baseline.diff(&report)?.new;
    }
    if let Some(path) = args.write_baseline {
        save_baseline(&path, &report)?;
    }
    report.stats.elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let code = report.exit_code();
    write_report(&report, output_format(&args.format), io::stdout().lock())?;
    Ok(code)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            // Configuration/runtime errors are distinct from a clean empty scan.
            eprintln!("secret-scan: {error:#}");
            ExitCode::from(2)
        }
    }
}
