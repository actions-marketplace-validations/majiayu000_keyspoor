//! Filesystem and local Git acquisition. No remote connections are made.
use crate::{Engine, ScanReport};
use anyhow::{Context, Result, bail};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub threads: usize,
    pub max_bytes: u64,
    pub respect_ignore: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            threads: 4,
            max_bytes: 64 * 1024 * 1024,
            respect_ignore: true,
        }
    }
}

fn finish(mut report: ScanReport, started: Instant) -> ScanReport {
    report.findings.sort_by(|a, b| {
        (&a.path, a.start, a.end, &a.rule_id, &a.fingerprint).cmp(&(
            &b.path,
            b.start,
            b.end,
            &b.rule_id,
            &b.fingerprint,
        ))
    });
    report
        .errors
        .sort_by(|a, b| (&a.path, &a.message).cmp(&(&b.path, &b.message)));
    report.stats.elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    report
}

pub fn scan_reader(engine: &Engine, name: &str, reader: impl Read, max_bytes: u64) -> ScanReport {
    let started = Instant::now();
    let mut report = ScanReport::default();
    let mut bytes = Vec::new();
    match reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        Err(e) => report.fail(name, format!("cannot read input ({:?})", e.kind())),
        Ok(_) if bytes.len() as u64 > max_bytes => {
            report.stats.skipped = 1;
            report.fail(name, format!("input exceeds {max_bytes} byte limit"));
        }
        Ok(_) => report = scan_buffer(engine, name, &bytes, max_bytes),
    }

    finish(report, started)
}

// Shared dispatch for already bounded filesystem, stdin and Git inputs. Borrow
// Git blobs directly so every path can be checked without copying blob bytes.
fn scan_buffer(engine: &Engine, name: &str, bytes: &[u8], max_bytes: u64) -> ScanReport {
    let mut report = ScanReport::default();
    match crate::archive::scan_archive(engine, name, bytes, max_bytes) {
        Ok(Some(archive_report)) => report = archive_report,
        Err(_) => report.fail(name, "archive decoding failed; input was not fully scanned"),
        Ok(None) => {
            report.stats.files = 1;
            report.stats.detection_passes = 1;
            report.stats.bytes = bytes.len() as u64;
            match engine.scan_bytes(name, bytes) {
                Ok(findings) => report.findings = findings,
                Err(_) => report.fail(name, "detection failed; input was not fully scanned"),
            }
        }
    }
    report
}

pub fn scan_paths(engine: &Engine, paths: &[PathBuf], options: &ScanOptions) -> Result<ScanReport> {
    if paths.is_empty() {
        bail!("at least one input path is required");
    }
    if options.threads == 0 {
        bail!("threads must be positive");
    }
    let started = Instant::now();
    let mut report = ScanReport::default();
    let mut files = BTreeSet::new();
    for path in paths {
        if path.is_file() {
            files.insert(path.clone());
            continue;
        }
        if !path.is_dir() {
            report.fail(
                path.to_string_lossy(),
                "input path is not an accessible file or directory",
            );
            continue;
        }
        let mut builder = WalkBuilder::new(path);
        builder
            .hidden(false)
            .follow_links(false)
            .git_ignore(options.respect_ignore)
            .git_global(options.respect_ignore)
            .git_exclude(options.respect_ignore)
            .ignore(options.respect_ignore)
            .require_git(false)
            .filter_entry(|entry| entry.file_name() != ".git");
        for entry in builder.build() {
            match entry {
                Ok(entry) => {
                    // Ignore parse errors can accompany a successful directory
                    // entry. Preserve incomplete status without echoing rules.
                    if entry.error().is_some() {
                        report.fail(
                            entry.path().to_string_lossy(),
                            "directory ignore rules could not be fully read",
                        );
                    }
                    if entry.file_type().is_some_and(|t| t.is_file()) {
                        files.insert(entry.into_path());
                    }
                }
                Err(_) => report.fail(path.to_string_lossy(), "directory traversal failed"),
            }
        }
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads)
        .build()?;
    let partials: Vec<ScanReport> = pool.install(|| {
        files
            .par_iter()
            .map(|path| match std::fs::File::open(path) {
                Ok(file) => scan_reader(engine, &path.to_string_lossy(), file, options.max_bytes),
                Err(e) => {
                    let mut r = ScanReport::default();
                    r.fail(path.to_string_lossy(), format!("cannot open file: {e}"));
                    r
                }
            })
            .collect()
    });
    for partial in partials {
        report.complete &= partial.complete;
        report.stats.files += partial.stats.files;
        report.stats.detection_passes += partial.stats.detection_passes;
        report.stats.bytes += partial.stats.bytes;
        report.stats.skipped += partial.stats.skipped;
        report.findings.extend(partial.findings);
        report.errors.extend(partial.errors);
    }
    Ok(finish(report, started))
}

fn git(repo: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo).args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]);
    command.env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn git_output(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = git(repo).args(args).output().context("cannot start Git")?;
    if !output.status.success() {
        bail!("Git {} failed ({})", args[0], output.status);
    }
    Ok(output.stdout)
}

/// Scan changed staged files from the index, never their working-tree versions.
/// The entire indexed file is scanned, preserving paired-credential context.
pub fn scan_staged(engine: &Engine, repo: &Path, options: &ScanOptions) -> Result<ScanReport> {
    let started = Instant::now();
    let names = git_output(
        repo,
        &[
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
        ],
    )?;
    let changed: BTreeSet<&[u8]> = names
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect();
    let entries = git_output(repo, &["ls-files", "--stage", "-z"])?;
    let mut objects: GitObjects = BTreeMap::new();
    for entry in entries
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let split = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .context("invalid Git index record")?;
        let path = &entry[split + 1..];
        if !changed.contains(path) {
            continue;
        }
        let fields: Vec<_> = std::str::from_utf8(&entry[..split])?
            .split_whitespace()
            .collect();
        if fields.len() != 3 {
            bail!("invalid Git index metadata");
        }
        // Gitlinks are separate repositories; merge-conflict stages are not files
        // that `git diff --cached --diff-filter=ACMR` selected for this scan.
        if fields[0] == "160000" || fields[2] != "0" {
            continue;
        }
        let path = std::str::from_utf8(path).context("Git path is not UTF-8")?;
        objects
            .entry(fields[1].into())
            .or_default()
            .entry(path.into())
            .or_default();
    }
    Ok(finish(
        scan_git_objects(engine, repo, options, objects)?,
        started,
    ))
}

// Blob -> exact path -> all reachable commits. Exact paths are significant to
// path-restricted rules and fingerprints, even when extensions are identical.
type GitObjects = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// Read each unique blob once, detect once per distinct blob/path pair, then
/// retain every reachable commit/path occurrence. Only local refs are read;
/// submodules and external LFS objects are not fetched. `stats.files`/`bytes`
/// measure unique input blobs; `detection_passes` counts actual engine calls.
pub fn scan_history(engine: &Engine, repo: &Path, options: &ScanOptions) -> Result<ScanReport> {
    let started = Instant::now();
    let commits = git_output(repo, &["rev-list", "--all"])?;
    let mut objects: GitObjects = BTreeMap::new();
    for commit in std::str::from_utf8(&commits)?.lines() {
        let tree = git_output(repo, &["ls-tree", "-r", "-z", commit])?;
        for entry in tree
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let split = entry
                .iter()
                .position(|byte| *byte == b'\t')
                .context("invalid Git tree record")?;
            let mut meta = std::str::from_utf8(&entry[..split])?.split_whitespace();
            let _mode = meta.next();
            if meta.next() != Some("blob") {
                continue;
            }
            let oid = meta.next().context("missing Git object id")?;
            let path = std::str::from_utf8(&entry[split + 1..]).context("Git path is not UTF-8")?;
            objects
                .entry(oid.into())
                .or_default()
                .entry(path.into())
                .or_default()
                .push(commit.into());
        }
    }
    Ok(finish(
        scan_git_objects(engine, repo, options, objects)?,
        started,
    ))
}

fn blob_header(output: &mut impl BufRead, oid: &str) -> Result<u64> {
    let mut header = String::new();
    output
        .read_line(&mut header)
        .context("cannot read Git blob metadata")?;
    let fields: Vec<_> = header.split_whitespace().collect();
    if fields.len() != 3 || fields[0] != oid || fields[1] != "blob" {
        bail!("invalid or missing Git blob response for {oid}");
    }
    fields[2].parse().context("invalid Git blob size")
}

fn scan_git_objects(
    engine: &Engine,
    repo: &Path,
    options: &ScanOptions,
    objects: GitObjects,
) -> Result<ScanReport> {
    if objects.is_empty() {
        return Ok(ScanReport::default());
    }
    let mut child = git(repo)
        .args(["cat-file", "--batch-command"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot start Git blob reader")?;
    let result = (|| -> Result<ScanReport> {
        let mut input = child.stdin.take().context("missing Git input pipe")?;
        let mut output = BufReader::new(child.stdout.take().context("missing Git output pipe")?);
        let mut report = ScanReport::default();
        for (oid, paths) in objects {
            // Ask for metadata before contents: oversized blobs are never loaded
            // into memory or streamed through the scanner just to discard them.
            writeln!(input, "info {oid}")?;
            input.flush()?;
            let size = blob_header(&mut output, &oid)?;
            if size > options.max_bytes {
                report.stats.skipped += 1;
                report.fail(
                    format!("git-object:{oid}"),
                    format!("blob exceeds {} byte limit", options.max_bytes),
                );
                continue;
            }
            writeln!(input, "contents {oid}")?;
            input.flush()?;
            if blob_header(&mut output, &oid)? != size {
                bail!("Git blob size changed");
            }
            let mut bytes = vec![
                0;
                usize::try_from(size)
                    .context("Git blob does not fit in memory address space")?
            ];
            output
                .read_exact(&mut bytes)
                .context("truncated Git blob")?;
            let mut newline = [0];
            output
                .read_exact(&mut newline)
                .context("missing Git blob terminator")?;
            if newline != *b"\n" {
                bail!("invalid Git blob terminator");
            }
            report.stats.files += 1;
            report.stats.bytes += size;
            for (path, commits) in paths {
                let partial = scan_buffer(engine, &path, &bytes, options.max_bytes);
                report.complete &= partial.complete;
                // files/bytes remain unique Git blob acquisition counts; member
                // scans contribute their actual detection passes and skips.
                report.stats.detection_passes += partial.stats.detection_passes;
                report.stats.skipped += partial.stats.skipped;
                if commits.is_empty() {
                    report.findings.extend(partial.findings);
                    report.errors.extend(partial.errors);
                } else {
                    for commit in commits {
                        for found in &partial.findings {
                            let mut found = found.clone();
                            found.path = format!("git:{commit}:{}", found.path);
                            report.findings.push(found);
                        }
                        for error in &partial.errors {
                            let mut error = error.clone();
                            error.path = format!("git:{commit}:{}", error.path);
                            report.errors.push(error);
                        }
                    }
                }
            }
        }
        drop(input);
        Ok(report)
    })();
    match result {
        Err(error) => {
            // Always reap the process; cleanup errors must not replace the
            // original parse/read/detection acquisition error.
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
        Ok(report) => {
            let status = child.wait().context("cannot wait for Git blob reader")?;
            if !status.success() {
                bail!("Git blob reader failed ({status})");
            }
            Ok(report)
        }
    }
}
