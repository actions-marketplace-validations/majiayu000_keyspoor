//! Filesystem and local Git acquisition. No remote connections are made.
use crate::context::{ScanContext, policy_digest};
use crate::{Engine, Finding, ScanError, ScanReport, ScanStats};
use anyhow::{Context, Result, bail};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, SyncSender},
};
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

/// Cooperative cancellation. An in-progress engine call finishes before stopping.
#[derive(Debug, Clone, Default)]
pub struct ScanControl {
    cancelled: Arc<AtomicBool>,
}

impl ScanControl {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Finding(Finding),
    Error(ScanError),
    Progress(ScanStats),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub complete: bool,
    pub finding_count: u64,
    pub error_count: u64,
    pub stats: ScanStats,
    pub context: Option<ScanContext>,
}

impl Default for ScanSummary {
    fn default() -> Self {
        Self {
            complete: true,
            finding_count: 0,
            error_count: 0,
            stats: ScanStats::default(),
            context: None,
        }
    }
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

/// Progress is advisory; findings and errors always bypass this throttle.
#[derive(Default)]
struct ProgressThrottle {
    last_elapsed_ms: Option<u64>,
}

impl ProgressThrottle {
    fn emit(
        &mut self,
        stats: &ScanStats,
        sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
    ) -> Result<()> {
        if self
            .last_elapsed_ms
            .is_none_or(|last| stats.elapsed_ms.saturating_sub(last) >= 100)
        {
            sink(ScanEvent::Progress(stats.clone()))?;
            self.last_elapsed_ms = Some(stats.elapsed_ms);
        }
        Ok(())
    }
}

fn sort_report(report: &mut ScanReport) {
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
}

fn collect_scan(
    run: impl FnOnce(&mut dyn FnMut(ScanEvent) -> Result<()>) -> Result<ScanSummary>,
) -> Result<ScanReport> {
    let mut report = ScanReport::default();
    let summary = run(&mut |event| {
        match event {
            ScanEvent::Finding(finding) => report.findings.push(finding),
            ScanEvent::Error(error) => report.errors.push(error),
            ScanEvent::Progress(_) => {}
        }
        Ok(())
    })?;
    report.complete = summary.complete;
    report.stats = summary.stats;
    report.context = summary.context;
    sort_report(&mut report);
    Ok(report)
}

fn emit(
    summary: &mut ScanSummary,
    event: ScanEvent,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
) -> Result<()> {
    match &event {
        ScanEvent::Finding(_) => summary.finding_count += 1,
        ScanEvent::Error(_) => {
            summary.complete = false;
            summary.error_count += 1;
        }
        ScanEvent::Progress(_) => {}
    }
    sink(event)
}

fn emit_partial(
    summary: &mut ScanSummary,
    partial: ScanReport,
    progress: &mut ProgressThrottle,
    control: &ScanControl,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
    started: Instant,
) -> Result<()> {
    summary.complete &= partial.complete && partial.errors.is_empty();
    summary.stats.files += partial.stats.files;
    summary.stats.bytes += partial.stats.bytes;
    summary.stats.skipped += partial.stats.skipped;
    summary.stats.detection_passes += partial.stats.detection_passes;
    for finding in partial.findings {
        if control.is_cancelled() {
            break;
        }
        emit(summary, ScanEvent::Finding(finding), sink)?;
    }
    for error in partial.errors {
        if control.is_cancelled() {
            break;
        }
        emit(summary, ScanEvent::Error(error), sink)?;
    }
    if !control.is_cancelled() {
        summary.stats.elapsed_ms = elapsed(started);
        progress.emit(&summary.stats, sink)?;
    }
    Ok(())
}

fn finish_summary(
    mut summary: ScanSummary,
    control: &ScanControl,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
    started: Instant,
) -> Result<ScanSummary> {
    if control.is_cancelled() {
        emit(
            &mut summary,
            ScanEvent::Error(ScanError {
                path: "scan".into(),
                message: "scan cancelled; remaining inputs were not fully scanned".into(),
            }),
            sink,
        )?;
    }
    summary.stats.elapsed_ms = elapsed(started);
    sink(ScanEvent::Progress(summary.stats.clone()))?;
    Ok(summary)
}

fn context(engine: &Engine, mode: &str, roots: Vec<String>, parts: &[&[u8]]) -> ScanContext {
    ScanContext {
        mode: mode.into(),
        roots,
        engine_configuration_id: engine.configuration_id().into(),
        selection_policy_id: policy_digest(parts),
    }
}

/// Read one input into a bounded file buffer. Use path streams for many files.
pub fn scan_reader(engine: &Engine, name: &str, reader: impl Read, max_bytes: u64) -> ScanReport {
    let started = Instant::now();
    let mut report = read_input(
        engine,
        name,
        name,
        reader,
        max_bytes,
        &ScanControl::default(),
    );
    report.context = Some(context(
        engine,
        "reader",
        vec![name.into()],
        &[&max_bytes.to_le_bytes()],
    ));
    report.stats.elapsed_ms = elapsed(started);
    sort_report(&mut report);
    report
}

fn read_input(
    engine: &Engine,
    name: &str,
    identity: &str,
    mut reader: impl Read,
    max_bytes: u64,
    control: &ScanControl,
) -> ScanReport {
    let mut report = ScanReport::default();
    let mut bytes = Vec::new();
    let mut buffer = [0; 32 * 1024];
    loop {
        if control.is_cancelled() {
            report.complete = false;
            return report;
        }
        let remaining = max_bytes
            .saturating_sub(bytes.len() as u64)
            .saturating_add(1);
        let capacity = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        match reader.read(&mut buffer[..capacity]) {
            Ok(0) => break,
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() as u64 > max_bytes {
                    report.stats.skipped = 1;
                    report.fail(name, format!("input exceeds {max_bytes} byte limit"));
                    return report;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                report.fail(name, format!("cannot read input ({:?})", error.kind()));
                return report;
            }
        }
    }
    scan_buffer_controlled(engine, name, identity, &bytes, max_bytes, control)
}

/// Scan borrowed input bytes without a second text/file copy. Findings within one
/// input remain buffered; this API does not promise constant memory per finding.
pub fn scan_buffer(engine: &Engine, name: &str, bytes: &[u8], max_bytes: u64) -> ScanReport {
    let started = Instant::now();
    let mut report = scan_buffer_controlled(
        engine,
        name,
        name,
        bytes,
        max_bytes,
        &ScanControl::default(),
    );
    report.context = Some(context(
        engine,
        "reader",
        vec![name.into()],
        &[&max_bytes.to_le_bytes()],
    ));
    report.stats.elapsed_ms = elapsed(started);
    report
}

fn scan_buffer_controlled(
    engine: &Engine,
    name: &str,
    identity: &str,
    bytes: &[u8],
    max_bytes: u64,
    control: &ScanControl,
) -> ScanReport {
    let mut report = ScanReport::default();
    if control.is_cancelled() {
        report.complete = false;
        return report;
    }
    if bytes.len() as u64 > max_bytes {
        report.stats.skipped = 1;
        report.fail(name, format!("input exceeds {max_bytes} byte limit"));
        return report;
    }
    match crate::archive::scan_archive_with_identity(
        engine, name, identity, bytes, max_bytes, control,
    ) {
        Ok(Some(archive_report)) => report = archive_report,
        Err(_) => report.fail(name, "archive decoding failed; input was not fully scanned"),
        Ok(None) => {
            report.stats.files = 1;
            report.stats.detection_passes = 1;
            report.stats.bytes = bytes.len() as u64;
            match engine.scan_bytes_with_identity(name, identity, bytes) {
                Ok(findings) => report.findings = findings,
                Err(_) => report.fail(name, "detection failed; input was not fully scanned"),
            }
        }
    }
    if control.is_cancelled() {
        report.complete = false;
    }
    report
}

#[derive(Clone)]
struct FileJob {
    path: PathBuf,
    display: String,
    identity: String,
}

fn file_job(path: PathBuf, root: &Path) -> Result<FileJob> {
    let display = path
        .strip_prefix(root)
        .unwrap_or(&path)
        .to_str()
        .context("filesystem path is not UTF-8")?
        .to_owned();
    let identity = path
        .to_str()
        .context("filesystem path is not UTF-8")?
        .to_owned();
    Ok(FileJob {
        path,
        display,
        identity,
    })
}

#[derive(Default)]
struct PolicyFiles {
    inputs: BTreeMap<PathBuf, [u8; 32]>,
    require_git: BTreeMap<PathBuf, bool>,
}

impl PolicyFiles {
    fn observe(&mut self, path: PathBuf) -> Result<()> {
        if self.inputs.contains_key(&path) {
            return Ok(());
        }
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(());
            }
            Err(_) => bail!("ignore policy could not be read"),
        };
        let path = std::fs::canonicalize(&path)
            .map_err(|_| anyhow::anyhow!("ignore policy location could not be resolved"))?;
        if self.inputs.contains_key(&path) {
            return Ok(());
        }
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0; 8192];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| anyhow::anyhow!("ignore policy could not be read"))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        self.inputs.insert(path, *hasher.finalize().as_bytes());
        Ok(())
    }
    fn directory(&mut self, path: &Path) -> Result<()> {
        // Marker presence and type change where inherited Git rules stop.
        // Absence is represented by no entry, so ordinary directory additions
        // do not invalidate the scope merely because they lack VCS markers.
        for marker in [".git", ".jj"] {
            let boundary = path.join(marker);
            let metadata = match std::fs::metadata(&boundary) {
                Ok(metadata) => metadata,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(_) => bail!("repository boundary could not be inspected"),
            };
            let kind: &[u8] = if metadata.is_dir() {
                b"repository-boundary:directory"
            } else if metadata.is_file() {
                b"repository-boundary:file"
            } else {
                b"repository-boundary:other"
            };
            // Keep the marker's location, not its symlink target: the location
            // determines the boundary. Never hash refs, HEAD, or index data.
            self.inputs.insert(boundary, *blake3::hash(kind).as_bytes());
        }
        self.observe(path.join(".ignore"))?;
        self.observe(path.join(".gitignore"))?;
        self.observe(path.join(".git/info/exclude"))?;
        // Linked worktrees use a .git file pointing at their private Git directory.
        let gitfile = path.join(".git");
        if gitfile.is_file() {
            let data = std::fs::read_to_string(&gitfile)
                .map_err(|_| anyhow::anyhow!("Git ignore policy location could not be read"))?;
            if let Some(target) = data.trim().strip_prefix("gitdir: ") {
                let gitdir = path.join(target);
                self.observe(gitdir.join("info/exclude"))?;
                if let Ok(common) = std::fs::read_to_string(gitdir.join("commondir")) {
                    self.observe(gitdir.join(common.trim()).join("info/exclude"))?;
                }
            }
        }
        Ok(())
    }
    fn digest(&self, options: &ScanOptions) -> String {
        let max_bytes = options.max_bytes.to_le_bytes();
        let respect = [u8::from(options.respect_ignore)];
        let mut parts: Vec<&[u8]> = vec![b"filesystem-v1", &max_bytes, &respect];
        for (path, digest) in &self.inputs {
            parts.push(path.as_os_str().as_encoded_bytes());
            parts.push(digest);
        }
        parts.push(b"walk-root-require-git");
        for (root, require_git) in &self.require_git {
            parts.push(root.as_os_str().as_encoded_bytes());
            parts.push(if *require_git { b"true" } else { b"false" });
        }
        policy_digest(&parts)
    }
}

fn failure(path: &Path, message: &str) -> ScanReport {
    let mut report = ScanReport::default();
    report.fail(path.to_string_lossy(), message);
    report
}

fn produce_files(
    roots: &[PathBuf],
    options: &ScanOptions,
    control: &ScanControl,
    jobs: SyncSender<FileJob>,
    results: SyncSender<ScanReport>,
) -> PolicyFiles {
    let mut policy = PolicyFiles::default();
    let directories: Vec<_> = roots.iter().filter(|path| path.is_dir()).collect();
    let files: BTreeSet<_> = roots
        .iter()
        .filter(|path| !path.is_dir())
        .cloned()
        .collect();
    if options.respect_ignore {
        if let Some(path) = ignore::gitignore::gitconfig_excludes_path()
            && policy.observe(path.clone()).is_err()
            && results
                .send(failure(&path, "global ignore policy could not be read"))
                .is_err()
        {
            return policy;
        }
        for root in &directories {
            for ancestor in root.ancestors() {
                if control.is_cancelled() {
                    return policy;
                }
                if policy.directory(ancestor).is_err()
                    && results
                        .send(failure(ancestor, "ignore policy could not be read"))
                        .is_err()
                {
                    return policy;
                }
            }
        }
    }
    for file in &files {
        if control.is_cancelled() {
            return policy;
        }
        let root = directories
            .iter()
            .find(|root| file.starts_with(root))
            .copied()
            .map(|p| p.as_path())
            .unwrap_or_else(|| file.parent().unwrap_or(file));
        match file_job(file.clone(), root) {
            Ok(job) => {
                if jobs.send(job).is_err() {
                    return policy;
                }
            }
            Err(_) => {
                if results
                    .send(failure(file, "filesystem path is not UTF-8"))
                    .is_err()
                {
                    return policy;
                }
            }
        }
    }
    for root in &directories {
        if directories
            .iter()
            .any(|ancestor| ancestor != root && root.starts_with(ancestor))
        {
            continue;
        }
        let require_git = root.ancestors().any(|parent| parent.join(".git").exists());
        if options.respect_ignore {
            policy.require_git.insert((*root).clone(), require_git);
        }
        let mut builder = WalkBuilder::new(root);
        builder
            .hidden(false)
            .follow_links(false)
            .git_ignore(options.respect_ignore)
            .git_global(options.respect_ignore)
            .git_exclude(options.respect_ignore)
            .ignore(options.respect_ignore)
            // `ignore` needs VCS discovery enabled to resolve a linked
            // worktree's .git file and shared info/exclude. Plain directories
            // still honor .gitignore without requiring a repository.
            .require_git(require_git)
            .filter_entry(|entry| entry.file_name() != ".git");
        for entry in builder.build() {
            if control.is_cancelled() {
                return policy;
            }
            match entry {
                Ok(entry) => {
                    if entry.error().is_some()
                        && results
                            .send(failure(
                                entry.path(),
                                "directory ignore rules could not be fully read",
                            ))
                            .is_err()
                    {
                        return policy;
                    }
                    if options.respect_ignore
                        && entry.file_type().is_some_and(|kind| kind.is_dir())
                        && policy.directory(entry.path()).is_err()
                        && results
                            .send(failure(entry.path(), "ignore policy could not be read"))
                            .is_err()
                    {
                        return policy;
                    }
                    if entry.file_type().is_some_and(|kind| kind.is_file())
                        && !files.contains(entry.path())
                    {
                        match file_job(entry.into_path(), root) {
                            Ok(job) => {
                                if jobs.send(job).is_err() {
                                    return policy;
                                }
                            }
                            Err(_) => {
                                if results
                                    .send(failure(root, "filesystem path is not UTF-8"))
                                    .is_err()
                                {
                                    return policy;
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    if results
                        .send(failure(root, "directory traversal failed"))
                        .is_err()
                    {
                        return policy;
                    }
                }
            }
        }
    }
    policy
}

/// File-level streaming with bounded job/result queues and synchronous sink
/// backpressure. Each worker buffers one input and its findings. Streaming order
/// follows completion order; the collecting API sorts its final report. Progress
/// retains the first event, then emits at most once per 100 ms, plus a final event.
pub fn scan_paths_stream(
    engine: &Engine,
    paths: &[PathBuf],
    options: &ScanOptions,
    control: &ScanControl,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
) -> Result<ScanSummary> {
    if paths.is_empty() {
        bail!("at least one input path is required");
    }
    if options.threads == 0 {
        bail!("threads must be positive");
    }
    let started = Instant::now();
    let mut summary = ScanSummary::default();
    let mut progress = ProgressThrottle::default();
    let mut roots = BTreeSet::new();
    for path in paths {
        if control.is_cancelled() {
            break;
        }
        match std::fs::canonicalize(path) {
            Ok(path) if path.is_file() || path.is_dir() => {
                roots.insert(path);
            }
            _ => {
                if let Err(error) = emit(
                    &mut summary,
                    ScanEvent::Error(ScanError {
                        path: path.to_string_lossy().into(),
                        message: "input path is not an accessible file or directory".into(),
                    }),
                    sink,
                ) {
                    control.cancel();
                    return Err(error);
                }
            }
        }
    }
    let roots: Vec<_> = roots.into_iter().collect();
    let capacity = options.threads.saturating_mul(2).max(1);
    let (job_tx, job_rx) = mpsc::sync_channel::<FileJob>(capacity);
    let (result_tx, result_rx) = mpsc::sync_channel::<ScanReport>(capacity);
    let job_rx = Arc::new(Mutex::new(job_rx));
    let policy = std::thread::scope(|scope| -> Result<PolicyFiles> {
        let mut workers = Vec::new();
        for _ in 0..options.threads {
            let jobs = Arc::clone(&job_rx);
            let results = result_tx.clone();
            workers.push(std::thread::Builder::new().spawn_scoped(scope, move || {
                loop {
                    if control.is_cancelled() {
                        break;
                    }
                    let job = match jobs.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => break,
                    };
                    let Ok(job) = job else {
                        break;
                    };
                    if control.is_cancelled() {
                        break;
                    }
                    let report = match std::fs::File::open(&job.path) {
                        Ok(file) => read_input(
                            engine,
                            &job.display,
                            &job.identity,
                            file,
                            options.max_bytes,
                            control,
                        ),
                        Err(error) => {
                            failure(&job.path, &format!("cannot open file ({:?})", error.kind()))
                        }
                    };
                    if results.send(report).is_err() {
                        break;
                    }
                }
            })?);
        }
        drop(job_rx);
        let producer = std::thread::Builder::new().spawn_scoped(scope, || {
            produce_files(&roots, options, control, job_tx, result_tx)
        })?;
        let mut sink_error = None;
        for partial in result_rx {
            if sink_error.is_none()
                && let Err(error) =
                    emit_partial(&mut summary, partial, &mut progress, control, sink, started)
            {
                control.cancel();
                sink_error = Some(error);
            }
        }
        let policy = producer
            .join()
            .map_err(|_| anyhow::anyhow!("filesystem traversal worker failed"))?;
        for worker in workers {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("file detection worker failed"))?;
        }
        if let Some(error) = sink_error {
            return Err(error);
        }
        Ok(policy)
    })?;
    summary.context = Some(ScanContext {
        mode: "filesystem".into(),
        roots: roots
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        engine_configuration_id: engine.configuration_id().into(),
        selection_policy_id: policy.digest(options),
    });
    match finish_summary(summary, control, sink, started) {
        Ok(summary) => Ok(summary),
        Err(error) => {
            control.cancel();
            Err(error)
        }
    }
}

pub fn scan_paths(engine: &Engine, paths: &[PathBuf], options: &ScanOptions) -> Result<ScanReport> {
    collect_scan(|sink| scan_paths_stream(engine, paths, options, &ScanControl::default(), sink))
}
fn git(repo: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.fsmonitor=false"]);
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

fn git_root(repo: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(repo).context("cannot resolve Git repository path")?;
    let bare = git_output(&canonical, &["rev-parse", "--is-bare-repository"])?;
    let output = match bare.as_slice() {
        b"true\n" | b"true\r\n" => git_output(&canonical, &["rev-parse", "--absolute-git-dir"])?,
        b"false\n" | b"false\r\n" => git_output(&canonical, &["rev-parse", "--show-toplevel"])?,
        _ => bail!("invalid Git repository type response"),
    };
    let root = output.strip_suffix(b"\n").unwrap_or(&output);
    let root = std::str::from_utf8(root).context("Git repository path is not UTF-8")?;
    std::fs::canonicalize(root).context("cannot resolve Git repository root")
}

// Blob -> exact path -> shared commit groups. All paths from one root tree share
// the same commit metadata, instead of copying every commit/path combination.
type GitObjects = BTreeMap<String, BTreeMap<String, Vec<Arc<[String]>>>>;

fn staged_objects(repo: &Path, control: &ScanControl) -> Result<GitObjects> {
    let mut objects = GitObjects::new();
    if control.is_cancelled() {
        return Ok(objects);
    }
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
    if control.is_cancelled() {
        return Ok(objects);
    }
    let changed: BTreeSet<&[u8]> = names
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect();
    let entries = git_output(repo, &["ls-files", "--stage", "-z"])?;
    for entry in entries
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        if control.is_cancelled() {
            break;
        }
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
    Ok(objects)
}

fn history_objects(
    repo: &Path,
    range: Option<&str>,
    control: &ScanControl,
    summary: &mut ScanSummary,
    progress: &mut ProgressThrottle,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
    started: Instant,
) -> Result<GitObjects> {
    let mut objects = GitObjects::new();
    if control.is_cancelled() {
        return Ok(objects);
    }
    // One metadata command gets each commit and its root tree. Reused root trees
    // are expanded only once, including long runs of empty/metadata-only commits.
    let commits = match range {
        Some(range) => git_output(
            repo,
            &[
                "log",
                "--format=%H %T",
                "--no-show-signature",
                "--end-of-options",
                range,
                "--",
            ],
        )?,
        None => git_output(
            repo,
            &["log", "--all", "--format=%H %T", "--no-show-signature"],
        )?,
    };
    let mut trees: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for line in std::str::from_utf8(&commits)?.lines() {
        if control.is_cancelled() {
            return Ok(objects);
        }
        let (commit, tree) = line
            .split_once(' ')
            .context("invalid Git commit metadata")?;
        trees.entry(tree).or_default().push(commit.into());
    }
    for (tree_oid, commits) in trees {
        if control.is_cancelled() {
            break;
        }
        let commits: Arc<[String]> = commits.into();
        let tree = git_output(repo, &["ls-tree", "-r", "-z", tree_oid])?;
        for entry in tree
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            if control.is_cancelled() {
                break;
            }
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
                .push(Arc::clone(&commits));
        }
        summary.stats.elapsed_ms = elapsed(started);
        progress.emit(&summary.stats, sink)?;
    }
    Ok(objects)
}

/// Scan index contents, retaining complete file and archive context.
pub fn scan_staged(engine: &Engine, repo: &Path, options: &ScanOptions) -> Result<ScanReport> {
    collect_scan(|sink| scan_staged_stream(engine, repo, options, &ScanControl::default(), sink))
}

pub fn scan_staged_stream(
    engine: &Engine,
    repo: &Path,
    options: &ScanOptions,
    control: &ScanControl,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
) -> Result<ScanSummary> {
    scan_git_stream(engine, repo, options, control, sink, true, None)
}

/// Scan all local refs. Blob bytes are read once; detection runs once per exact
/// blob/path pair. Findings stream without accumulating all commit occurrences.
/// Metadata for unique trees, blob paths and commit groups remains in memory.
pub fn scan_history(engine: &Engine, repo: &Path, options: &ScanOptions) -> Result<ScanReport> {
    collect_scan(|sink| scan_history_stream(engine, repo, options, &ScanControl::default(), sink))
}

pub fn scan_history_stream(
    engine: &Engine,
    repo: &Path,
    options: &ScanOptions,
    control: &ScanControl,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
) -> Result<ScanSummary> {
    scan_git_stream(engine, repo, options, control, sink, false, None)
}

/// Scan complete snapshots of commits selected by a Git revision expression
/// (for example `main..feature`). This is not changed-lines-only patch scanning.
pub fn scan_history_range(
    engine: &Engine,
    repo: &Path,
    range: &str,
    options: &ScanOptions,
) -> Result<ScanReport> {
    collect_scan(|sink| {
        scan_history_range_stream(engine, repo, range, options, &ScanControl::default(), sink)
    })
}

pub fn scan_history_range_stream(
    engine: &Engine,
    repo: &Path,
    range: &str,
    options: &ScanOptions,
    control: &ScanControl,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
) -> Result<ScanSummary> {
    if range.is_empty() {
        bail!("Git revision range must not be empty");
    }
    scan_git_stream(engine, repo, options, control, sink, false, Some(range))
}

fn scan_git_stream(
    engine: &Engine,
    repo: &Path,
    options: &ScanOptions,
    control: &ScanControl,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
    staged: bool,
    range: Option<&str>,
) -> Result<ScanSummary> {
    let started = Instant::now();
    let canonical = git_root(repo)?;
    let mode = if staged { "git-staged" } else { "git-history" };
    let selection = if staged {
        "index"
    } else {
        range.unwrap_or("--all")
    };
    let mut summary = ScanSummary {
        context: Some(context(
            engine,
            mode,
            vec![canonical.to_string_lossy().into()],
            &[&options.max_bytes.to_le_bytes(), selection.as_bytes()],
        )),
        ..ScanSummary::default()
    };
    let mut progress = ProgressThrottle::default();
    let result = (|| {
        let objects = if staged {
            staged_objects(&canonical, control)?
        } else {
            history_objects(
                &canonical,
                range,
                control,
                &mut summary,
                &mut progress,
                sink,
                started,
            )?
        };
        scan_git_objects(
            engine,
            &canonical,
            options,
            objects,
            control,
            &mut summary,
            &mut progress,
            sink,
            started,
        )?;
        finish_summary(summary, control, sink, started)
    })();
    if result.is_err() {
        control.cancel();
    }
    result
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

#[allow(clippy::too_many_arguments)]
fn scan_git_objects(
    engine: &Engine,
    repo: &Path,
    options: &ScanOptions,
    objects: GitObjects,
    control: &ScanControl,
    summary: &mut ScanSummary,
    progress: &mut ProgressThrottle,
    sink: &mut (impl FnMut(ScanEvent) -> Result<()> + ?Sized),
    started: Instant,
) -> Result<()> {
    if objects.is_empty() || control.is_cancelled() {
        return Ok(());
    }
    let mut child = git(repo)
        .args(["cat-file", "--batch-command"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot start Git blob reader")?;
    let result = (|| -> Result<()> {
        let mut input = child.stdin.take().context("missing Git input pipe")?;
        let mut output = BufReader::new(child.stdout.take().context("missing Git output pipe")?);
        for (oid, paths) in objects {
            if control.is_cancelled() {
                break;
            }
            writeln!(input, "info {oid}")?;
            input.flush()?;
            let size = blob_header(&mut output, &oid)?;
            if size > options.max_bytes {
                summary.stats.skipped += 1;
                emit(
                    summary,
                    ScanEvent::Error(ScanError {
                        path: format!("git-object:{oid}"),
                        message: format!("blob exceeds {} byte limit", options.max_bytes),
                    }),
                    sink,
                )?;
                continue;
            }
            if control.is_cancelled() {
                break;
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
            // Cooperative cancellation during byte acquisition; the child is
            // killed/reaped below if its current response was not consumed.
            for chunk in bytes.chunks_mut(32 * 1024) {
                if control.is_cancelled() {
                    return Ok(());
                }
                output.read_exact(chunk).context("truncated Git blob")?;
            }
            let mut newline = [0];
            output
                .read_exact(&mut newline)
                .context("missing Git blob terminator")?;
            if newline != *b"\n" {
                bail!("invalid Git blob terminator");
            }
            summary.stats.files += 1;
            summary.stats.bytes += size;
            for (path, commit_groups) in paths {
                if control.is_cancelled() {
                    break;
                }
                let mut partial = scan_buffer_controlled(
                    engine,
                    &path,
                    &path,
                    &bytes,
                    options.max_bytes,
                    control,
                );
                partial.stats.files = 0;
                partial.stats.bytes = 0;
                if commit_groups.is_empty() {
                    emit_partial(summary, partial, progress, control, sink, started)?;
                } else {
                    summary.complete &= partial.complete && partial.errors.is_empty();
                    summary.stats.detection_passes += partial.stats.detection_passes;
                    summary.stats.skipped += partial.stats.skipped;
                    for group in commit_groups {
                        for commit in group.iter() {
                            if control.is_cancelled() {
                                break;
                            }
                            for found in &partial.findings {
                                if control.is_cancelled() {
                                    break;
                                }
                                let mut found = found.clone();
                                found.path = format!("git:{commit}:{}", found.path).into();
                                emit(summary, ScanEvent::Finding(found), sink)?;
                            }
                            for error in &partial.errors {
                                if control.is_cancelled() {
                                    break;
                                }
                                let mut error = error.clone();
                                error.path = format!("git:{commit}:{}", error.path);
                                emit(summary, ScanEvent::Error(error), sink)?;
                            }
                        }
                    }
                    if !control.is_cancelled() {
                        summary.stats.elapsed_ms = elapsed(started);
                        progress.emit(&summary.stats, sink)?;
                    }
                }
            }
        }
        drop(input);
        Ok(())
    })();
    if result.is_err() || control.is_cancelled() {
        let _ = child.kill();
        let _ = child.wait();
        return result;
    }
    let status = child.wait().context("cannot wait for Git blob reader")?;
    if !status.success() {
        bail!("Git blob reader failed ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    #[test]
    fn progress_keeps_first_event_and_respects_interval_without_wall_clock_waits() {
        let mut throttle = ProgressThrottle::default();
        let mut emitted = Vec::new();
        for elapsed_ms in [0, 0, 1, 99, 100, 101, 199, 200, 450, 451] {
            throttle
                .emit(
                    &ScanStats {
                        elapsed_ms,
                        ..Default::default()
                    },
                    &mut |event| {
                        if let ScanEvent::Progress(stats) = event {
                            emitted.push(stats.elapsed_ms);
                        }
                        Ok(())
                    },
                )
                .unwrap();
        }
        assert_eq!(emitted, [0, 100, 200, 450]);
    }

    #[test]
    fn progress_sink_error_is_returned_without_advancing_throttle() {
        let mut throttle = ProgressThrottle::default();
        let stats = ScanStats {
            elapsed_ms: 7,
            ..Default::default()
        };
        let error = throttle
            .emit(&stats, &mut |_| anyhow::bail!("sink failed"))
            .unwrap_err();
        assert_eq!(error.to_string(), "sink failed");
        assert_eq!(throttle.last_elapsed_ms, None);
        throttle.emit(&stats, &mut |_| Ok(())).unwrap();
        assert_eq!(throttle.last_elapsed_ms, Some(7));
    }
}
