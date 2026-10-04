//! Read-only MCP 2025-11-25 over newline-delimited stdio JSON-RPC.
//!
//! Protocol references: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
//! and https://modelcontextprotocol.io/specification/2025-11-25/server/tools.
//! No credential validation, file mutation, or logging to stdout is performed.
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, SyncSender},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::scan::{ScanControl, ScanEvent, ScanOptions, scan_buffer, scan_paths_stream};
use crate::{Engine, ScanReport};

const REQUEST_LIMIT: usize = 8 * 1024 * 1024;
const PROTOCOL_VERSION: &str = "2025-11-25";
const RESULT_LIMIT: usize = 100;
const RESULT_BYTES: usize = 512 * 1024;
type Output = Arc<Mutex<io::Stdout>>;

/// Serve until stdin closes. Paths resolve relative to the canonical server root.
/// Traversal does not follow directory symlinks; explicitly requested paths must
/// resolve inside root. This is not an OS sandbox against concurrent file changes.
pub fn serve(engine: &Engine, root: &Path, max_bytes: u64) -> Result<()> {
    let root = root.canonicalize().context("cannot resolve MCP root")?;
    ensure!(root.is_dir(), "MCP root must be a directory");
    let stdin = io::stdin();
    let output = Arc::new(Mutex::new(io::stdout()));
    let mut input = stdin.lock();
    std::thread::scope(|scope| -> Result<()> {
        let (jobs, pending) = mpsc::sync_channel::<Job>(1);
        let worker_output = Arc::clone(&output);
        let worker_root = &root;
        let worker = scope.spawn(move || -> Result<()> {
            for job in pending {
                let result = execute(engine, worker_root, max_bytes, &job, &worker_output);
                // The scan has finished. A subsequent request may now be queued.
                job.done.store(true, Ordering::Release);
                // MCP cancellation has no final response; the internal scan summary
                // remains incomplete, and the connection stays available for reuse.
                if job.cancelled_by_client.load(Ordering::Acquire) {
                    continue;
                }
                let response = match result {
                    Ok(result) => json!({"jsonrpc":"2.0", "id":job.id, "result":result}),
                    Err(_) => error(job.id, -32603, "Scan worker failed"),
                };
                send(&worker_output, &response)?;
            }
            Ok(())
        });
        let mut state = State::New;
        let mut active: Option<Active> = None;
        let reader_result = (|| -> Result<()> {
            while let Some(frame) = read_frame(&mut input)? {
                if active
                    .as_ref()
                    .is_some_and(|scan| scan.done.load(Ordering::Acquire))
                {
                    active = None;
                }
                let response = match frame {
                    Some(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                        Ok(request) => dispatch(&mut state, &mut active, &jobs, request),
                        Err(_) => Some(error(Value::Null, -32700, "Parse error")),
                    },
                    None => Some(error(Value::Null, -32600, "Request exceeds 8 MiB limit")),
                };
                if let Some(response) = response {
                    send(&output, &response)?;
                }
            }
            Ok(())
        })();
        if reader_result.is_err()
            && let Some(active) = &active
        {
            active.control.cancel();
        }
        drop(jobs);
        let worker_result = worker
            .join()
            .map_err(|_| anyhow::anyhow!("MCP scan worker panicked"))?;
        reader_result?;
        worker_result
    })
}

fn send(output: &Output, message: &Value) -> Result<()> {
    let mut writer = output
        .lock()
        .map_err(|_| anyhow::anyhow!("MCP output lock poisoned"))?;
    serde_json::to_writer(&mut *writer, message)?;
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}

struct Active {
    id: Value,
    control: ScanControl,
    done: Arc<AtomicBool>,
    cancelled_by_client: Arc<AtomicBool>,
}

struct Job {
    id: Value,
    input: ToolInput,
    progress_token: Option<Value>,
    control: ScanControl,
    done: Arc<AtomicBool>,
    cancelled_by_client: Arc<AtomicBool>,
}

enum ToolInput {
    Text(TextArgs),
    Paths(PathsArgs),
}

// Read bounded chunks and drain only the oversized frame, never its successor.
// Outer None means EOF; inner None means a frame exceeded the limit.
fn read_frame(input: &mut impl BufRead) -> io::Result<Option<Option<Vec<u8>>>> {
    let mut frame = Vec::new();
    let mut oversized = false;
    let mut seen = false;
    loop {
        let chunk = input.fill_buf()?;
        if chunk.is_empty() {
            return Ok(seen.then_some((!oversized).then_some(frame)));
        }
        seen = true;
        let end = chunk.iter().position(|&byte| byte == b'\n');
        let take = end.map_or(chunk.len(), |end| end + 1);
        if !oversized {
            if frame.len().saturating_add(take) > REQUEST_LIMIT {
                oversized = true;
                frame.clear();
            } else {
                frame.extend_from_slice(&chunk[..take]);
            }
        }
        input.consume(take);
        if end.is_some() {
            return Ok(Some((!oversized).then_some(frame)));
        }
    }
}

#[derive(PartialEq)]
enum State {
    New,
    Initializing,
    Ready,
}

fn error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message}})
}

fn dispatch(
    state: &mut State,
    active: &mut Option<Active>,
    jobs: &SyncSender<Job>,
    request: Value,
) -> Option<Value> {
    let Some(object) = request.as_object() else {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    };
    let id = object.get("id").cloned();
    let valid_id = id
        .as_ref()
        .is_none_or(|id| id.is_string() || id.is_i64() || id.is_u64());
    let method = object.get("method").and_then(Value::as_str);
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || method.is_none() || !valid_id
    {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    }
    let method = method?;
    let params = object.get("params");
    // Notifications never receive a response and never execute tools.
    let Some(id) = id else {
        if method == "notifications/initialized"
            && *state == State::Initializing
            && params.is_none_or(Value::is_object)
        {
            *state = State::Ready;
        }
        if method == "notifications/cancelled"
            && let (Some(scan), Some(request_id)) =
                (active.as_ref(), params.and_then(|p| p.get("requestId")))
            && request_id == &scan.id
        {
            scan.cancelled_by_client.store(true, Ordering::Release);
            scan.control.cancel();
        }
        return None;
    };
    if params.is_some_and(|params| !params.is_object()) {
        return Some(error(id, -32602, "Invalid params"));
    }
    let result = match method {
        "ping" => json!({}),
        "initialize" => {
            if *state != State::New {
                return Some(error(id, -32600, "Already initialized"));
            }
            let valid = params.is_some_and(|params| {
                params["protocolVersion"].is_string()
                    && params["capabilities"].is_object()
                    && params["clientInfo"]["name"].is_string()
                    && params["clientInfo"]["version"].is_string()
            });
            if !valid {
                return Some(error(id, -32602, "Invalid initialize params"));
            }
            *state = State::Initializing;
            json!({
                "protocolVersion":PROTOCOL_VERSION,
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"keyspoor","version":env!("CARGO_PKG_VERSION")}
            })
        }
        "tools/list" | "tools/call" if *state != State::Ready => {
            return Some(error(id, -32000, "Initialization is not complete"));
        }
        "tools/list" => {
            if params.is_some_and(|params| params.get("cursor").is_some()) {
                return Some(error(
                    id,
                    -32602,
                    "Invalid cursor; tool list is not paginated",
                ));
            }
            tools()
        }
        "tools/call" => {
            let Some(params) = params else {
                return Some(error(id, -32602, "Missing tool call params"));
            };
            let Some(name) = params["name"].as_str() else {
                return Some(error(id, -32602, "Missing tool name"));
            };
            if !matches!(name, "scan_text" | "scan_paths") {
                return Some(error(id, -32602, "Unknown tool"));
            }
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if !arguments.is_object() {
                return Some(error(id, -32602, "Tool arguments must be an object"));
            }
            let input = match name {
                "scan_text" => serde_json::from_value::<TextArgs>(arguments).map(ToolInput::Text),
                _ => serde_json::from_value::<PathsArgs>(arguments).map(ToolInput::Paths),
            };
            let input = match input {
                Ok(input) => input,
                Err(_) => {
                    return Some(tool_error(
                        id,
                        name,
                        "Arguments do not match the tool input schema",
                    ));
                }
            };
            if params.get("_meta").is_some_and(|meta| !meta.is_object()) {
                return Some(error(id, -32602, "Invalid request metadata"));
            }
            let progress_token = params
                .get("_meta")
                .and_then(|meta| meta.get("progressToken"))
                .cloned();
            if progress_token
                .as_ref()
                .is_some_and(|token| !token.is_string() && !token.is_i64() && !token.is_u64())
            {
                return Some(error(id, -32602, "Invalid progress token"));
            }
            if active.is_some() {
                return Some(tool_error(
                    id,
                    name,
                    "A scan is already running; cancel it or wait for its response",
                ));
            }
            let control = ScanControl::default();
            let done = Arc::new(AtomicBool::new(false));
            let cancelled_by_client = Arc::new(AtomicBool::new(false));
            let job = Job {
                id: id.clone(),
                input,
                progress_token,
                control: control.clone(),
                done: Arc::clone(&done),
                cancelled_by_client: Arc::clone(&cancelled_by_client),
            };
            if jobs.send(job).is_err() {
                return Some(error(id, -32603, "Scan worker is unavailable"));
            }
            *active = Some(Active {
                id,
                control,
                done,
                cancelled_by_client,
            });
            return None;
        }
        _ => return Some(error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0", "id":id, "result":result}))
}

fn tools() -> Value {
    let annotations = json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false});
    json!({"tools":[
        {"name":"scan_text", "description":"Scan supplied text offline. Returns a redacted report with at most 100 findings/errors and a shared 512 KiB preview budget. Check complete, finding_count, error_count and output_truncated.",
         "inputSchema":{"type":"object","properties":{"text":{"type":"string"},"path":{"type":"string","description":"Logical filename, not read from disk; defaults to stdin"}},"required":["text"],"additionalProperties":false},
         "annotations":annotations},
        {"name":"scan_paths", "description":"Read files or directories within the configured server root, respecting ignore files. Does not follow directory symlinks. Returns a bounded redacted preview with complete, total counts and output_truncated. Only one scan may run at a time; requests support cancellation and optional progressToken.",
         "inputSchema":{"type":"object","properties":{"paths":{"type":"array","items":{"type":"string"},"minItems":1}},"required":["paths"],"additionalProperties":false},
         "annotations":annotations}
    ]})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TextArgs {
    text: String,
    #[serde(default = "stdin_name")]
    path: String,
}

fn stdin_name() -> String {
    "stdin".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathsArgs {
    paths: Vec<PathBuf>,
}

fn failed(tool: &str, message: &str) -> ScanReport {
    let mut report = ScanReport::default();
    report.fail(tool, message);
    report
}

// Counts describe the whole scan, while these bounded arrays are only a preview.
#[derive(Default)]
struct Preview {
    report: ScanReport,
    finding_count: u64,
    error_count: u64,
    bytes: usize,
}

impl Preview {
    fn push(&mut self, event: ScanEvent) -> Result<()> {
        match event {
            ScanEvent::Finding(finding) => {
                self.finding_count += 1;
                if self.report.findings.len() < RESULT_LIMIT {
                    let size = serde_json::to_vec(&finding)?.len();
                    if self.bytes.saturating_add(size) <= RESULT_BYTES {
                        self.bytes += size;
                        self.report.findings.push(finding);
                    }
                }
            }
            ScanEvent::Error(error) => {
                self.error_count += 1;
                self.report.complete = false;
                if self.report.errors.len() < RESULT_LIMIT {
                    let size = serde_json::to_vec(&error)?.len();
                    if self.bytes.saturating_add(size) <= RESULT_BYTES {
                        self.bytes += size;
                        self.report.errors.push(error);
                    }
                }
            }
            ScanEvent::Progress(stats) => self.report.stats = stats,
        }
        Ok(())
    }

    fn from_report(mut report: ScanReport) -> Result<Self> {
        let mut preview = Self::default();
        for finding in std::mem::take(&mut report.findings) {
            preview.push(ScanEvent::Finding(finding))?;
        }
        for error in std::mem::take(&mut report.errors) {
            preview.push(ScanEvent::Error(error))?;
        }
        preview.report.complete = report.complete;
        preview.report.stats = report.stats;
        preview.report.context = report.context;
        Ok(preview)
    }

    fn result(self) -> Result<Value> {
        let is_error = !self.report.complete || self.error_count > 0;
        let truncated = self.finding_count > self.report.findings.len() as u64
            || self.error_count > self.report.errors.len() as u64;
        let mut report = serde_json::to_value(self.report)?;
        report["finding_count"] = json!(self.finding_count);
        report["error_count"] = json!(self.error_count);
        report["output_truncated"] = json!(truncated);
        Ok(
            json!({"content":[{"type":"text","text":report.to_string()}],
            "structuredContent":report,"isError":is_error}),
        )
    }
}

fn tool_error(id: Value, tool: &str, message: &str) -> Value {
    match Preview::from_report(failed(tool, message)).and_then(Preview::result) {
        Ok(result) => json!({"jsonrpc":"2.0", "id":id, "result":result}),
        Err(_) => error(id, -32603, "Cannot serialize scan report"),
    }
}

fn progress(output: &Output, token: &Value, files: u64) -> Result<()> {
    send(
        output,
        &json!({"jsonrpc":"2.0","method":"notifications/progress",
        "params":{"progressToken":token,"progress":files,"message":"Scanning local inputs"}}),
    )
}

fn execute(
    engine: &Engine,
    root: &Path,
    max_bytes: u64,
    job: &Job,
    output: &Output,
) -> Result<Value> {
    if !job.control.is_cancelled()
        && let Some(token) = &job.progress_token
    {
        progress(output, token, 0)?;
    }
    let mut reported_files = 0;
    let mut preview = match &job.input {
        ToolInput::Text(args) => {
            let report = if job.control.is_cancelled() {
                failed("scan_text", "Scan cancelled")
            } else {
                scan_buffer(engine, &args.path, args.text.as_bytes(), max_bytes)
            };
            Preview::from_report(report)?
        }
        ToolInput::Paths(args) => {
            if args.paths.is_empty() {
                return Preview::from_report(failed(
                    "scan_paths",
                    "At least one path is required",
                ))?
                .result();
            }
            let mut paths = Vec::with_capacity(args.paths.len());
            for path in &args.paths {
                if job.control.is_cancelled() {
                    return Preview::from_report(failed("scan_paths", "Scan cancelled"))?.result();
                }
                let candidate = if path.is_absolute() {
                    path.clone()
                } else {
                    root.join(path)
                };
                let Ok(canonical) = candidate.canonicalize() else {
                    return Preview::from_report(failed(
                        "scan_paths",
                        "A requested path cannot be resolved; no paths were scanned",
                    ))?
                    .result();
                };
                if !canonical.starts_with(root) {
                    return Preview::from_report(failed(
                        "scan_paths",
                        "A requested path is outside the server root; no paths were scanned",
                    ))?
                    .result();
                }
                paths.push(canonical);
            }
            let options = ScanOptions {
                max_bytes,
                ..Default::default()
            };
            let mut preview = Preview::default();
            let mut last_progress = Instant::now();
            let summary = scan_paths_stream(engine, &paths, &options, &job.control, &mut |event| {
                if let ScanEvent::Progress(stats) = &event
                    && !job.control.is_cancelled()
                    && stats.files > reported_files
                    && last_progress.elapsed() >= Duration::from_millis(100)
                {
                    if let Some(token) = &job.progress_token {
                        progress(output, token, stats.files)?;
                    }
                    reported_files = stats.files;
                    last_progress = Instant::now();
                }
                preview.push(event)
            });
            match summary {
                Ok(summary) => {
                    preview.report.complete = summary.complete;
                    preview.report.stats = summary.stats;
                    preview.report.context = summary.context;
                    preview.finding_count = summary.finding_count;
                    preview.error_count = summary.error_count;
                }
                Err(_) => {
                    preview.push(ScanEvent::Error(crate::ScanError {
                        path: "scan_paths".into(),
                        message: "Filesystem scan failed; inputs were not fully scanned".into(),
                    }))?;
                }
            }
            preview
        }
    };
    if job.control.is_cancelled() {
        preview.report.complete = false;
        if preview.error_count == 0 {
            preview.push(ScanEvent::Error(crate::ScanError {
                path: "scan".into(),
                message: "Scan cancelled".into(),
            }))?;
        }
    }
    if !job.control.is_cancelled()
        && preview.report.stats.files > reported_files
        && let Some(token) = &job.progress_token
    {
        progress(output, token, preview.report.stats.files)?;
    }
    preview.result()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_scan_accepts_ping_and_cancellation_and_rejects_busy_calls() {
        let mut state = State::Ready;
        let mut active = None;
        let (jobs, pending) = mpsc::sync_channel(1);
        let call = |id| {
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":"scan_text","arguments":{"text":"safe"}}})
        };
        assert!(dispatch(&mut state, &mut active, &jobs, call(2)).is_none());
        // Hold the queued job instead of racing a worker against fixture I/O.
        let job = pending.recv().unwrap();
        assert!(!job.done.load(Ordering::Acquire));
        let busy = dispatch(&mut state, &mut active, &jobs, call(3)).unwrap();
        assert_eq!(busy["id"], 3);
        assert_eq!(busy["result"]["isError"], true);
        assert_eq!(busy["result"]["structuredContent"]["complete"], false);
        assert!(matches!(pending.try_recv(), Err(mpsc::TryRecvError::Empty)));
        let ping = dispatch(
            &mut state,
            &mut active,
            &jobs,
            json!({"jsonrpc":"2.0","id":4,"method":"ping"}),
        )
        .unwrap();
        assert_eq!(ping["id"], 4);
        assert_eq!(ping["result"], json!({}));
        let cancel = |id| {
            json!({"jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":id}})
        };
        assert!(dispatch(&mut state, &mut active, &jobs, cancel(999)).is_none());
        assert!(!job.control.is_cancelled());
        assert!(!job.cancelled_by_client.load(Ordering::Acquire));
        assert!(dispatch(&mut state, &mut active, &jobs, cancel(2)).is_none());
        assert!(job.control.is_cancelled());
        assert!(job.cancelled_by_client.load(Ordering::Acquire));

        let engine = Engine::new(crate::EngineConfig::default()).unwrap();
        let output = Arc::new(Mutex::new(io::stdout()));
        let result = execute(&engine, Path::new("."), 1024, &job, &output).unwrap();
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["complete"], false);
        assert_eq!(
            result["structuredContent"]["errors"][0]["message"],
            "Scan cancelled"
        );
    }
}
