//! Read-only MCP 2025-11-25 over newline-delimited stdio JSON-RPC.
//!
//! Protocol references: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
//! and https://modelcontextprotocol.io/specification/2025-11-25/server/tools.
//! No credential validation, file mutation, or logging to stdout is performed.
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::scan::{ScanOptions, scan_paths, scan_reader};
use crate::{Engine, ScanReport};

const REQUEST_LIMIT: usize = 8 * 1024 * 1024;
const PROTOCOL_VERSION: &str = "2025-11-25";

/// Serve until stdin closes. Paths resolve relative to the canonical server root.
/// Traversal does not follow directory symlinks; explicitly requested paths must
/// resolve inside root. This is not an OS sandbox against concurrent file changes.
pub fn serve(engine: &Engine, root: &Path, max_bytes: u64) -> Result<()> {
    let root = root.canonicalize().context("cannot resolve MCP root")?;
    ensure!(root.is_dir(), "MCP root must be a directory");
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let mut state = State::New;
    while let Some(frame) = read_frame(&mut input)? {
        let response = match frame {
            Some(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(request) => dispatch(engine, &root, max_bytes, &mut state, request),
                Err(_) => Some(error(Value::Null, -32700, "Parse error")),
            },
            None => Some(error(Value::Null, -32600, "Request exceeds 8 MiB limit")),
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut output, &response)?;
            writeln!(output)?;
            output.flush()?;
        }
    }
    Ok(())
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
    engine: &Engine,
    root: &Path,
    max_bytes: u64,
    state: &mut State,
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
                "serverInfo":{"name":"secret-scan","version":env!("CARGO_PKG_VERSION")}
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
            let report = call_tool(engine, root, max_bytes, name, arguments);
            let is_error = !report.complete || !report.errors.is_empty();
            match serde_json::to_value(report) {
                Ok(report) => json!({
                    "content":[{"type":"text","text":report.to_string()}],
                    "structuredContent":report,"isError":is_error
                }),
                Err(_) => return Some(error(id, -32603, "Cannot serialize scan report")),
            }
        }
        _ => return Some(error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0", "id":id, "result":result}))
}

fn tools() -> Value {
    let annotations = json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false});
    json!({"tools":[
        {"name":"scan_text", "description":"Scan supplied text offline. Returns a redacted ScanReport; check complete and errors before interpreting no findings as clean.",
         "inputSchema":{"type":"object","properties":{"text":{"type":"string"},"path":{"type":"string","description":"Logical filename, not read from disk; defaults to stdin"}},"required":["text"],"additionalProperties":false},
         "annotations":annotations},
        {"name":"scan_paths", "description":"Read files or directories within the configured server root, respecting ignore files. Does not follow directory symlinks. Returns a redacted ScanReport with completeness and errors.",
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

fn call_tool(
    engine: &Engine,
    root: &Path,
    max_bytes: u64,
    name: &str,
    arguments: Value,
) -> ScanReport {
    if name == "scan_text" {
        let Ok(args) = serde_json::from_value::<TextArgs>(arguments) else {
            return failed(name, "Expected text string and optional path string");
        };
        return scan_reader(engine, &args.path, args.text.as_bytes(), max_bytes);
    }
    let Ok(args) = serde_json::from_value::<PathsArgs>(arguments) else {
        return failed(name, "Expected a nonempty array of path strings");
    };
    if args.paths.is_empty() {
        return failed(name, "At least one path is required");
    }
    let mut paths = Vec::with_capacity(args.paths.len());
    for path in args.paths {
        let candidate = if path.is_absolute() {
            path
        } else {
            root.join(path)
        };
        let Ok(canonical) = candidate.canonicalize() else {
            return failed(
                name,
                "A requested path cannot be resolved; no paths were scanned",
            );
        };
        if !canonical.starts_with(root) {
            return failed(
                name,
                "A requested path is outside the server root; no paths were scanned",
            );
        }
        paths.push(canonical);
    }
    let options = ScanOptions {
        max_bytes,
        ..Default::default()
    };
    match scan_paths(engine, &paths, &options) {
        Ok(report) => report,
        Err(_) => failed(
            name,
            "Filesystem scan failed; inputs were not fully scanned",
        ),
    }
}
