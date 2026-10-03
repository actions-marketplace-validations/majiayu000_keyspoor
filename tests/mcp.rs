use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;

fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"synthetic-test","version":"1"}
    }})
}

fn ready() -> Vec<Value> {
    vec![
        initialize(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ]
}

fn call(id: i64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})
}

fn encode(requests: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for request in requests {
        serde_json::to_writer(&mut bytes, request).unwrap();
        bytes.push(b'\n');
    }
    bytes
}

struct Client {
    child: Option<Child>,
    input: Option<ChildStdin>,
    responses: Receiver<Value>,
}

impl Client {
    fn new(root: &Path, max_bytes: u64, rules: Option<&Path>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_keyspoor"));
        if let Some(rules) = rules {
            command.arg("--no-builtin").arg("--rules").arg(rules);
        }
        let mut child = command
            .arg("mcp")
            .arg("--root")
            .arg(root)
            .arg("--max-bytes")
            .arg(max_bytes.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let output = child.stdout.take().unwrap();
        let (send, responses) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let value =
                    serde_json::from_str(&line.unwrap()).expect("stdout contains only JSON-RPC");
                if send.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child: Some(child),
            input,
            responses,
        }
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.input.as_mut().unwrap().write_all(bytes).unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
    }

    fn send(&mut self, request: Value) {
        self.raw(&encode(&[request]));
    }

    fn receive(&self) -> Value {
        self.responses
            .recv_timeout(Duration::from_secs(10))
            .expect("MCP response deadline exceeded")
    }

    fn ready(&mut self) {
        self.send(initialize());
        assert!(self.receive()["result"]["capabilities"]["tools"].is_object());
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    }

    fn finish(mut self) {
        drop(self.input.take());
        let output = self.child.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "unexpected diagnostic output");
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run(root: &Path, bytes: &[u8], max_bytes: u64, rules: Option<&Path>) -> Vec<Value> {
    let mut client = Client::new(root, max_bytes, rules);
    let mut responses = Vec::new();
    for line in bytes.split_inclusive(|&byte| byte == b'\n') {
        client.raw(line);
        let notification = serde_json::from_slice::<Value>(line)
            .is_ok_and(|value| value.is_object() && value.get("id").is_none());
        if !notification {
            responses.push(client.receive());
        }
    }
    client.finish();
    responses
}

#[test]
fn handshake_tools_and_notifications_follow_protocol() {
    let root = TempDir::new().unwrap();
    let mut requests = vec![json!({"jsonrpc":"2.0","id":0,"method":"tools/list"})];
    requests.extend(ready());
    requests.extend([
        json!({"jsonrpc":"2.0","id":"list-request","method":"tools/list"}),
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":100}}),
        json!({"jsonrpc":"2.0","method":"unknown_notification"}),
        json!({"jsonrpc":"2.0","id":3,"method":"ping"}),
    ]);
    let responses = run(root.path(), &encode(&requests), 1024, None);
    assert_eq!(responses.len(), 4);
    assert_eq!(responses[0]["error"]["code"], -32000);
    assert_eq!(responses[1]["result"]["protocolVersion"], "2025-11-25");
    assert!(responses[1]["result"]["capabilities"]["tools"].is_object());
    assert_eq!(responses[2]["id"], "list-request");
    let tools = responses[2]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
        assert_eq!(tool["annotations"]["openWorldHint"], false);
    }
    assert_eq!(responses[3]["result"], json!({}));
}

#[test]
fn text_results_are_redacted_and_incomplete_is_an_error() {
    let root = TempDir::new().unwrap();
    let rules = root.path().join("rules.json");
    fs::write(
        &rules,
        serde_json::to_vec(&json!({"rules":[{
            "id":"synthetic-mcp","name":"Synthetic MCP fixture",
            "pattern":"FIXTURE_[a-z0-9]{16}","secret_group":0,
            "min_entropy":0,"confidence":"high"
        }]}))
        .unwrap(),
    )
    .unwrap();
    let fixture = "FIXTURE_abc123def456gh78";
    let mut requests = ready();
    requests.push(call(
        2,
        "scan_text",
        json!({"text":fixture,"path":"demo.txt"}),
    ));
    requests.push(call(3, "scan_text", json!({"text":"x".repeat(256)})));
    requests.push(call(4, "scan_text", json!({"text":false})));
    let responses = run(root.path(), &encode(&requests), 64, Some(&rules));
    let result = &responses[1]["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["complete"], true);
    assert_eq!(
        result["structuredContent"]["findings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!serde_json::to_string(&responses).unwrap().contains(fixture));
    assert_eq!(
        serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
        result["structuredContent"]
    );
    for response in &responses[2..] {
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(response["result"]["structuredContent"]["complete"], false);
    }
}

#[test]
fn malformed_frames_and_protocol_errors_do_not_break_following_requests() {
    let root = TempDir::new().unwrap();
    let mut bytes = encode(&ready());
    bytes.extend_from_slice(b"{invalid_json\n");
    bytes.extend(encode(&[
        json!({"jsonrpc":"2.0","id":2,"method":"does-not-exist"}),
        call(3, "does-not-exist", json!({})),
        json!({"jsonrpc":"2.0","id":{},"method":"ping"}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scan_text","arguments":false}}),
        json!({"jsonrpc":"2.0","id":5,"method":"ping"}),
    ]));
    let responses = run(root.path(), &bytes, 1024, None);
    let codes: Vec<_> = responses[1..6]
        .iter()
        .map(|r| r["error"]["code"].as_i64().unwrap())
        .collect();
    assert_eq!(codes, [-32700, -32601, -32602, -32600, -32602]);
    assert_eq!(responses[6]["result"], json!({}));
}

#[test]
fn oversized_frame_is_drained_without_losing_the_next_request() {
    let root = TempDir::new().unwrap();
    let mut bytes = encode(&ready());
    bytes.extend(std::iter::repeat_n(b'x', 8 * 1024 * 1024 + 64));
    bytes.push(b'\n');
    bytes.extend(encode(&[json!({"jsonrpc":"2.0","id":2,"method":"ping"})]));
    let responses = run(root.path(), &bytes, 1024, None);
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[1]["error"]["code"], -32600);
    assert_eq!(responses[2]["id"], 2);
    assert_eq!(responses[2]["result"], json!({}));
}

#[test]
fn path_scans_respect_root_and_preserve_partial_status() {
    let base = TempDir::new().unwrap();
    let root = base.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("small.txt"), "safe").unwrap();
    fs::write(root.join("large.txt"), "x".repeat(256)).unwrap();
    fs::write(base.path().join("outside.txt"), "outside").unwrap();
    let mut requests = ready();
    requests.extend([
        call(2, "scan_paths", json!({"paths":["small.txt"]})),
        call(3, "scan_paths", json!({"paths":["small.txt","large.txt"]})),
        call(4, "scan_paths", json!({"paths":["../outside.txt"]})),
        call(5, "scan_paths", json!({"paths":["missing.txt"]})),
    ]);
    let responses = run(&root, &encode(&requests), 16, None);
    assert_eq!(
        responses[1]["result"]["structuredContent"]["stats"]["files"],
        1
    );
    assert_eq!(responses[1]["result"]["isError"], false);
    assert_eq!(
        responses[2]["result"]["structuredContent"]["stats"]["files"],
        1
    );
    for response in &responses[2..] {
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(response["result"]["structuredContent"]["complete"], false);
    }
}

#[cfg(unix)]
#[test]
fn symlink_outside_root_cannot_be_requested_or_traversed() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("outside.txt"), "not-scanned").unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
    let mut requests = ready();
    requests.extend([
        call(2, "scan_paths", json!({"paths":["escape/outside.txt"]})),
        call(3, "scan_paths", json!({"paths":["."]})),
    ]);
    let responses = run(root.path(), &encode(&requests), 1024, None);
    assert_eq!(responses[1]["result"]["isError"], true);
    assert_eq!(
        responses[2]["result"]["structuredContent"]["stats"]["files"],
        0
    );
}

fn synthetic_rules(root: &Path) -> std::path::PathBuf {
    let rules = root.join("synthetic-rules.json");
    fs::write(
        &rules,
        serde_json::to_vec(&json!({"rules":[{
            "id":"synthetic-preview","name":"Synthetic preview fixture",
            "pattern":"FIXTURE_[a-z0-9]{16}","secret_group":0,
            "min_entropy":0,"confidence":"high"
        }]}))
        .unwrap(),
    )
    .unwrap();
    rules
}

#[test]
fn bounded_preview_keeps_total_counts_and_scan_completeness() {
    let root = TempDir::new().unwrap();
    let rules = synthetic_rules(root.path());
    let mut requests = ready();
    requests.push(call(
        2,
        "scan_text",
        json!({"text":"FIXTURE_abc123def456gh78\n".repeat(250)}),
    ));
    requests.push(call(
        3,
        "scan_text",
        json!({"text":"FIXTURE_abc123def456gh78", "path":"p".repeat(600_000)}),
    ));
    let responses = run(root.path(), &encode(&requests), 1_000_000, Some(&rules));
    let count_limited = &responses[1]["result"]["structuredContent"];
    assert_eq!(count_limited["complete"], true);
    assert_eq!(count_limited["output_truncated"], true);
    assert_eq!(count_limited["finding_count"], 250);
    assert_eq!(count_limited["findings"].as_array().unwrap().len(), 100);
    assert_eq!(responses[1]["result"]["isError"], false);
    let byte_limited = &responses[2]["result"]["structuredContent"];
    assert_eq!(byte_limited["complete"], true);
    assert_eq!(byte_limited["finding_count"], 1);
    assert_eq!(byte_limited["output_truncated"], true);
    assert!(byte_limited["findings"].as_array().unwrap().is_empty());
}

#[test]
fn bounded_error_preview_never_makes_an_incomplete_scan_clean() {
    let root = TempDir::new().unwrap();
    for index in 0..130 {
        fs::write(root.path().join(format!("large-{index}.txt")), "too large").unwrap();
    }
    let mut requests = ready();
    requests.push(call(2, "scan_paths", json!({"paths":["."]})));
    let responses = run(root.path(), &encode(&requests), 1, None);
    let result = &responses[1]["result"];
    let report = &result["structuredContent"];
    assert_eq!(result["isError"], true);
    assert_eq!(report["complete"], false);
    assert_eq!(report["error_count"], 130);
    assert_eq!(report["errors"].as_array().unwrap().len(), 100);
    assert_eq!(report["output_truncated"], true);
}

#[test]
fn requested_progress_is_monotonic_and_uses_only_the_given_token() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("first.txt"), "safe").unwrap();
    fs::write(root.path().join("second.txt"), "safe").unwrap();
    let mut client = Client::new(root.path(), 1024, None);
    client.ready();
    let mut request = call(2, "scan_paths", json!({"paths":["."]}));
    request["params"]["_meta"] = json!({"progressToken":"synthetic-progress"});
    client.send(request);
    let mut values = Vec::new();
    loop {
        let response = client.receive();
        if response.get("id").is_some() {
            assert_eq!(response["id"], 2);
            assert_eq!(response["result"]["structuredContent"]["complete"], true);
            break;
        }
        assert_eq!(response["method"], "notifications/progress");
        assert_eq!(response["params"]["progressToken"], "synthetic-progress");
        values.push(response["params"]["progress"].as_u64().unwrap());
    }
    assert_eq!(values.first(), Some(&0));
    assert_eq!(values.last(), Some(&2));
    assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
    client.finish();
}

#[test]
fn active_scan_accepts_ping_and_cancellation_and_rejects_busy_calls() {
    let root = TempDir::new().unwrap();
    for index in 0..2048 {
        fs::write(
            root.path().join(format!("input-{index}.txt")),
            "ordinary data\n".repeat(64),
        )
        .unwrap();
    }
    let mut client = Client::new(root.path(), 4096, None);
    client.ready();
    client.raw(&encode(&[
        call(2, "scan_paths", json!({"paths":["."]})),
        call(3, "scan_text", json!({"text":"safe"})),
        json!({"jsonrpc":"2.0","id":4,"method":"ping"}),
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999}}),
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}),
    ]));
    let responses: Vec<_> = (0..2).map(|_| client.receive()).collect();
    let busy = responses
        .iter()
        .find(|response| response["id"] == 3)
        .unwrap();
    let ping = responses
        .iter()
        .position(|response| response["id"] == 4)
        .unwrap();
    assert_eq!(busy["result"]["isError"], true);
    assert_eq!(busy["result"]["structuredContent"]["complete"], false);
    assert_eq!(responses[ping]["result"], json!({}));
    assert!(
        client
            .responses
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "cancelled request must not emit a final response"
    );
    client.send(call(5, "scan_text", json!({"text":"safe"})));
    let next = client.receive();
    assert_eq!(next["id"], 5);
    assert_eq!(next["result"]["structuredContent"]["complete"], true);
    client.finish();
}

#[test]
fn scan_worker_output_failure_exits_with_error() {
    let root = TempDir::new().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_keyspoor"))
        .arg("mcp")
        .arg("--root")
        .arg(root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    input.write_all(&encode(&[initialize()])).unwrap();
    input.flush().unwrap();
    let mut response = String::new();
    output.read_line(&mut response).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&response).unwrap()["id"], 1);
    drop(output);

    let mut request = call(2, "scan_text", json!({"text":"ordinary data"}));
    request["params"]["_meta"] = json!({"progressToken":"synthetic-progress"});
    input
        .write_all(&encode(&[
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            request,
        ]))
        .unwrap();
    drop(input);
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!result.stderr.is_empty());
}
