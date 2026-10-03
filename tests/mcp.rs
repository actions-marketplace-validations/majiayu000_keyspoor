use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

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

fn run(root: &Path, bytes: &[u8], max_bytes: u64, rules: Option<&Path>) -> Vec<Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secret-scan"));
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
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "unexpected diagnostic output");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("stdout contains only JSON-RPC messages"))
        .collect()
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
