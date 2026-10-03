use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn setup() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let rule = dir.path().join("rules.json");
    fs::write(&rule, r#"{"rules":[{"id":"canary","name":"Test canary","pattern":"CANARY_[a-z0-9]{16}","keywords":["CANARY_"],"confidence":"high"}]}"#).unwrap();
    (dir, rule)
}

fn cli(rule: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_secret-scan"));
    cmd.args(["--no-builtin", "--rules"]).arg(rule);
    cmd
}

#[test]
fn cli_distinguishes_clean_finding_and_missing_input_and_redacts() {
    let (dir, rule) = setup();
    let path = dir.path().join("input.txt");
    fs::write(&path, "ordinary text\n").unwrap();
    let clean = cli(&rule).arg("scan").arg(&path).output().unwrap();
    assert_eq!(clean.status.code(), Some(0));
    fs::write(&path, "CANARY_abc123def456gh78\n").unwrap();
    let finding = cli(&rule).arg("scan").arg(&path).output().unwrap();
    assert_eq!(finding.status.code(), Some(1));
    let text = String::from_utf8(finding.stdout).unwrap();
    assert!(!text.contains("abc123def456gh78"));
    let report: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["complete"], true);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    let missing = cli(&rule)
        .arg("scan")
        .arg(dir.path().join("absent"))
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(report["complete"], false);
}

#[test]
fn baseline_suppresses_existing_but_not_changed_secret_and_survives_error() {
    let (dir, rule) = setup();
    let path = dir.path().join("input.txt");
    let baseline = dir.path().join("baseline.json");
    fs::write(&path, "CANARY_abc123def456gh78\n").unwrap();
    let saved = cli(&rule)
        .arg("scan")
        .arg(&path)
        .arg("--write-baseline")
        .arg(&baseline)
        .output()
        .unwrap();
    assert_eq!(saved.status.code(), Some(1));
    let original = fs::read(&baseline).unwrap();
    let same = cli(&rule)
        .arg("scan")
        .arg(&path)
        .arg("--baseline")
        .arg(&baseline)
        .output()
        .unwrap();
    assert_eq!(same.status.code(), Some(0));
    fs::write(&path, "CANARY_def123abc456gh78\n").unwrap();
    let new = cli(&rule)
        .arg("scan")
        .arg(&path)
        .arg("--baseline")
        .arg(&baseline)
        .output()
        .unwrap();
    assert_eq!(new.status.code(), Some(1));
    let failed = cli(&rule)
        .arg("scan")
        .arg(dir.path().join("absent"))
        .arg("--write-baseline")
        .arg(&baseline)
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(2));
    assert_eq!(fs::read(&baseline).unwrap(), original);
}

#[test]
fn persistent_scanner_recovers_after_malformed_request_without_echoing_it() {
    let (_dir, rule) = setup();
    let mut child = cli(&rule)
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let input = child.stdin.as_mut().unwrap();
        writeln!(input, "THIS_IS_SENSITIVE_BUT_INVALID_JSON").unwrap();
        writeln!(
            input,
            "{}",
            serde_json::json!({"id":7,"path":"test.txt","text":"CANARY_abc123def456gh78"})
        )
        .unwrap();
        writeln!(input, "{}", serde_json::json!({"id":8,"text":"clean"})).unwrap();
    }
    drop(child.stdin.take());
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(!text.contains("SENSITIVE"));
    assert!(!text.contains("abc123def456gh78"));
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0]["error"].is_string());
    assert_eq!(lines[1]["result"]["findings"].as_array().unwrap().len(), 1);
    assert_eq!(lines[2]["result"]["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn baseline_rejects_narrowed_scope_and_policy_changes_without_overwrite() {
    let (dir, rule) = setup();
    let root = dir.path().join("source");
    fs::create_dir_all(root.join("clean")).unwrap();
    fs::write(root.join("secret.txt"), "CANARY_abc123def456gh78").unwrap();
    let baseline = dir.path().join("baseline.json");
    assert_eq!(
        cli(&rule)
            .arg("scan")
            .arg(&root)
            .arg("--write-baseline")
            .arg(&baseline)
            .output()
            .unwrap()
            .status
            .code(),
        Some(1)
    );
    let original = fs::read(&baseline).unwrap();
    for switch in ["--baseline", "--write-baseline"] {
        let output = cli(&rule)
            .arg("scan")
            .arg(root.join("clean"))
            .arg(switch)
            .arg(&baseline)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(fs::read(&baseline).unwrap(), original);
    }
    for extra in ["--no-ignore", "--no-decode"] {
        let output = cli(&rule)
            .arg("scan")
            .arg(&root)
            .arg(extra)
            .arg("--write-baseline")
            .arg(&baseline)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(fs::read(&baseline).unwrap(), original);
    }
    fs::write(root.join(".ignore"), "secret.txt\n").unwrap();
    let output = cli(&rule)
        .arg("scan")
        .arg(&root)
        .arg("--write-baseline")
        .arg(&baseline)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(&baseline).unwrap(), original);
}

#[test]
fn jsonl_events_preserve_findings_errors_and_exit_contract() {
    let (dir, rule) = setup();
    let input = dir.path().join("input.txt");
    fs::write(&input, "CANARY_abc123def456gh78").unwrap();
    let output = cli(&rule)
        .arg("scan")
        .arg(&input)
        .arg("--format=jsonl")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(events.iter().filter(|e| e["type"] == "finding").count(), 1);
    let summary = events.last().unwrap();
    assert_eq!(summary["type"], "summary");
    assert_eq!(summary["complete"], true);
    assert_eq!(summary["finding_count"], 1);
    assert_eq!(summary["error_count"], 0);
    let missing = cli(&rule)
        .arg("scan")
        .arg(dir.path().join("missing"))
        .arg("--format=jsonl")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    let events: Vec<serde_json::Value> = String::from_utf8(missing.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert!(events.iter().any(|e| e["type"] == "error"));
    assert_eq!(events.last().unwrap()["complete"], false);
}

#[test]
fn history_range_is_rejected_for_file_scans() {
    let (_dir, rule) = setup();
    assert_eq!(
        cli(&rule)
            .args(["scan", "--range", "HEAD~1..HEAD"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
}
