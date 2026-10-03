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
