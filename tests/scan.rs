use secret_scan::scan::{ScanOptions, scan_history, scan_staged};
use secret_scan::{Engine, EngineConfig};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn repo() -> TempDir {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(dir.path(), &["config", "user.name", "Synthetic Test"]);
    git(
        dir.path(),
        &["config", "user.email", "synthetic@example.invalid"],
    );
    git(dir.path(), &["config", "commit.gpgsign", "false"]);
    dir
}

fn engine(dir: &Path, path_pattern: Option<&str>) -> Engine {
    let rules = dir.join("test-rules.json");
    fs::write(&rules, serde_json::to_vec(&serde_json::json!({"rules":[{
        "id":"synthetic.fixture", "name":"Synthetic fixture", "pattern":"fixture_(?P<TOKEN>[A-Za-z0-9]{24})",
        "secret_group":1, "keywords":["fixture_"], "min_entropy":0, "confidence":"high", "path":path_pattern
    }]})).unwrap()).unwrap();
    Engine::new(EngineConfig {
        builtin_rules: false,
        custom_rule_paths: vec![rules],
        ..Default::default()
    })
    .unwrap()
}

const FIXTURE: &str = "fixture_SyntheticOnly00000000000\n";

#[test]
fn staged_reads_index_when_worktree_has_changed() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    let file = dir.path().join("partial.txt");
    fs::write(&file, FIXTURE).unwrap();
    git(dir.path(), &["add", "partial.txt"]);
    fs::write(&file, "clean worktree\n").unwrap();
    let report = scan_staged(&engine, dir.path(), &ScanOptions::default()).unwrap();
    assert!(report.complete);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].path, "partial.txt");
    fs::write(&file, "clean index\n").unwrap();
    git(dir.path(), &["add", "partial.txt"]);
    fs::write(&file, FIXTURE).unwrap();
    let report = scan_staged(&engine, dir.path(), &ScanOptions::default()).unwrap();
    assert!(report.complete);
    assert!(report.findings.is_empty());
}

#[test]
fn history_reuses_blob_reads_but_respects_every_path_and_commit() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), Some("z-target\\.txt$"));
    fs::write(dir.path().join("a-other.txt"), FIXTURE).unwrap();
    fs::write(dir.path().join("z-target.txt"), FIXTURE).unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "first"]);
    let first = git(dir.path(), &["rev-parse", "HEAD"]);
    git(dir.path(), &["commit", "--allow-empty", "-qm", "second"]);
    let second = git(dir.path(), &["rev-parse", "HEAD"]);
    let report = scan_history(&engine, dir.path(), &ScanOptions::default()).unwrap();
    assert!(report.complete);
    assert_eq!(report.stats.files, 1);
    assert_eq!(report.stats.bytes, FIXTURE.len() as u64);
    assert_eq!(report.findings.len(), 2);
    assert_eq!(report.stats.detection_passes, 2);
    let paths: Vec<_> = report
        .findings
        .iter()
        .map(|finding| finding.path.as_str())
        .collect();
    assert!(paths.contains(&format!("git:{first}:z-target.txt").as_str()));
    assert!(paths.contains(&format!("git:{second}:z-target.txt").as_str()));
}

#[test]
fn blob_size_limit_preserves_partial_status_and_continues() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::write(dir.path().join("large.txt"), "X".repeat(1024)).unwrap();
    fs::write(dir.path().join("small.txt"), FIXTURE).unwrap();
    git(dir.path(), &["add", "."]);
    let options = ScanOptions {
        max_bytes: FIXTURE.len() as u64,
        ..Default::default()
    };
    let staged = scan_staged(&engine, dir.path(), &options).unwrap();
    assert!(!staged.complete);
    assert_eq!(staged.exit_code(), 2);
    assert_eq!(staged.stats.skipped, 1);
    assert_eq!(staged.stats.files, 1);
    assert_eq!(staged.findings.len(), 1);
    git(dir.path(), &["commit", "-qm", "limits"]);
    let history = scan_history(&engine, dir.path(), &options).unwrap();
    assert!(!history.complete);
    assert_eq!(history.exit_code(), 2);
    assert_eq!(history.stats.skipped, 1);
    assert_eq!(history.stats.files, 1);
    assert_eq!(history.findings.len(), 1);
}

#[test]
fn missing_git_objects_are_errors_not_clean_reports() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::write(dir.path().join("fixture.txt"), FIXTURE).unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "missing blob"]);
    let oid = git(dir.path(), &["rev-parse", "HEAD:fixture.txt"]);
    fs::remove_file(
        dir.path()
            .join(".git/objects")
            .join(&oid[..2])
            .join(&oid[2..]),
    )
    .unwrap();
    assert!(scan_history(&engine, dir.path(), &ScanOptions::default()).is_err());
}

#[test]
fn staged_handles_git_paths_containing_protocol_delimiters() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    let path = "colon:name\tline\nbreak.txt";
    fs::write(dir.path().join(path), FIXTURE).unwrap();
    git(dir.path(), &["add", "--", path]);
    let report = scan_staged(&engine, dir.path(), &ScanOptions::default()).unwrap();
    assert!(report.complete);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].path, path);
}

#[test]
fn empty_blob_at_zero_byte_limit_is_a_complete_scan() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::write(dir.path().join("empty.txt"), "").unwrap();
    git(dir.path(), &["add", "."]);
    let options = ScanOptions {
        max_bytes: 0,
        ..Default::default()
    };
    let report = scan_staged(&engine, dir.path(), &options).unwrap();
    assert!(report.complete);
    assert!(report.findings.is_empty());
    assert_eq!(report.stats.files, 1);
    assert_eq!(report.stats.bytes, 0);
}

#[test]
fn reader_integrates_archive_decoding_and_corruption_status() {
    use std::io::Write;
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(FIXTURE.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let report =
        secret_scan::scan::scan_reader(&engine, "fixture.txt.gz", compressed.as_slice(), 4096);
    assert!(report.complete);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.stats.detection_passes, 1);
    assert_eq!(report.findings[0].coordinate_space, "archive_member_bytes");
    let broken =
        secret_scan::scan::scan_reader(&engine, "broken.zip", b"PK\x03\x04broken".as_slice(), 4096);
    assert!(!broken.complete);
    assert_eq!(broken.exit_code(), 2);
}

fn gzip_fixture(content: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(content).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn git_archives_preserve_index_member_paths_fingerprints_and_every_commit() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), Some("z-target\\.txt\\.gz!z-target\\.txt$"));
    let compressed = gzip_fixture(FIXTURE.as_bytes());
    fs::write(dir.path().join("a-other.txt.gz"), &compressed).unwrap();
    fs::write(dir.path().join("z-target.txt.gz"), &compressed).unwrap();
    git(dir.path(), &["add", "."]);
    // Index content must continue to win even for archive inputs.
    fs::write(
        dir.path().join("z-target.txt.gz"),
        "broken worktree archive",
    )
    .unwrap();
    let staged = scan_staged(&engine, dir.path(), &ScanOptions::default()).unwrap();
    let member_path = "z-target.txt.gz!z-target.txt";
    let direct = engine.scan_bytes(member_path, FIXTURE.as_bytes()).unwrap();
    assert!(staged.complete);
    assert_eq!(staged.stats.files, 1);
    assert_eq!(staged.stats.bytes, compressed.len() as u64);
    assert_eq!(staged.stats.detection_passes, 2);
    assert_eq!(staged.findings.len(), 1);
    assert_eq!(staged.findings[0].path, member_path);
    assert_eq!(staged.findings[0].fingerprint, direct[0].fingerprint);
    assert_eq!(staged.findings[0].coordinate_space, "archive_member_bytes");

    git(dir.path(), &["commit", "-qm", "archive first"]);
    let first = git(dir.path(), &["rev-parse", "HEAD"]);
    git(
        dir.path(),
        &["commit", "--allow-empty", "-qm", "archive second"],
    );
    let second = git(dir.path(), &["rev-parse", "HEAD"]);
    let history = scan_history(&engine, dir.path(), &ScanOptions::default()).unwrap();
    assert!(history.complete);
    assert_eq!(history.stats.files, 1);
    assert_eq!(history.stats.bytes, compressed.len() as u64);
    assert_eq!(history.stats.detection_passes, 2);
    assert_eq!(history.findings.len(), 2);
    for commit in [first, second] {
        let finding = history
            .findings
            .iter()
            .find(|finding| finding.path == format!("git:{commit}:{member_path}"))
            .unwrap();
        assert_eq!(finding.fingerprint, direct[0].fingerprint);
        assert_eq!(finding.coordinate_space, "archive_member_bytes");
    }
}

#[test]
fn git_archive_errors_and_expansion_limits_remain_incomplete_with_other_findings() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    let oversized = gzip_fixture(&vec![b'X'; 4096]);
    assert!(oversized.len() < 256);
    fs::write(dir.path().join("oversized.txt.gz"), oversized).unwrap();
    fs::write(dir.path().join("broken.zip"), b"PK\x03\x04broken").unwrap();
    fs::write(dir.path().join("good.txt"), FIXTURE).unwrap();
    git(dir.path(), &["add", "."]);
    let options = ScanOptions {
        max_bytes: 256,
        ..Default::default()
    };
    let staged = scan_staged(&engine, dir.path(), &options).unwrap();
    assert!(!staged.complete);
    assert_eq!(staged.exit_code(), 2);
    assert_eq!(staged.findings.len(), 1);
    assert_eq!(staged.stats.skipped, 1);
    assert!(staged.errors.iter().any(|error| error.path == "broken.zip"));
    assert!(
        staged
            .errors
            .iter()
            .any(|error| error.path == "oversized.txt.gz!oversized.txt")
    );

    git(dir.path(), &["commit", "-qm", "partial archives"]);
    let commit = git(dir.path(), &["rev-parse", "HEAD"]);
    let history = scan_history(&engine, dir.path(), &options).unwrap();
    assert!(!history.complete);
    assert_eq!(history.exit_code(), 2);
    assert_eq!(history.findings.len(), 1);
    assert_eq!(history.stats.skipped, 1);
    assert_eq!(history.findings[0].path, format!("git:{commit}:good.txt"));
    assert!(
        history
            .errors
            .iter()
            .any(|error| error.path == format!("git:{commit}:broken.zip"))
    );
    assert!(
        history
            .errors
            .iter()
            .any(|error| error.path == format!("git:{commit}:oversized.txt.gz!oversized.txt"))
    );
}

#[test]
fn reader_errors_keep_kind_without_echoing_untrusted_details() {
    const SYNTHETIC: &str = "synthetic-sensitive-read-error-value";
    struct FailedReader;
    impl std::io::Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                SYNTHETIC,
            ))
        }
    }
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    let report = secret_scan::scan::scan_reader(&engine, "reader-input", FailedReader, 4096);
    assert!(!report.complete);
    assert_eq!(report.exit_code(), 2);
    assert_eq!(report.errors[0].path, "reader-input");
    assert!(report.errors[0].message.contains("PermissionDenied"));
    assert!(!serde_json::to_string(&report).unwrap().contains(SYNTHETIC));
}

#[test]
fn invalid_ignore_rules_are_incomplete_without_echoing_rule_contents() {
    const SYNTHETIC: &str = "synthetic-sensitive-ignore-rule-value";
    let dir = TempDir::new().unwrap();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::write(dir.path().join(".gitignore"), format!("{SYNTHETIC}[z-a]\n")).unwrap();
    fs::write(dir.path().join("good.txt"), FIXTURE).unwrap();
    let report = secret_scan::scan::scan_paths(
        &engine,
        &[dir.path().to_path_buf()],
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(!report.complete);
    assert_eq!(report.exit_code(), 2);
    assert!(!report.errors.is_empty());
    assert_eq!(report.findings.len(), 1);
    assert!(!serde_json::to_string(&report).unwrap().contains(SYNTHETIC));
}
