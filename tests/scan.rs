use keyspoor::scan::{ScanOptions, scan_history, scan_staged};
use keyspoor::{Engine, EngineConfig};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("-c")
        .arg(format!(
            "core.hooksPath={}",
            repo.join("disabled-hooks").display()
        ))
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
    assert_eq!(report.findings[0].path.as_ref(), "partial.txt");
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
        .map(|finding| finding.path.as_ref())
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

// Windows filesystems cannot create this colon/control-character filename.
#[cfg(unix)]
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
    assert_eq!(report.findings[0].path.as_ref(), path);
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
        keyspoor::scan::scan_reader(&engine, "fixture.txt.gz", compressed.as_slice(), 4096);
    assert!(report.complete);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.stats.detection_passes, 1);
    assert_eq!(report.findings[0].coordinate_space, "archive_member_bytes");
    let broken =
        keyspoor::scan::scan_reader(&engine, "broken.zip", b"PK\x03\x04broken".as_slice(), 4096);
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
    assert_eq!(staged.findings[0].path.as_ref(), member_path);
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
            .find(|finding| finding.path.as_ref() == format!("git:{commit}:{member_path}"))
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
    assert_eq!(
        history.findings[0].path.as_ref(),
        format!("git:{commit}:good.txt")
    );
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
    let report = keyspoor::scan::scan_reader(&engine, "reader-input", FailedReader, 4096);
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
    let report = keyspoor::scan::scan_paths(
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

#[test]
fn filesystem_identity_is_canonical_while_rule_paths_are_root_relative() {
    let dir = TempDir::new().unwrap();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), Some("^nested/fixture\\.txt$"));
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested/fixture.txt"), FIXTURE).unwrap();
    let options = ScanOptions::default();
    let one = keyspoor::scan::scan_paths(&engine, &[dir.path().to_path_buf()], &options).unwrap();
    let alias = keyspoor::scan::scan_paths(&engine, &[dir.path().join(".")], &options).unwrap();
    assert_eq!(one.findings.len(), 1);
    assert_eq!(one.findings[0].path.as_ref(), "nested/fixture.txt");
    assert_eq!(one.findings[0].fingerprint, alias.findings[0].fingerprint);
    assert_eq!(one.context, alias.context);
    let canonical = fs::canonicalize(dir.path().join("nested/fixture.txt")).unwrap();
    let direct = engine
        .scan_bytes_with_identity(
            "nested/fixture.txt",
            canonical.to_str().unwrap(),
            FIXTURE.as_bytes(),
        )
        .unwrap();
    assert_eq!(one.findings[0].fingerprint, direct[0].fingerprint);
}

#[test]
fn filesystem_stream_cancels_after_first_finding_and_reports_partial_counts() {
    use keyspoor::scan::{ScanControl, ScanEvent, scan_paths_stream};
    let dir = TempDir::new().unwrap();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    for index in 0..128 {
        fs::write(dir.path().join(format!("{index}.txt")), FIXTURE).unwrap();
    }
    let control = ScanControl::default();
    let mut findings = 0;
    let mut errors = 0;
    let mut progress = Vec::new();
    let summary = scan_paths_stream(
        &engine,
        &[dir.path().to_path_buf()],
        &ScanOptions {
            threads: 1,
            ..Default::default()
        },
        &control,
        &mut |event| {
            match event {
                ScanEvent::Finding(_) => {
                    findings += 1;
                    control.cancel();
                }
                ScanEvent::Error(_) => errors += 1,
                ScanEvent::Progress(stats) => progress.push(stats),
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(!summary.complete);
    assert_eq!(findings, 1);
    assert_eq!(summary.finding_count, findings);
    assert_eq!(summary.error_count, errors);
    assert!(summary.error_count > 0);
    assert!(summary.stats.files < 128);
    assert!(summary.context.is_some());
    assert_eq!(progress.last().unwrap().files, summary.stats.files);
}

#[test]
fn filesystem_stream_sink_failure_stops_delivery_without_deadlocking_workers() {
    use keyspoor::scan::{ScanControl, scan_paths_stream};
    let dir = TempDir::new().unwrap();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    for index in 0..64 {
        fs::write(dir.path().join(format!("{index}.txt")), FIXTURE).unwrap();
    }
    let control = ScanControl::default();
    let mut calls = 0;
    let result = scan_paths_stream(
        &engine,
        &[dir.path().to_path_buf()],
        &ScanOptions {
            threads: 2,
            ..Default::default()
        },
        &control,
        &mut |_| {
            calls += 1;
            anyhow::bail!("synthetic writer failure")
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("synthetic writer failure")
    );
    assert_eq!(calls, 1);
    assert!(control.is_cancelled());
}

#[test]
fn filesystem_context_changes_when_ignore_policy_changes() {
    let dir = TempDir::new().unwrap();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::write(dir.path().join("fixture.txt"), FIXTURE).unwrap();
    fs::write(dir.path().join(".gitignore"), "unrelated.txt\n").unwrap();
    let before = keyspoor::scan::scan_paths(
        &engine,
        &[dir.path().to_path_buf()],
        &ScanOptions::default(),
    )
    .unwrap();
    fs::write(dir.path().join(".gitignore"), "fixture.txt\n").unwrap();
    let after = keyspoor::scan::scan_paths(
        &engine,
        &[dir.path().to_path_buf()],
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(before.complete && after.complete);
    assert_eq!(before.findings.len(), 1);
    assert!(after.findings.is_empty());
    assert_ne!(
        before.context.unwrap().selection_policy_id,
        after.context.unwrap().selection_policy_id
    );
}

#[test]
fn git_history_range_selects_complete_commit_snapshots_and_rejects_options() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::write(dir.path().join("fixture.txt"), FIXTURE).unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "first"]);
    let first = git(dir.path(), &["rev-parse", "HEAD"]);
    git(dir.path(), &["commit", "--allow-empty", "-qm", "second"]);
    let second = git(dir.path(), &["rev-parse", "HEAD"]);
    let report = keyspoor::scan::scan_history_range(
        &engine,
        dir.path(),
        &format!("{first}..{second}"),
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(report.complete);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].path.as_ref(),
        format!("git:{second}:fixture.txt")
    );
    assert_eq!(report.stats.detection_passes, 1);
    assert!(
        keyspoor::scan::scan_history_range(&engine, dir.path(), "--all", &ScanOptions::default())
            .is_err()
    );
}

#[test]
fn git_stream_cancels_projection_and_sink_failure_is_returned() {
    use keyspoor::scan::{ScanControl, ScanEvent, scan_history_stream, scan_staged_stream};
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::write(dir.path().join("fixture.txt"), FIXTURE).unwrap();
    git(dir.path(), &["add", "."]);
    let control = ScanControl::default();
    let error = scan_staged_stream(
        &engine,
        dir.path(),
        &ScanOptions::default(),
        &control,
        &mut |_| anyhow::bail!("synthetic sink failure"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("synthetic sink failure"));
    assert!(control.is_cancelled());
    git(dir.path(), &["commit", "-qm", "first"]);
    for _ in 0..5 {
        git(dir.path(), &["commit", "--allow-empty", "-qm", "same tree"]);
    }
    let control = ScanControl::default();
    let summary = scan_history_stream(
        &engine,
        dir.path(),
        &ScanOptions::default(),
        &control,
        &mut |event| {
            if matches!(event, ScanEvent::Finding(_)) {
                control.cancel();
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(!summary.complete);
    assert_eq!(summary.finding_count, 1);
    assert_eq!(summary.stats.files, 1);
    assert_eq!(summary.stats.detection_passes, 1);
    assert_eq!(summary.error_count, 1);
}

#[test]
fn linked_worktree_context_tracks_shared_git_exclude_policy() {
    let main = repo();
    let linked = TempDir::new().unwrap();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::write(main.path().join("fixture.txt"), FIXTURE).unwrap();
    git(main.path(), &["add", "."]);
    git(main.path(), &["commit", "-qm", "fixture"]);
    git(
        main.path(),
        &[
            "worktree",
            "add",
            "--detach",
            linked.path().to_str().unwrap(),
            "HEAD",
        ],
    );
    assert!(linked.path().join(".git").is_file());
    let before = keyspoor::scan::scan_paths(
        &engine,
        &[linked.path().to_path_buf()],
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(before.complete, "{:?}", before.errors);
    assert_eq!(before.findings.len(), 1);
    fs::write(main.path().join(".git/info/exclude"), "fixture.txt\n").unwrap();
    let after = keyspoor::scan::scan_paths(
        &engine,
        &[linked.path().to_path_buf()],
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(after.complete, "{:?}", after.errors);
    assert!(after.findings.is_empty());
    assert_ne!(
        before.context.unwrap().selection_policy_id,
        after.context.unwrap().selection_policy_id
    );
}

#[test]
fn git_subdirectory_scan_matches_repository_root_scope_and_identity() {
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("root.txt"), FIXTURE).unwrap();
    fs::write(dir.path().join("nested/fixture.txt"), FIXTURE).unwrap();
    git(dir.path(), &["add", "."]);
    let options = ScanOptions::default();
    let root = scan_staged(&engine, dir.path(), &options).unwrap();
    let child = scan_staged(&engine, &dir.path().join("nested"), &options).unwrap();
    assert_eq!(root.findings.len(), 2);
    assert_eq!(child.findings, root.findings);
    assert_eq!(child.context, root.context);
    git(dir.path(), &["commit", "-qm", "root and nested"]);
    let root = scan_history(&engine, dir.path(), &options).unwrap();
    let child = scan_history(&engine, &dir.path().join("nested"), &options).unwrap();
    assert_eq!(root.findings.len(), 2);
    assert_eq!(child.findings, root.findings);
    assert_eq!(child.context, root.context);
}

#[test]
fn bare_git_history_uses_repository_root_context_and_invalid_repo_is_an_error() {
    let dir = repo();
    let bare = TempDir::new().unwrap();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    fs::write(dir.path().join("fixture.txt"), FIXTURE).unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "fixture"]);
    git(
        dir.path(),
        &[
            "clone",
            "--bare",
            "--local",
            ".",
            bare.path().to_str().unwrap(),
        ],
    );
    let root = scan_history(&engine, bare.path(), &ScanOptions::default()).unwrap();
    let child = scan_history(
        &engine,
        &bare.path().join("objects"),
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(root.complete);
    assert_eq!(root.findings.len(), 1);
    assert_eq!(child.findings, root.findings);
    assert_eq!(child.context, root.context);
    let invalid = TempDir::new().unwrap();
    assert!(scan_history(&engine, invalid.path(), &ScanOptions::default()).is_err());
}

#[test]
fn removing_root_repository_boundary_changes_context_before_resolution() {
    let parent = TempDir::new().unwrap();
    let root = parent.path().join("scan-root");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join(".git")).unwrap();
    fs::write(parent.path().join(".gitignore"), "secret.txt\n").unwrap();
    fs::write(root.join("secret.txt"), FIXTURE).unwrap();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    let before = keyspoor::scan::scan_paths(
        &engine,
        std::slice::from_ref(&root),
        &ScanOptions::default(),
    )
    .unwrap();
    fs::remove_dir(root.join(".git")).unwrap();
    let after = keyspoor::scan::scan_paths(
        &engine,
        std::slice::from_ref(&root),
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(before.complete && after.complete);
    assert_eq!(before.findings.len(), 1);
    assert!(after.findings.is_empty());
    assert_ne!(
        before.context, after.context,
        "repository-boundary changes must invalidate scope compatibility"
    );
}

#[test]
fn removing_nested_vcs_boundary_changes_context_with_unchanged_ignore_contents() {
    for marker in [".git", ".jj"] {
        let root = TempDir::new().unwrap();
        let child = root.path().join("child");
        fs::create_dir(root.path().join(".git")).unwrap();
        fs::create_dir(&child).unwrap();
        fs::create_dir(child.join(marker)).unwrap();
        fs::write(root.path().join(".gitignore"), "secret.txt\n").unwrap();
        fs::write(child.join("secret.txt"), FIXTURE).unwrap();
        let rules = TempDir::new().unwrap();
        let engine = engine(rules.path(), None);
        let before = keyspoor::scan::scan_paths(
            &engine,
            &[root.path().to_path_buf()],
            &ScanOptions::default(),
        )
        .unwrap();
        fs::remove_dir(child.join(marker)).unwrap();
        let after = keyspoor::scan::scan_paths(
            &engine,
            &[root.path().to_path_buf()],
            &ScanOptions::default(),
        )
        .unwrap();
        assert!(before.complete && after.complete);
        assert_eq!(before.findings.len(), 1, "{marker}");
        assert!(after.findings.is_empty(), "{marker}");
        assert_ne!(
            before.context, after.context,
            "{marker} boundary removal must invalidate scope compatibility"
        );
    }
}

fn assert_throttled_progress(
    progress: &[keyspoor::ScanStats],
    summary: &keyspoor::scan::ScanSummary,
) {
    assert!(!progress.is_empty());
    let final_stats = progress.last().unwrap();
    assert_eq!(
        serde_json::to_value(final_stats).unwrap(),
        serde_json::to_value(&summary.stats).unwrap()
    );
    // The final snapshot is mandatory even when less than 100 ms has passed.
    for pair in progress[..progress.len() - 1].windows(2) {
        assert!(pair[1].elapsed_ms.saturating_sub(pair[0].elapsed_ms) >= 100);
    }
}

#[test]
fn filesystem_progress_is_throttled_without_losing_findings_or_final_stats() {
    use keyspoor::scan::{ScanControl, ScanEvent, scan_paths_stream};
    let dir = TempDir::new().unwrap();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    for index in 0..128 {
        fs::write(dir.path().join(format!("{index}.txt")), FIXTURE).unwrap();
    }
    let mut progress = Vec::new();
    let mut findings = 0;
    let summary = scan_paths_stream(
        &engine,
        &[dir.path().to_path_buf()],
        &ScanOptions::default(),
        &ScanControl::default(),
        &mut |event| {
            match event {
                ScanEvent::Finding(_) => findings += 1,
                ScanEvent::Progress(stats) => progress.push(stats),
                ScanEvent::Error(error) => panic!("unexpected scan error: {error:?}"),
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(summary.complete);
    assert_eq!(summary.stats.files, 128);
    assert_eq!(findings, 128);
    assert_eq!(summary.finding_count, findings);
    assert_eq!(progress.first().unwrap().files, 1);
    assert_throttled_progress(&progress, &summary);
}

#[test]
fn git_metadata_and_blob_progress_share_one_throttle_and_keep_final_stats() {
    use keyspoor::scan::{ScanControl, ScanEvent, scan_history_stream, scan_staged_stream};
    let dir = repo();
    let rules = TempDir::new().unwrap();
    let engine = engine(rules.path(), None);
    for index in 0..3 {
        fs::write(dir.path().join(format!("{index}.txt")), FIXTURE).unwrap();
        git(dir.path(), &["add", "."]);
        git(dir.path(), &["commit", "-qm", "synthetic snapshot"]);
    }
    for staged in [false, true] {
        if staged {
            fs::write(dir.path().join("staged.txt"), FIXTURE).unwrap();
            git(dir.path(), &["add", "."]);
        }
        let mut progress = Vec::new();
        let mut findings = 0;
        let mut sink = |event| {
            match event {
                ScanEvent::Finding(_) => findings += 1,
                ScanEvent::Progress(stats) => progress.push(stats),
                ScanEvent::Error(error) => panic!("unexpected scan error: {error:?}"),
            }
            Ok(())
        };
        let scan = if staged {
            scan_staged_stream
        } else {
            scan_history_stream
        };
        let summary = scan(
            &engine,
            dir.path(),
            &ScanOptions::default(),
            &ScanControl::default(),
            &mut sink,
        )
        .unwrap();
        assert!(summary.complete);
        assert_eq!(findings, if staged { 1 } else { 6 });
        assert_eq!(summary.finding_count, findings);
        assert_eq!(progress.first().unwrap().files, u64::from(staged));
        assert_throttled_progress(&progress, &summary);
    }
}
