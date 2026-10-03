use secret_scan::baseline::Baseline;
use secret_scan::context::{ScanContext, policy_digest};
use secret_scan::report::{OutputFormat, write_report};
use secret_scan::{Finding, ScanError, ScanReport, ScanStats};
use serde_json::Value;

fn finding(fingerprint: &str, path: &str) -> Finding {
    Finding {
        rule_id: "test-rule".into(),
        path: path.into(),
        start: 0,
        end: 10,
        line: 1,
        column: 1,
        redacted: "[REDACTED]".into(),
        fingerprint: fingerprint.into(),
        explanation: "Synthetic fixture \"quoted\"\nexplanation".into(),
        ..Default::default()
    }
}

fn report(findings: Vec<Finding>) -> ScanReport {
    ScanReport {
        schema_version: 1,
        context: Some(ScanContext {
            mode: "filesystem".into(),
            roots: vec!["/synthetic/fixture".into()],
            engine_configuration_id: "synthetic-engine-policy".into(),
            selection_policy_id: policy_digest(&[b"max_bytes=1024", b"ignore=true"]),
        }),
        complete: true,
        findings,
        errors: vec![],
        stats: ScanStats {
            detection_passes: 2,
            files: 2,
            bytes: 80,
            skipped: 0,
            elapsed_ms: 1,
        },
    }
}

#[test]
fn jsonl_escapes_records_and_marks_incomplete_summary() {
    let mut scan = report(vec![finding("one", "file\n\"name.txt")]);
    scan.complete = false;
    scan.errors.push(ScanError {
        path: "failed".into(),
        message: "unreadable".into(),
    });
    let mut out = Vec::new();
    write_report(&scan, OutputFormat::Jsonl, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["type"], "finding");
    assert_eq!(records[0]["finding"]["path"], "file\n\"name.txt");
    assert_eq!(records[1]["type"], "error");
    assert_eq!(records[1]["error"]["path"], "failed");
    assert_eq!(records[1]["error"]["message"], "unreadable");
    assert_eq!(records[2]["type"], "summary");
    assert_eq!(records[2]["complete"], false);
    assert_eq!(records[2]["finding_count"], 1);
    assert_eq!(records[2]["error_count"], 1);
    assert_eq!(
        records[2]["context"],
        serde_json::to_value(&scan.context).unwrap()
    );
    assert!(records[2].get("errors").is_none());
    assert!(!text.contains("\"raw\""));
}

#[test]
fn sarif_preserves_locations_and_completion() {
    let mut scan = report(vec![finding("one", "folder/a b#c.txt")]);
    scan.complete = false;
    scan.errors.push(ScanError {
        path: "missing".into(),
        message: "unreadable".into(),
    });
    let mut out = Vec::new();
    write_report(&scan, OutputFormat::Sarif, &mut out).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    let run = &doc["runs"][0];
    assert_eq!(doc["version"], "2.1.0");
    assert_eq!(run["invocations"][0]["executionSuccessful"], false);
    let location = &run["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(location["artifactLocation"]["uri"], "folder/a%20b%23c.txt");
    assert_eq!(location["region"]["startLine"], 1);
    assert_eq!(
        run["results"][0]["partialFingerprints"]["secretFingerprint/v1"],
        "one"
    );
}

#[test]
fn baseline_tracks_secret_identity_and_retains_human_labels() {
    let before = report(vec![finding("stay", "old.txt"), finding("gone", "old.txt")]);
    let mut baseline = Baseline::from_report(&before, None).unwrap();
    baseline.entries.get_mut("stay").unwrap().disposition = Some("accepted: local fixture".into());
    let after = report(vec![
        finding("stay", "moved.txt"),
        finding("new", "old.txt"),
    ]);
    let diff = baseline.diff(&after).unwrap();
    assert!(diff.complete);
    assert_eq!(diff.new.len(), 1);
    assert_eq!(diff.new[0].fingerprint, "new");
    assert_eq!(diff.resolved.len(), 1);
    assert_eq!(diff.resolved[0].finding.fingerprint, "gone");
    let refreshed = Baseline::from_report(&after, Some(&baseline)).unwrap();
    assert_eq!(
        refreshed.entries["stay"].disposition.as_deref(),
        Some("accepted: local fixture")
    );
    assert_eq!(refreshed.entries["stay"].finding.path, "moved.txt");
    let mut out = Vec::new();
    refreshed.write(&mut out).unwrap();
    let roundtrip = Baseline::read(out.as_slice()).unwrap();
    assert_eq!(roundtrip.schema_version, 2);
    assert_eq!(roundtrip.context, refreshed.context);
    assert_eq!(
        roundtrip.entries["stay"].disposition,
        refreshed.entries["stay"].disposition
    );
}

#[test]
fn invalid_baselines_fail_instead_of_becoming_empty() {
    for bytes in [
        b"not json".as_slice(),
        br#"{}"#,
        br#"{"schema_version":999,"entries":{}}"#,
    ] {
        assert!(Baseline::read(bytes).is_err());
    }
    let mut doc = serde_json::to_value(
        Baseline::from_report(&report(vec![finding("one", "a")]), None).unwrap(),
    )
    .unwrap();
    doc["entries"]["one"]["finding"]["fingerprint"] = Value::String("different".into());
    assert!(Baseline::read(serde_json::to_vec(&doc).unwrap().as_slice()).is_err());
}

#[test]
fn incomplete_scan_does_not_resolve_or_erase_baseline() {
    let baseline = Baseline::from_report(&report(vec![finding("keep", "a")]), None).unwrap();
    let mut incomplete = report(vec![]);
    incomplete.complete = false;
    let diff = baseline.diff(&incomplete).unwrap();
    assert!(!diff.complete);
    assert!(diff.resolved.is_empty());
    assert!(Baseline::from_report(&incomplete, Some(&baseline)).is_err());
}

#[test]
fn output_writer_failures_are_propagated() {
    struct FailedWriter;
    impl std::io::Write for FailedWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("output closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for format in [OutputFormat::Json, OutputFormat::Jsonl, OutputFormat::Sarif] {
        assert!(write_report(&report(vec![finding("one", "a")]), format, FailedWriter).is_err());
    }
}

#[test]
fn baseline_parse_errors_never_echo_input_values_or_reader_errors() {
    const SYNTHETIC: &str = "synthetic-sensitive-value-for-error-test";
    let json = serde_json::json!({"schema_version": SYNTHETIC, "entries": {}});
    let error = Baseline::read(serde_json::to_vec(&json).unwrap().as_slice()).unwrap_err();
    let message = format!("{error:#}");
    assert!(!message.contains(SYNTHETIC));
    assert!(message.contains("Data"));
    assert!(message.contains("line 1"));
    assert!(message.contains("column"));
    assert_eq!(error.chain().count(), 1);

    struct FailedReader;
    impl std::io::Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other(SYNTHETIC))
        }
    }
    let error = Baseline::read(FailedReader).unwrap_err();
    let message = format!("{error:#}");
    assert!(!message.contains(SYNTHETIC));
    assert!(message.contains("Io"));
    assert_eq!(error.chain().count(), 1);
}

#[test]
fn report_errors_prevent_baseline_updates_and_resolution_even_if_complete_is_true() {
    let baseline = Baseline::from_report(&report(vec![finding("keep", "a")]), None).unwrap();
    let mut inconsistent = report(vec![finding("new", "b")]);
    inconsistent.errors.push(ScanError {
        path: "failed".into(),
        message: "unreadable".into(),
    });
    assert!(inconsistent.complete);
    assert_eq!(inconsistent.exit_code(), 2);
    assert!(Baseline::from_report(&inconsistent, Some(&baseline)).is_err());
    let diff = baseline.diff(&inconsistent).unwrap();
    assert!(!diff.complete);
    assert!(diff.resolved.is_empty());
    assert_eq!(diff.new.len(), 1);
    assert_eq!(diff.new[0].fingerprint, "new");
}

#[test]
fn baselines_require_explicit_context_and_reject_legacy_schema() {
    let scan = report(vec![finding("existing", "a")]);
    let baseline = Baseline::from_report(&scan, None).unwrap();
    let mut unscoped = scan;
    unscoped.context = None;
    assert!(Baseline::from_report(&unscoped, None).is_err());
    assert!(baseline.diff(&unscoped).is_err());

    let mut doc = serde_json::to_value(&baseline).unwrap();
    doc["schema_version"] = Value::from(1);
    let error = Baseline::read(serde_json::to_vec(&doc).unwrap().as_slice()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported baseline schema version 1")
    );
    doc["schema_version"] = Value::from(2);
    doc.as_object_mut().unwrap().remove("context");
    assert!(Baseline::read(serde_json::to_vec(&doc).unwrap().as_slice()).is_err());
}

#[test]
fn every_context_dimension_blocks_comparison_and_replacement() {
    let scan = report(vec![finding("existing", "a")]);
    let baseline = Baseline::from_report(&scan, None).unwrap();
    let original = scan.context.as_ref().unwrap();
    let contexts = [
        ScanContext {
            mode: "staged".into(),
            ..original.clone()
        },
        ScanContext {
            roots: vec!["/synthetic/other".into()],
            ..original.clone()
        },
        ScanContext {
            engine_configuration_id: "changed-rules-or-key".into(),
            ..original.clone()
        },
        ScanContext {
            selection_policy_id: policy_digest(&[b"changed-ignore"]),
            ..original.clone()
        },
    ];
    for context in contexts {
        let mut changed = report(vec![finding("new", "b")]);
        changed.context = Some(context);
        assert!(baseline.diff(&changed).is_err());
        assert!(Baseline::from_report(&changed, Some(&baseline)).is_err());
        changed.complete = false;
        assert!(baseline.diff(&changed).is_err());
    }
}

#[test]
fn incomplete_scoped_scan_can_report_new_findings_but_never_resolved() {
    let baseline = Baseline::from_report(&report(vec![finding("existing", "a")]), None).unwrap();
    let mut after = report(vec![finding("new", "b")]);
    after.complete = false;
    let diff = baseline.diff(&after).unwrap();
    assert!(!diff.complete);
    assert_eq!(diff.new.len(), 1);
    assert_eq!(diff.new[0].fingerprint, "new");
    assert!(diff.resolved.is_empty());
}

#[test]
fn policy_digest_preserves_component_boundaries_and_does_not_embed_contents() {
    const SYNTHETIC: &[u8] = b"synthetic-ignore-policy-content";
    assert_eq!(policy_digest(&[SYNTHETIC]), policy_digest(&[SYNTHETIC]));
    assert_ne!(policy_digest(&[b"ab", b"c"]), policy_digest(&[b"a", b"bc"]));
    assert_ne!(policy_digest(&[]), policy_digest(&[b""]));
    assert!(!policy_digest(&[SYNTHETIC]).contains("synthetic"));
}
