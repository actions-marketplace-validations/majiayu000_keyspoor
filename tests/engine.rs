use secret_scan::{Engine, EngineConfig, Finding};
use tempfile::TempDir;

const RULE: &str = r#"{"rules":[{"id":"synthetic.fixture","name":"Synthetic fixture token","pattern":"fixture_([A-Za-z0-9]{24})","secret_group":1,"keywords":["fixture_"],"confidence":"high"}]}"#;
const TOKEN: &str = "Ab3dEf7hIj9kLm2nOp4qRs6t";

fn custom_engine(rule: &str, key: Option<[u8; 32]>) -> (TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.json");
    std::fs::write(&path, rule).unwrap();
    let engine = Engine::new(EngineConfig {
        builtin_rules: false,
        custom_rule_paths: vec![path],
        fingerprint_key: key,
        ..Default::default()
    })
    .unwrap();
    (dir, engine)
}

#[test]
fn findings_are_redacted_precise_and_repeatable() {
    let (_dir, engine) = custom_engine(RULE, None);
    let input = format!("first line\n  fixture_{TOKEN}\n");
    let findings = engine.scan_bytes("config.txt", input.as_bytes()).unwrap();
    assert_eq!(findings.len(), 1);
    let found = &findings[0];
    assert_eq!(&input[found.start..found.end], TOKEN);
    assert_eq!((found.line, found.column), (2, 10));
    assert_eq!(found.coordinate_space, "source_bytes");
    assert_eq!(found.redacted, "[REDACTED]");
    assert!(found.explanation.contains("not live-validated"));
    assert!(!serde_json::to_string(&findings).unwrap().contains(TOKEN));
    assert!(!format!("{findings:?}").contains(TOKEN));
    assert_eq!(
        findings,
        engine.scan_bytes("config.txt", input.as_bytes()).unwrap()
    );
    let moved = engine
        .scan_bytes("config.txt", format!("\n{input}").as_bytes())
        .unwrap();
    assert_eq!(found.fingerprint, moved[0].fingerprint);
    assert_eq!(engine.rule_count(), 1);
    assert_eq!(engine.rules()[0].id, "synthetic.fixture");
}

#[test]
fn fingerprints_are_keyed_and_bound_to_path_and_secret() {
    let (_d1, a) = custom_engine(RULE, Some([1; 32]));
    let (_d2, b) = custom_engine(RULE, Some([2; 32]));
    let input = format!("fixture_{TOKEN}");
    let scan = |engine: &Engine, path| {
        engine.scan_bytes(path, input.as_bytes()).unwrap()[0]
            .fingerprint
            .clone()
    };
    assert_ne!(scan(&a, "a"), scan(&b, "a"));
    assert_ne!(scan(&a, "a"), scan(&a, "b"));
    let changed = a
        .scan_bytes("a", b"fixture_Zb3dEf7hIj9kLm2nOp4qRs6t")
        .unwrap();
    assert_ne!(scan(&a, "a"), changed[0].fingerprint);
}

#[test]
fn base64_detection_is_explicit_and_configurable() {
    let (_dir, engine) = custom_engine(RULE, None);
    // Synthetic ASCII fixture encoded once; never a real credential.
    let encoded = b"Zml4dHVyZV9BYjNkRWY3aElqOWtMbTJuT3A0cVJzNnQ=";
    let findings = engine.scan_bytes("encoded.txt", encoded).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].is_base64_encoded);
    assert_eq!((findings[0].start, findings[0].end), (0, encoded.len()));
    assert!(!serde_json::to_string(&findings).unwrap().contains(TOKEN));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.json");
    std::fs::write(&path, RULE).unwrap();
    let no_decode = Engine::new(EngineConfig {
        builtin_rules: false,
        custom_rule_paths: vec![path],
        enable_base64: false,
        ..Default::default()
    })
    .unwrap();
    assert!(
        no_decode
            .scan_bytes("encoded.txt", encoded)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn custom_json_rules_obey_path_predicates() {
    let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
    json["rules"][0]["path"] = serde_json::json!(r"\.env$");
    let (_dir, engine) = custom_engine(&json.to_string(), None);
    let input = format!("fixture_{TOKEN}");
    assert_eq!(
        engine
            .scan_bytes("settings.env", input.as_bytes())
            .unwrap()
            .len(),
        1
    );
    assert!(
        engine
            .scan_bytes("settings.txt", input.as_bytes())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn invalid_configuration_propagates_errors() {
    assert!(
        Engine::new(EngineConfig {
            builtin_rules: false,
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        Engine::new(EngineConfig {
            custom_rule_paths: vec!["/missing/secret-scan-rules.json".into()],
            ..Default::default()
        })
        .is_err()
    );
    for entropy in [f32::NAN, f32::INFINITY, -1.0, 8.1] {
        assert!(
            Engine::new(EngineConfig {
                min_entropy: Some(entropy),
                ..Default::default()
            })
            .is_err()
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.json");
    std::fs::write(&path, "{invalid").unwrap();
    assert!(
        Engine::new(EngineConfig {
            builtin_rules: false,
            custom_rule_paths: vec![path.clone()],
            ..Default::default()
        })
        .is_err()
    );
    std::fs::write(&path, RULE.replace("fixture_([A-Za-z0-9]{24})", "(")).unwrap();
    assert!(
        Engine::new(EngineConfig {
            builtin_rules: false,
            custom_rule_paths: vec![path],
            ..Default::default()
        })
        .is_err()
    );
}

#[test]
fn one_compiled_engine_is_safe_for_parallel_calls() {
    let (_dir, engine) = custom_engine(RULE, None);
    let input = format!("fixture_{TOKEN}");
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| engine.scan_bytes("same.txt", input.as_bytes()).unwrap()))
            .collect();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(
            results
                .iter()
                .all(|result| result == &results[0] && result.len() == 1)
        );
    });
}

#[test]
fn finding_defaults_never_contain_unredacted_material() {
    let finding = Finding::default();
    assert_eq!(finding.redacted, "[REDACTED]");
    let roundtrip: Finding =
        serde_json::from_str(&serde_json::to_string(&finding).unwrap()).unwrap();
    assert_eq!(finding, roundtrip);
}

#[test]
fn entropy_allowlist_and_excluded_paths_filter_without_leaking() {
    let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
    json["rules"][0]["exclude_paths"] = serde_json::json!(["(^|/)vendor/"]);
    json["rules"][0]["allowlist"] = serde_json::json!(["^Ab3d"]);
    let (_dir, engine) = custom_engine(&json.to_string(), None);
    assert!(
        engine
            .scan_bytes("app.txt", format!("fixture_{TOKEN}").as_bytes())
            .unwrap()
            .is_empty()
    );
    assert!(
        engine
            .scan_bytes("vendor/app.txt", b"fixture_Zb3dEf7hIj9kLm2nOp4qRs6t")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        engine
            .scan_bytes("app.txt", b"fixture_Zb3dEf7hIj9kLm2nOp4qRs6t")
            .unwrap()
            .len(),
        1
    );
    json["rules"][0]["min_entropy"] = serde_json::json!(4.0);
    let (_dir, threshold) = custom_engine(&json.to_string(), None);
    assert!(
        threshold
            .scan_bytes("a", b"fixture_aaaaaaaabbbbbbbbcccccccc")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn overlapping_and_case_insensitive_keywords_do_not_drop_rules() {
    let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
    json["rules"][0]["keywords"] = serde_json::json!(["TURE", "FIXTURE_"]);
    let (_dir, engine) = custom_engine(&json.to_string(), None);
    assert_eq!(
        engine
            .scan_bytes("a", format!("fixture_{TOKEN}").as_bytes())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn byte_offsets_and_columns_remain_correct_after_unicode_and_invalid_utf8() {
    let (_dir, engine) = custom_engine(RULE, None);
    let mut input = "你好\nλ ".as_bytes().to_vec();
    input.push(0xff);
    input.extend_from_slice(format!("fixture_{TOKEN}").as_bytes());
    let findings = engine.scan_bytes("binary.dat", &input).unwrap();
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!((finding.line, finding.column), (2, 12));
    assert_eq!(&input[finding.start..finding.end], TOKEN.as_bytes());
}

#[test]
fn embedded_catalog_compiles_and_detects_synthetic_github_fixture() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    assert!(engine.rule_count() >= 200);
    let fixture = b"token = 'ghp_9Zb2Ef7hIj4kLm6nOp8qRs0tUv3wXy5zAbCd'";
    let findings = engine.scan_bytes("config.txt", fixture).unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "github-pat")
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.redacted == "[REDACTED]")
    );
}

#[test]
fn generic_assignments_find_weak_literals_without_treating_references_as_secrets() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let text =
        b"db_password = 'password'\n\"client_secret\": \"ordinary literal\"\napi_key=short123\n";
    let findings = engine.scan_bytes("settings.txt", text).unwrap();
    let generic: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id.starts_with("generic-credential-"))
        .collect();
    assert_eq!(generic.len(), 3);
    let expected: [&[u8]; 3] = [b"password", b"ordinary literal", b"short123"];
    for (finding, expected) in generic.iter().zip(expected) {
        assert_eq!(&text[finding.start..finding.end], expected);
        assert_eq!(finding.redacted, "[REDACTED]");
    }
    let references = br#"
password = "${DATABASE_PASSWORD}"
password = "{{ secrets.database_password }}"
password = process.env.DATABASE_PASSWORD
password = "your_password_here"
password = "xxxxxxxxxxxx"
password = "redacted"
password = null
password = "env('PASSWORD')"
"#;
    assert!(
        !engine
            .scan_bytes("settings.txt", references)
            .unwrap()
            .iter()
            .any(|finding| finding.rule_id.starts_with("generic-credential-"))
    );
}

#[test]
fn configuration_errors_do_not_echo_secret_bearing_patterns_or_json_values() {
    for field in ["pattern", "path"] {
        let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
        json["rules"][0][field] = serde_json::json!("SyntheticSensitiveConfigMarker(");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        std::fs::write(&path, json.to_string()).unwrap();
        let error = Engine::new(EngineConfig {
            builtin_rules: false,
            custom_rule_paths: vec![path],
            ..Default::default()
        })
        .err()
        .unwrap();
        assert!(!format!("{error:#}").contains("SyntheticSensitiveConfigMarker"));
        assert!(!format!("{error:?}").contains("SyntheticSensitiveConfigMarker"));
        assert!(format!("{error}").contains("synthetic.fixture"));
    }
    for field in ["allowlist", "exclude_paths"] {
        let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
        json["rules"][0][field] = serde_json::json!(["SyntheticSensitiveConfigMarker("]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        std::fs::write(&path, json.to_string()).unwrap();
        let error = Engine::new(EngineConfig {
            builtin_rules: false,
            custom_rule_paths: vec![path],
            ..Default::default()
        })
        .err()
        .unwrap();
        assert!(!format!("{error:#?}").contains("SyntheticSensitiveConfigMarker"));
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.json");
    std::fs::write(&path, r#"{"rules":[{"SyntheticSensitiveConfigMarker":1}]}"#).unwrap();
    let error = Engine::new(EngineConfig {
        builtin_rules: false,
        custom_rule_paths: vec![path],
        ..Default::default()
    })
    .err()
    .unwrap();
    assert!(!format!("{error:#?}").contains("SyntheticSensitiveConfigMarker"));
}

#[test]
fn utf16_bom_findings_map_back_to_original_source_bytes_and_columns() {
    let (_dir, engine) = custom_engine(RULE, None);
    let text = format!("emoji 😀\n  fixture_{TOKEN}\n");
    for little in [true, false] {
        let mut source = if little {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        source.extend(text.encode_utf16().flat_map(|unit| {
            if little {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            }
        }));
        let findings = engine.scan_bytes("utf16.txt", &source).unwrap();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!((finding.line, finding.column), (2, 20));
        assert_eq!(finding.coordinate_space, "source_bytes");
        let expected: Vec<_> = TOKEN
            .encode_utf16()
            .flat_map(|unit| {
                if little {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                }
            })
            .collect();
        assert_eq!(&source[finding.start..finding.end], expected);
        assert_eq!(finding.end - finding.start, 48);
    }
}

#[test]
fn malformed_utf16_is_an_error_and_base64_inside_utf16_retains_source_spans() {
    let (_dir, engine) = custom_engine(RULE, None);
    for bytes in [
        &[0xff, 0xfe, 1][..],
        &[0xff, 0xfe, 0, 0xd8],
        &[0xfe, 0xff, 0xdc, 0],
    ] {
        assert!(engine.scan_bytes("broken.txt", bytes).is_err());
    }
    let encoded = "Zml4dHVyZV9BYjNkRWY3aElqOWtMbTJuT3A0cVJzNnQ=";
    let source: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(encoded.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let findings = engine.scan_bytes("encoded.txt", &source).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].is_base64_encoded);
    assert_eq!((findings[0].start, findings[0].end), (2, source.len()));
}

#[test]
fn replacing_a_credential_with_our_redaction_marker_is_idempotent() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let original = b"password = 'weak-passphrase'\n";
    let findings = engine.scan_bytes("settings.txt", original).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding.rule_id.starts_with("generic-credential-"))
        .unwrap();
    let mut repaired = original[..finding.start].to_vec();
    repaired.extend_from_slice(finding.redacted.as_bytes());
    repaired.extend_from_slice(&original[finding.end..]);
    assert!(
        engine
            .scan_bytes("settings.txt", &repaired)
            .unwrap()
            .is_empty()
    );
    assert!(
        engine
            .scan_bytes("settings.txt", b"password = '[redacted]'\n")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn utf16_sparse_mapping_preserves_overlapping_and_adjacent_surrogate_boundaries() {
    let rules = serde_json::json!({"rules": [
        {"id":"before","name":"Before","pattern":"(α😀)","secret_group":1},
        {"id":"after","name":"After","pattern":"(β)","secret_group":1},
        {"id":"overlap","name":"Overlap","pattern":"(😀β)","secret_group":1},
        {"id":"byte","name":"Byte within surrogate","pattern":r"(\x9F)","secret_group":1}
    ]});
    let (_dir, engine) = custom_engine(&rules.to_string(), None);
    for little in [true, false] {
        let text = "\nα😀β";
        let mut source = if little {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        source.extend(text.encode_utf16().flat_map(|unit| {
            if little {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            }
        }));
        let findings = engine.scan_bytes("unicode.txt", &source).unwrap();
        assert_eq!(findings.len(), 4);
        for (id, start, end, column) in [
            ("before", 4, 10, 0),
            ("after", 10, 12, 6),
            ("overlap", 6, 12, 2),
            ("byte", 6, 10, 2),
        ] {
            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == id)
                .unwrap();
            assert_eq!(
                (finding.start, finding.end, finding.line, finding.column),
                (start, end, 2, column)
            );
        }
    }
}

#[test]
fn clean_utf16_does_not_require_a_source_map() {
    let (_dir, engine) = custom_engine(RULE, None);
    let source: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(
            "ordinary text 😀\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        )
        .collect();
    assert!(engine.scan_bytes("clean.txt", &source).unwrap().is_empty());
}

#[test]
fn multiline_assignment_only_accepts_an_immediately_following_quoted_literal() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for text in [
        "service_password =\n  'pear-otter-42'\n",
        "\"auth_token\":\r\n\t\"walnut.badger.73\",\r\n",
    ] {
        let findings = engine
            .scan_bytes("continuation.txt", text.as_bytes())
            .unwrap();
        let found: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id.starts_with("generic-credential-"))
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 2);
        assert!(matches!(
            &text[found[0].start..found[0].end],
            "pear-otter-42" | "walnut.badger.73"
        ));
    }
    for text in [
        "password =\n\n 'remote-literal'\n",
        "password =\n process.env.DB_PASSWORD\n",
        "password =\n nextVariable\n",
        "\"password\":\n \"next_property\": \"ordinary text\"\n",
        "password =\n \"${DB_PASSWORD}\"\n",
        "password =\n 'literal' + suffix\n",
    ] {
        assert!(
            !engine
                .scan_bytes("continuation.txt", text.as_bytes())
                .unwrap()
                .iter()
                .any(|finding| finding.rule_id.starts_with("generic-credential-")),
            "unexpected literal match"
        );
    }
}

#[test]
fn uri_passwords_have_exact_spans_across_schemes_and_encoded_characters() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for (uri, password) in [
        (
            "postgresql://reader:walnut-pony-71@db.internal:5432/app",
            "walnut-pony-71",
        ),
        (
            "postgres://writer:cedar_otter_82@[::1]/app",
            "cedar_otter_82",
        ),
        ("mysql://guest:elm.quail.53@localhost/data", "elm.quail.53"),
        (
            "https://viewer:p%40ss%3Aphrase@service.invalid/api",
            "p%40ss%3Aphrase",
        ),
        ("http://viewer:q@service.invalid/", "q"),
        (
            "redis://:maple-heron-64@cache.internal:6379/0",
            "maple-heron-64",
        ),
        (
            "rediss://default:birch.finch.95@cache.internal/1",
            "birch.finch.95",
        ),
    ] {
        let text = format!("connection = \"{uri}\"\n");
        let findings = engine
            .scan_bytes("connections.conf", text.as_bytes())
            .unwrap();
        let found: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == "uri-userinfo-password")
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(&text[found[0].start..found[0].end], password);
        assert_eq!(found[0].redacted, "[REDACTED]");
    }
}

#[test]
fn uri_userinfo_without_literal_password_is_not_a_secret() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for uri in [
        "http://service.invalid/docs",
        "https://viewer@service.invalid/",
        "mysql://guest:@localhost/db",
        "redis://:${REDIS_PASSWORD}@localhost/0",
        "postgres://user:$DB_PASSWORD@localhost/db",
        "http://viewer:process.env.PASSWORD@service.invalid/",
        "redis://:[REDACTED]@localhost/0",
        "http://service.invalid/path:unrelated@next",
        "mysql://user:{{ vault.password }}@localhost/db",
    ] {
        assert!(
            !engine
                .scan_bytes("connections.conf", uri.as_bytes())
                .unwrap()
                .iter()
                .any(|finding| finding.rule_id == "uri-userinfo-password")
        );
    }
}

#[test]
fn quoted_assignments_allow_comments_and_closing_call_parentheses() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for quote in ['\'', '"'] {
        for ending in [
            " # trailing comment",
            " // trailing comment",
            " /* trailing comment */",
            ")",
        ] {
            let text = format!("configure(password={quote}spruce-wren-26{quote}{ending}\n");
            let findings = engine.scan_bytes("source.txt", text.as_bytes()).unwrap();
            let generic: Vec<_> = findings
                .iter()
                .filter(|finding| finding.rule_id.starts_with("generic-credential-"))
                .collect();
            assert_eq!(generic.len(), 1, "quoted assignment ending was omitted");
            assert_eq!(&text[generic[0].start..generic[0].end], "spruce-wren-26");
        }
    }
}
