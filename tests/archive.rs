use std::io::{Cursor, Write};
use std::sync::LazyLock;

use flate2::{Compression, write::GzEncoder};
use secret_scan::{Engine, EngineConfig, archive::scan_archive};

static ENGINE: LazyLock<Engine> = LazyLock::new(|| Engine::new(EngineConfig::default()).unwrap());

// Generated, synthetic pattern fixture, never a credential issued by a provider.
fn fixture() -> Vec<u8> {
    format!("line one\nghp_{}\n", "aZ7kP2mQ9xT4vR6n".repeat(3)).into_bytes()
}

fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in members {
        writer
            .start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut writer = GzEncoder::new(Vec::new(), Compression::default());
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap()
}

fn tar(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder.append_data(&mut header, name, bytes).unwrap();
    builder.into_inner().unwrap()
}

#[test]
fn member_offsets_and_redaction_refer_to_unpacked_bytes() {
    let input = fixture();
    let bytes = zip(&[("dir/config.txt", &input)]);
    let report = scan_archive(&ENGINE, "bundle.zip", &bytes, 100_000)
        .unwrap()
        .unwrap();
    assert!(report.complete);
    let finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == "github-pat")
        .unwrap();
    assert_eq!(finding.path, "bundle.zip!dir/config.txt");
    assert_eq!(finding.coordinate_space, "archive_member_bytes");
    assert_eq!(finding.line, 2);
    assert!(input[finding.start..finding.end].starts_with(b"ghp_"));
    assert!(!serde_json::to_string(&report).unwrap().contains("aZ7kP2mQ"));
    assert_eq!(report.stats.files, 1);
}

#[test]
fn nested_zip_gzip_tar_retains_every_member_origin() {
    let input = fixture();
    let tar = tar("config.txt", &input);
    let gz = gzip(&tar);
    let outer = zip(&[("inner.tar.gz", &gz)]);
    let report = scan_archive(&ENGINE, "outer.zip", &outer, 100_000)
        .unwrap()
        .unwrap();
    assert!(report.complete, "{:?}", report.errors);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.path == "outer.zip!inner.tar.gz!inner.tar!config.txt")
    );
}

#[test]
fn cumulative_expansion_limit_never_reports_clean() {
    let first = fixture();
    let second = vec![b'x'; 128];
    let bytes = zip(&[("first.txt", &first), ("second.txt", &second)]);
    let report = scan_archive(&ENGINE, "bundle.zip", &bytes, first.len() as u64 + 10)
        .unwrap()
        .unwrap();
    assert!(!report.complete);
    assert_eq!(report.exit_code(), 2);
    assert!(!report.findings.is_empty());
    assert_eq!(report.stats.skipped, 1);
}

#[test]
fn gzip_expansion_and_nested_depth_are_bounded() {
    let compressed = gzip(&vec![b'x'; 4096]);
    let report = scan_archive(&ENGINE, "large.gz", &compressed, 100)
        .unwrap()
        .unwrap();
    assert!(!report.complete);
    let mut bytes = fixture();
    for _ in 0..6 {
        bytes = zip(&[("nested.zip", &bytes)]);
    }
    let report = scan_archive(&ENGINE, "outer.zip", &bytes, 100_000)
        .unwrap()
        .unwrap();
    assert!(!report.complete);
    assert!(report.errors.iter().any(|e| e.message.contains("depth")));
}

#[test]
fn malformed_archive_is_an_error_not_a_clean_scan() {
    for (name, bytes) in [
        ("bad.zip", b"PK\x03\x04junk".as_slice()),
        ("bad.gz", b"\x1f\x8bjunk"),
        ("bad.tar", b"broken"),
    ] {
        assert!(scan_archive(&ENGINE, name, bytes, 1000).is_err(), "{name}");
    }
    assert!(
        scan_archive(&ENGINE, "plain.txt", b"ordinary text", 1000)
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_nested_member_preserves_sibling_findings() {
    let input = fixture();
    let bytes = zip(&[("config.txt", &input), ("broken.gz", b"\x1f\x8bbad")]);
    let report = scan_archive(&ENGINE, "outer.zip", &bytes, 100_000)
        .unwrap()
        .unwrap();
    assert!(!report.complete);
    assert!(!report.findings.is_empty());
    assert_eq!(report.errors[0].path, "outer.zip!broken.gz");
}

#[test]
fn corrupt_stored_zip_member_is_incomplete() {
    let payload = b"unique synthetic contents";
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "broken.txt",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(payload).unwrap();
    let mut bytes = writer.finish().unwrap().into_inner();
    let start = bytes
        .windows(payload.len())
        .position(|w| w == payload)
        .unwrap();
    bytes[start] ^= 1; // Keep central directory valid; fail the member CRC.
    let report = scan_archive(&ENGINE, "broken.zip", &bytes, 1000)
        .unwrap()
        .unwrap();
    assert!(!report.complete);
    assert_eq!(report.exit_code(), 2);
    assert_eq!(report.stats.files, 0);
}

#[test]
fn tar_symlinks_are_not_followed_or_claimed_scanned() {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name("/outside/archive").unwrap();
    header.set_cksum();
    builder.append_data(&mut header, "link", &[][..]).unwrap();
    let bytes = builder.into_inner().unwrap();
    let report = scan_archive(&ENGINE, "links.tar", &bytes, 1000)
        .unwrap()
        .unwrap();
    assert!(!report.complete);
    assert_eq!(report.stats.files, 0);
    assert_eq!(report.stats.skipped, 1);
}

#[test]
fn truncated_tar_member_does_not_become_clean() {
    let mut bytes = tar("truncated.txt", &[b'x'; 1024]);
    bytes.truncate(520);
    let report = scan_archive(&ENGINE, "truncated.tar", &bytes, 10_000)
        .unwrap()
        .unwrap();
    assert!(!report.complete);
    assert_eq!(report.exit_code(), 2);
}
