//! Machine-readable output. Findings contain redacted values only.
use std::{collections::BTreeMap, io::Write};

use anyhow::Result;
use serde_json::json;

use crate::ScanReport;
use crate::scan::{ScanEvent, ScanSummary};

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Sarif,
}

/// Write a report, preserving incomplete status and propagating output failures.
pub fn write_report(
    report: &ScanReport,
    format: OutputFormat,
    mut writer: impl Write,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut writer, report)?;
            writer.write_all(b"\n")?;
        }
        OutputFormat::Jsonl => {
            for finding in &report.findings {
                write_scan_event(&ScanEvent::Finding(finding.clone()), &mut writer)?;
            }
            for error in &report.errors {
                write_scan_event(&ScanEvent::Error(error.clone()), &mut writer)?;
            }
            write_scan_summary(
                &ScanSummary {
                    complete: report.complete,
                    finding_count: report.findings.len() as u64,
                    error_count: report.errors.len() as u64,
                    stats: report.stats.clone(),
                    context: report.context.clone(),
                },
                &mut writer,
            )?;
        }
        OutputFormat::Sarif => write_sarif(report, &mut writer)?,
    }
    writer.flush()?;
    Ok(())
}

/// Write a redacted event; progress flushes completed file results to the caller.
pub fn write_scan_event(event: &ScanEvent, mut writer: impl Write) -> Result<()> {
    let value = match event {
        ScanEvent::Finding(finding) => json!({"type":"finding", "finding":finding}),
        ScanEvent::Error(error) => json!({"type":"error", "error":error}),
        ScanEvent::Progress(stats) => json!({"type":"progress", "stats":stats}),
    };
    serde_json::to_writer(&mut writer, &value)?;
    writer.write_all(b"\n")?;
    if matches!(event, ScanEvent::Progress(_)) {
        writer.flush()?;
    }
    Ok(())
}

/// Finish a JSONL stream without retaining findings or errors in memory.
pub fn write_scan_summary(summary: &ScanSummary, mut writer: impl Write) -> Result<()> {
    serde_json::to_writer(
        &mut writer,
        &json!({
            "type":"summary", "schema_version":1, "complete":summary.complete,
            "finding_count":summary.finding_count, "error_count":summary.error_count,
            "stats":summary.stats, "context":summary.context,
        }),
    )?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn write_sarif(report: &ScanReport, mut writer: impl Write) -> Result<()> {
    let mut rules = BTreeMap::new();
    for finding in &report.findings {
        rules.entry(&finding.rule_id).or_insert_with(|| {
            json!({
                "id": finding.rule_id,
                "shortDescription": {"text": finding.explanation},
            })
        });
    }
    let results: Vec<_> = report
        .findings
        .iter()
        .map(|finding| {
            // A line is valid across UTF-8/16/32; byte offsets are not. Preserve the
            // scanner's precise coordinates as properties without mislabelling them.
            json!({
                "ruleId": finding.rule_id,
                "level": "warning",
                "message": {"text": format!("{} ({})", finding.explanation, finding.redacted)},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": path_uri(&finding.path)},
                    "region": {"startLine": finding.line.max(1)}
                }}],
                "partialFingerprints": {"secretFingerprint/v1": finding.fingerprint},
                "properties": {
                    "start": finding.start, "end": finding.end, "column": finding.column,
                    "coordinate_space": finding.coordinate_space,
                    "confidence": finding.confidence,
                    "is_base64_encoded": finding.is_base64_encoded,
                }
            })
        })
        .collect();
    let notifications: Vec<_> = report
        .errors
        .iter()
        .map(|error| {
            json!({
                "level": "error", "message": {"text": error.message},
                "properties": {"path": error.path}
            })
        })
        .collect();
    serde_json::to_writer(
        &mut writer,
        &json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "secret-scan", "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules.into_values().collect::<Vec<_>>() }},
                "results": results,
                "invocations": [{"executionSuccessful": report.complete,
                    "toolExecutionNotifications": notifications}],
                "properties": {"complete": report.complete, "stats": report.stats}
            }]
        }),
    )?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn path_uri(path: &str) -> String {
    use std::fmt::Write as _;
    let mut uri = String::with_capacity(path.len());
    if path.starts_with('/') {
        uri.push_str("file://");
    }
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                uri.push(char::from(byte))
            }
            _ => {
                let _ = write!(uri, "%{byte:02X}");
            }
        }
    }
    uri
}
