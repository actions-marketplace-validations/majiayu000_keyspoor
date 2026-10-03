//! Machine-readable output. Findings contain redacted values only.
use std::{collections::BTreeMap, io::Write};

use anyhow::Result;
use serde::Serialize;
use serde_json::json;

use crate::context::ScanContext;
use crate::scan::{ScanEvent, ScanSummary};
use crate::{Finding, ScanError, ScanReport, ScanStats};

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Sarif,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum JsonlRecord<'a> {
    Finding {
        finding: &'a Finding,
    },
    Error {
        error: &'a ScanError,
    },
    Progress {
        stats: &'a ScanStats,
    },
    Summary {
        schema_version: u8,
        complete: bool,
        finding_count: u64,
        error_count: u64,
        stats: &'a ScanStats,
        context: &'a Option<ScanContext>,
    },
}

impl JsonlRecord<'_> {
    fn write(&self, mut writer: impl Write) -> Result<()> {
        serde_json::to_writer(&mut writer, self)?;
        writer.write_all(b"\n")?;
        if !matches!(self, Self::Finding { .. }) {
            writer.flush()?;
        }
        Ok(())
    }
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
                JsonlRecord::Finding { finding }.write(&mut writer)?;
            }
            for error in &report.errors {
                JsonlRecord::Error { error }.write(&mut writer)?;
            }
            JsonlRecord::Summary {
                schema_version: 1,
                complete: report.complete,
                finding_count: report.findings.len() as u64,
                error_count: report.errors.len() as u64,
                stats: &report.stats,
                context: &report.context,
            }
            .write(&mut writer)?;
        }
        OutputFormat::Sarif => write_sarif(report, &mut writer)?,
    }
    writer.flush()?;
    Ok(())
}

/// Write a redacted event; progress and errors flush buffered output.
pub fn write_scan_event(event: &ScanEvent, writer: impl Write) -> Result<()> {
    match event {
        ScanEvent::Finding(finding) => JsonlRecord::Finding { finding },
        ScanEvent::Error(error) => JsonlRecord::Error { error },
        ScanEvent::Progress(stats) => JsonlRecord::Progress { stats },
    }
    .write(writer)
}

/// Finish a JSONL stream without retaining findings or errors in memory.
pub fn write_scan_summary(summary: &ScanSummary, writer: impl Write) -> Result<()> {
    JsonlRecord::Summary {
        schema_version: 1,
        complete: summary.complete,
        finding_count: summary.finding_count,
        error_count: summary.error_count,
        stats: &summary.stats,
        context: &summary.context,
    }
    .write(writer)
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
                    "matched_rule_ids": finding.matched_rule_ids,
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
                "tool": {"driver": {"name": "keyspoor", "version": env!("CARGO_PKG_VERSION"),
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
