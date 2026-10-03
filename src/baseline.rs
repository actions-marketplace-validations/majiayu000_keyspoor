//! Stable secret identities with optional human review dispositions.
use std::{
    collections::{BTreeMap, HashSet},
    io::{Read, Write},
};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::{Finding, ScanReport};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub finding: Finding,
    /// An open text label, e.g. "false positive" or "accepted fixture".
    pub disposition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: u32,
    /// One representative location per secret identity; reports retain all locations.
    pub entries: BTreeMap<String, BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiff {
    pub complete: bool,
    pub new: Vec<Finding>,
    /// Empty for incomplete scans, which cannot establish absence.
    pub resolved: Vec<BaselineEntry>,
}

impl Baseline {
    /// Build a replacement baseline, carrying forward dispositions by fingerprint.
    pub fn from_report(report: &ScanReport, previous: Option<&Self>) -> Result<Self> {
        ensure!(
            report.complete && report.errors.is_empty(),
            "cannot create a baseline from an incomplete scan"
        );
        let mut entries = BTreeMap::new();
        for finding in &report.findings {
            entries
                .entry(finding.fingerprint.clone())
                .or_insert_with(|| BaselineEntry {
                    finding: finding.clone(),
                    disposition: previous
                        .and_then(|baseline| baseline.entries.get(&finding.fingerprint))
                        .and_then(|entry| entry.disposition.clone()),
                });
        }
        Ok(Self {
            schema_version: 1,
            entries,
        })
    }

    /// Read and validate persisted data; corrupt data is never treated as empty.
    pub fn read(reader: impl Read) -> Result<Self> {
        // Deserializer error messages can quote an invalid input value. Keep
        // only static classification and position, without retaining the cause.
        let baseline: Self = serde_json::from_reader(reader).map_err(|error| {
            anyhow!(
                "invalid baseline JSON ({:?}) at line {} column {}",
                error.classify(),
                error.line(),
                error.column()
            )
        })?;
        ensure!(
            baseline.schema_version == 1,
            "unsupported baseline schema version {}",
            baseline.schema_version
        );
        for (fingerprint, entry) in &baseline.entries {
            ensure!(
                !fingerprint.is_empty() && fingerprint == &entry.finding.fingerprint,
                "baseline entry has an inconsistent fingerprint"
            );
        }
        Ok(baseline)
    }

    pub fn write(&self, mut writer: impl Write) -> Result<()> {
        serde_json::to_writer_pretty(&mut writer, self).context("could not serialize baseline")?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }

    /// Compare identities, retaining every new occurrence in the scan.
    pub fn diff(&self, report: &ScanReport) -> BaselineDiff {
        let complete = report.complete && report.errors.is_empty();
        let present: HashSet<&str> = report
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect();
        BaselineDiff {
            complete,
            new: report
                .findings
                .iter()
                .filter(|finding| !self.entries.contains_key(&finding.fingerprint))
                .cloned()
                .collect(),
            resolved: if complete {
                self.entries
                    .iter()
                    .filter(|(fingerprint, _)| !present.contains(fingerprint.as_str()))
                    .map(|(_, entry)| entry.clone())
                    .collect()
            } else {
                vec![]
            },
        }
    }
}
