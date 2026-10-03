//! Local secret detection with an independent Rust engine and redacted output.
//!
//! Scanning never validates credentials against a provider. A successful call
//! can contain findings; scan errors are separate from findings. Inspect
//! `ScanReport::complete` before treating an empty result as a clean scan.
pub mod archive;
pub mod baseline;
pub mod engine;
pub mod mcp;
pub mod report;
pub mod rules;
pub mod scan;

pub use engine::{Engine, EngineConfig, Finding};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    #[serde(default)]
    pub detection_passes: u64,
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub complete: bool,
    pub findings: Vec<Finding>,
    pub errors: Vec<ScanError>,
    pub stats: ScanStats,
}

impl Default for ScanReport {
    fn default() -> Self {
        Self {
            schema_version: 1,
            complete: true,
            findings: Vec::new(),
            errors: Vec::new(),
            stats: ScanStats::default(),
        }
    }
}

impl ScanReport {
    /// 0: complete and clean; 1: complete with findings; 2: incomplete/error.
    pub fn exit_code(&self) -> u8 {
        if !self.complete || !self.errors.is_empty() {
            2
        } else if !self.findings.is_empty() {
            1
        } else {
            0
        }
    }

    pub fn fail(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.complete = false;
        self.errors.push(ScanError {
            path: path.into(),
            message: message.into(),
        });
    }
}
