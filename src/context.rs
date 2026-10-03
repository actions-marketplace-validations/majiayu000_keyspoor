//! The selected input scope and detection policy used by a scan.

use serde::{Deserialize, Serialize};

/// Equality means two reports can be compared for newly present or absent secrets.
///
/// Acquisition code canonicalizes and sorts selected roots once at its boundary.
/// Keep changing file contents and current Git object IDs out of this context;
/// they are observations within the scope, not the scope itself. SDK callers
/// constructing reports directly must provide an explicit context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanContext {
    pub mode: String,
    pub roots: Vec<String>,
    pub engine_configuration_id: String,
    /// Digest of selection options and effective ignore policy, never their contents.
    pub selection_policy_id: String,
}

/// Hash ordered policy components without retaining their potentially sensitive data.
/// Callers supply components in a deterministic order. Length prefixes preserve
/// component boundaries, so `["ab", "c"]` differs from `["a", "bc"]`.
pub fn policy_digest(parts: &[&[u8]]) -> String {
    let mut hash = blake3::Hasher::new_derive_key("secret-scan selection policy v1");
    for part in parts {
        hash.update(&(part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    hash.finalize().to_hex().to_string()
}
