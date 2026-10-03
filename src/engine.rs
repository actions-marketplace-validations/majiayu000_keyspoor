//! Independent compile-once keyword and regex secret detection.
use std::{collections::BTreeMap, path::PathBuf};

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

pub use crate::rules::Confidence;

const REDACTED: &str = "[REDACTED]";
use crate::rules::{self, CompiledRule, RuleInfo};

/// No network validation or process-global configuration is used.
///
/// A fingerprint key enables keyed BLAKE3 fingerprints. Without a key, fingerprints
/// are ordinary digests and do not protect low-entropy secrets from guessing.
#[derive(Clone)]
pub struct EngineConfig {
    pub builtin_rules: bool,
    pub custom_rule_paths: Vec<PathBuf>,
    pub min_confidence: Confidence,
    pub enable_base64: bool,
    pub min_entropy: Option<f32>,
    pub fingerprint_key: Option<[u8; 32]>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            builtin_rules: true,
            custom_rule_paths: Vec::new(),
            min_confidence: Confidence::Medium,
            enable_base64: true,
            min_entropy: None,
            fingerprint_key: None,
        }
    }
}

/// A finding with no raw secret, capture values, source snippets, or rule patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub path: String,
    /// Zero-based start byte offset in `coordinate_space`.
    pub start: usize,
    /// Exclusive end byte offset. Base64 findings cover the encoded container.
    pub end: usize,
    /// One-based line number.
    pub line: usize,
    /// Zero-based byte column, not a Unicode scalar or UTF-16 column.
    pub column: usize,
    pub redacted: String,
    /// Domain-separated digest of rule, path and secret; stable across line moves.
    pub fingerprint: String,
    pub explanation: String,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub is_base64_encoded: bool,
    /// Always `source_bytes`; Base64 findings reference their encoded container.
    #[serde(default = "source_coordinates")]
    pub coordinate_space: String,
}

fn source_coordinates() -> String {
    "source_bytes".into()
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            rule_id: String::new(),
            path: String::new(),
            start: 0,
            end: 0,
            line: 0,
            column: 0,
            redacted: REDACTED.into(),
            fingerprint: String::new(),
            explanation: String::new(),
            confidence: String::new(),
            is_base64_encoded: false,
            coordinate_space: source_coordinates(),
        }
    }
}

/// Thread-safe scanner sharing immutable compiled regexes and keyword automaton.
/// Repeated calls are independent and deterministic; no global state or network.
pub struct Engine {
    rules: Vec<CompiledRule>,
    keywords: Option<AhoCorasick>,
    keyword_rules: Vec<Vec<usize>>,
    unconditional: Vec<usize>,
    base64_candidates: Regex,
    enable_base64: bool,
    min_entropy: Option<f32>,
    fingerprint_key: Option<[u8; 32]>,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Result<Self> {
        if let Some(entropy) = config.min_entropy {
            ensure!(
                entropy.is_finite() && (0.0..=8.0).contains(&entropy),
                "minimum byte entropy must be finite and between 0 and 8"
            );
        }
        let rules = rules::compile(
            config.builtin_rules,
            &config.custom_rule_paths,
            config.min_confidence,
        )?;
        let mut keyword_map: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut unconditional = Vec::new();
        for (id, rule) in rules.iter().enumerate() {
            if rule.spec.keywords.is_empty() {
                unconditional.push(id);
            }
            for keyword in &rule.spec.keywords {
                keyword_map
                    .entry(keyword.to_ascii_lowercase())
                    .or_default()
                    .push(id);
            }
        }
        let keywords = if keyword_map.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(keyword_map.keys())
                    .context("compiling keyword prefilter")?,
            )
        };
        Ok(Self {
            rules,
            keywords,
            keyword_rules: keyword_map.into_values().collect(),
            unconditional,
            base64_candidates: Regex::new(r"[A-Za-z0-9+/_-]{24,}={0,2}")?,
            enable_base64: config.enable_base64,
            min_entropy: config.min_entropy,
            fingerprint_key: config.fingerprint_key,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn rules(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|rule| RuleInfo {
                id: rule.spec.id.clone(),
                name: rule.spec.name.clone(),
                confidence: rule.spec.confidence.to_string(),
            })
            .collect()
    }

    /// Scan raw bytes, BOM-marked UTF-16 and optionally one layer of Base64. Positions refer to source
    /// bytes; decoded findings cover their original encoded container.
    pub fn scan_bytes(&self, path: &str, bytes: &[u8]) -> Result<Vec<Finding>> {
        let decoded_utf16 = decode_utf16_bom(bytes)?;
        let content = decoded_utf16
            .as_ref()
            .map_or(bytes, |decoded| decoded.bytes.as_slice());
        let mut findings = Vec::new();
        self.scan_content(path, content, None, &mut findings);
        if self.enable_base64 {
            for candidate in self.base64_candidates.find_iter(content) {
                let encoded = candidate.as_bytes();
                let decoded = [
                    general_purpose::STANDARD,
                    general_purpose::STANDARD_NO_PAD,
                    general_purpose::URL_SAFE,
                    general_purpose::URL_SAFE_NO_PAD,
                ]
                .iter()
                .find_map(|codec| codec.decode(encoded).ok());
                if let Some(decoded) = decoded {
                    self.scan_content(
                        path,
                        &decoded,
                        Some((candidate.start(), candidate.end())),
                        &mut findings,
                    );
                }
            }
        }
        if !findings.is_empty() {
            if let Some(decoded) = &decoded_utf16 {
                map_utf16_findings(bytes, decoded.little_endian, &mut findings)?;
            } else {
                let line_starts: Vec<_> = std::iter::once(0)
                    .chain(
                        bytes
                            .iter()
                            .enumerate()
                            .filter_map(|(at, &byte)| (byte == b'\n').then_some(at + 1)),
                    )
                    .collect();
                for finding in &mut findings {
                    let line_index = line_starts.partition_point(|&at| at <= finding.start) - 1;
                    finding.line = line_index + 1;
                    finding.column = finding.start - line_starts[line_index];
                }
            }
        }
        findings.sort_by(|a, b| {
            (&a.path, a.start, a.end, &a.rule_id, &a.fingerprint).cmp(&(
                &b.path,
                b.start,
                b.end,
                &b.rule_id,
                &b.fingerprint,
            ))
        });
        findings.dedup_by(|a, b| {
            a.rule_id == b.rule_id
                && a.start == b.start
                && a.end == b.end
                && a.fingerprint == b.fingerprint
        });
        Ok(findings)
    }

    fn scan_content(
        &self,
        path: &str,
        bytes: &[u8],
        container: Option<(usize, usize)>,
        out: &mut Vec<Finding>,
    ) {
        let mut candidates = vec![false; self.rules.len()];
        for &id in &self.unconditional {
            candidates[id] = true;
        }
        if let Some(keywords) = &self.keywords {
            for found in keywords.find_overlapping_iter(bytes) {
                for &id in &self.keyword_rules[found.pattern().as_usize()] {
                    candidates[id] = true;
                }
            }
        }
        for (id, rule) in self.rules.iter().enumerate() {
            if !candidates[id]
                || rule
                    .path
                    .as_ref()
                    .is_some_and(|filter| !filter.is_match(path))
                || rule
                    .exclude_paths
                    .iter()
                    .any(|filter| filter.is_match(path))
            {
                continue;
            }
            for captures in rule.pattern.captures_iter(bytes) {
                let Some(secret) = captures.get(rule.spec.secret_group) else {
                    continue;
                };
                let value = secret.as_bytes();
                if value.is_empty()
                    || is_placeholder(value)
                    || (self.min_entropy.unwrap_or(rule.spec.min_entropy) > 0.0
                        && entropy(value) <= self.min_entropy.unwrap_or(rule.spec.min_entropy))
                    || rule.allowlist.iter().any(|filter| filter.is_match(value))
                {
                    continue;
                }
                let (start, end) = container.unwrap_or((secret.start(), secret.end()));
                let encoding = if container.is_some() {
                    "; detected inside Base64 content"
                } else {
                    ""
                };
                out.push(Finding {
                    rule_id: rule.spec.id.clone(),
                    path: path.to_owned(),
                    start,
                    end,
                    line: 0,
                    column: 0,
                    redacted: REDACTED.into(),
                    fingerprint: self.fingerprint(&rule.spec.id, path, value),
                    explanation: format!(
                        "Matched {} ({} confidence){}; not live-validated",
                        rule.spec.name, rule.spec.confidence, encoding
                    ),
                    confidence: rule.spec.confidence.to_string(),
                    is_base64_encoded: container.is_some(),
                    coordinate_space: source_coordinates(),
                });
            }
        }
    }

    fn fingerprint(&self, rule: &str, path: &str, secret: &[u8]) -> String {
        let mut hash = match &self.fingerprint_key {
            Some(key) => blake3::Hasher::new_keyed(key),
            None => blake3::Hasher::new(),
        };
        hash.update(b"secret-scan/finding/v1\0");
        for part in [rule.as_bytes(), path.as_bytes(), secret] {
            hash.update(&(part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        hash.finalize().to_hex().to_string()
    }
}

fn entropy(value: &[u8]) -> f32 {
    let mut counts = [0usize; 256];
    for &byte in value {
        counts[byte as usize] += 1;
    }
    let len = value.len() as f32;
    counts
        .into_iter()
        .filter(|&count| count > 0)
        .map(|count| {
            let p = count as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn is_placeholder(value: &[u8]) -> bool {
    if value.eq_ignore_ascii_case(REDACTED.as_bytes()) {
        return true;
    }
    if value.len() >= 8 && value.iter().all(|&byte| byte == value[0]) {
        return true;
    }
    [
        b"changeme".as_slice(),
        b"your_secret_here",
        b"your_api_key_here",
        b"replace_me",
        b"example",
        b"xxxxxxxx",
    ]
    .iter()
    .any(|placeholder| value.eq_ignore_ascii_case(placeholder))
}

struct DecodedUtf16 {
    bytes: Vec<u8>,
    little_endian: bool,
}

/// Preserve exact byte spans, including surrogate pairs. Malformed marked text
/// is a scan error rather than a silently truncated or falsely clean result.
fn decode_utf16_bom(source: &[u8]) -> Result<Option<DecodedUtf16>> {
    if source.starts_with(&[0xff, 0xfe, 0, 0]) {
        return Ok(None); // UTF-32 is not supported by this decoder.
    }
    let little = if source.starts_with(&[0xff, 0xfe]) {
        true
    } else if source.starts_with(&[0xfe, 0xff]) {
        false
    } else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    visit_utf16_scalars(source, little, |character, _, _| {
        bytes.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
    })?;
    Ok(Some(DecodedUtf16 {
        bytes,
        little_endian: little,
    }))
}

/// Iterate without allocating source maps. Used again only when findings need
/// locations; mapping memory is proportional to findings, not decoded bytes.
fn visit_utf16_scalars(
    source: &[u8],
    little: bool,
    mut visit: impl FnMut(char, usize, usize),
) -> Result<()> {
    ensure!(
        source.len().is_multiple_of(2),
        "malformed UTF-16: incomplete code unit"
    );
    let unit = |offset| {
        let bytes = [source[offset], source[offset + 1]];
        if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    let mut at = 2;
    while at < source.len() {
        let start = at;
        let first = unit(at);
        at += 2;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            ensure!(
                at < source.len(),
                "malformed UTF-16: unpaired high surrogate"
            );
            let second = unit(at);
            ensure!(
                (0xdc00..=0xdfff).contains(&second),
                "malformed UTF-16: unpaired high surrogate"
            );
            at += 2;
            0x10000 + (((first as u32 - 0xd800) << 10) | (second as u32 - 0xdc00))
        } else {
            ensure!(
                !(0xdc00..=0xdfff).contains(&first),
                "malformed UTF-16: unpaired low surrogate"
            );
            first as u32
        };
        // The branches above construct only valid Unicode scalar values.
        let character = char::from_u32(scalar).context("invalid UTF-16 scalar")?;
        visit(character, start, at);
    }
    Ok(())
}

fn map_utf16_findings(source: &[u8], little: bool, findings: &mut [Finding]) -> Result<()> {
    // End boundaries sort before starts at the same offset: an end belongs to
    // the previous scalar and a start belongs to the following scalar.
    let mut boundaries: Vec<_> = findings
        .iter()
        .enumerate()
        .flat_map(|(index, finding)| [(finding.start, true, index), (finding.end, false, index)])
        .collect();
    boundaries.sort_unstable();
    let mut next = 0;
    let mut utf8_offset = 0;
    let mut line = 1;
    let mut line_start = 0;
    visit_utf16_scalars(source, little, |character, source_start, source_end| {
        let utf8_end = utf8_offset + character.len_utf8();
        while let Some(&(offset, is_start, index)) = boundaries.get(next) {
            if offset > utf8_end || (offset == utf8_end && is_start) {
                break;
            }
            if is_start {
                findings[index].start = source_start;
                findings[index].line = line;
                findings[index].column = source_start - line_start;
            } else {
                findings[index].end = source_end;
            }
            next += 1;
        }
        if character == '\n' {
            line += 1;
            line_start = source_end;
        }
        utf8_offset = utf8_end;
    })?;
    for finding in findings {
        finding.explanation.push_str("; decoded UTF-16 BOM text");
    }
    Ok(())
}
