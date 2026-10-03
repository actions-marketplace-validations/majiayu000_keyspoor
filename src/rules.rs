//! Rule schema and compilation for the independent detection engine.
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, ensure};
use regex::{
    Regex,
    bytes::{Regex as BytesRegex, RegexBuilder},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        })
    }
}

/// Custom JSON rule. Keywords are OR-ed, ASCII-case-insensitive necessary conditions.
/// `secret_group` selects the regex capture whose bytes are redacted/fingerprinted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub secret_group: usize,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub min_entropy: f32,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub path: Option<String>,
    /// Regexes matched against the extracted secret; matches are suppressed.
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleInfo {
    pub id: String,
    pub name: String,
    pub confidence: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    rules: Vec<RuleSpec>,
}

pub(crate) struct CompiledRule {
    pub spec: RuleSpec,
    pub pattern: BytesRegex,
    pub path: Option<Regex>,
    pub allowlist: Vec<Arc<BytesRegex>>,
    pub exclude_paths: Vec<Arc<Regex>>,
}

pub(crate) fn compile(
    builtin: bool,
    paths: &[PathBuf],
    confidence: Confidence,
) -> Result<Vec<CompiledRule>> {
    let mut specs = BTreeMap::new();
    if builtin {
        let defaults: RuleFile = serde_json::from_str(include_str!("builtin_rules.json"))
            .context("parsing embedded rule catalog")?;
        for rule in defaults
            .rules
            .into_iter()
            .chain(generic_assignment_rules())
            .chain([uri_password_rule()])
        {
            specs.insert(rule.id.clone(), rule);
        }
    }
    for path in paths {
        load_path(path, &mut specs)?;
    }
    let mut compiled = Vec::new();
    let mut shared_allowlists: HashMap<String, Arc<BytesRegex>> = HashMap::new();
    let mut shared_exclusions: HashMap<String, Arc<Regex>> = HashMap::new();
    for spec in specs
        .into_values()
        .filter(|rule| rule.confidence >= confidence)
    {
        ensure!(!spec.id.is_empty(), "rule ID must not be empty");
        ensure!(
            spec.min_entropy.is_finite() && (0.0..=8.0).contains(&spec.min_entropy),
            "invalid entropy threshold for rule {}",
            spec.id
        );
        let pattern = RegexBuilder::new(&spec.pattern)
            .unicode(false)
            .build()
            .map_err(|_| {
                anyhow!(
                    "invalid regex syntax or size limit in pattern for rule {}",
                    spec.id
                )
            })?;
        ensure!(
            spec.secret_group < pattern.captures_len(),
            "capture group missing for rule {}",
            spec.id
        );
        ensure!(
            !pattern.is_match(b""),
            "rule {} matches empty input",
            spec.id
        );
        ensure!(
            spec.keywords.iter().all(|keyword| !keyword.is_empty()),
            "empty keyword for rule {}",
            spec.id
        );
        let path = spec
            .path
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|_| {
                anyhow!(
                    "invalid regex syntax or size limit in path predicate for rule {}",
                    spec.id
                )
            })?;
        let mut allowlist = Vec::new();
        for expression in &spec.allowlist {
            let filter = if let Some(filter) = shared_allowlists.get(expression) {
                Arc::clone(filter)
            } else {
                let filter = Arc::new(
                    RegexBuilder::new(expression)
                        .unicode(false)
                        .build()
                        .map_err(|_| {
                            anyhow!(
                                "invalid regex syntax or size limit in allowlist for rule {}",
                                spec.id
                            )
                        })?,
                );
                shared_allowlists.insert(expression.clone(), Arc::clone(&filter));
                filter
            };
            allowlist.push(filter);
        }
        let mut exclude_paths = Vec::new();
        for expression in &spec.exclude_paths {
            let filter = if let Some(filter) = shared_exclusions.get(expression) {
                Arc::clone(filter)
            } else {
                let filter = Arc::new(Regex::new(expression).map_err(|_| {
                    anyhow!(
                        "invalid regex syntax or size limit in excluded path for rule {}",
                        spec.id
                    )
                })?);
                shared_exclusions.insert(expression.clone(), Arc::clone(&filter));
                filter
            };
            exclude_paths.push(filter);
        }
        compiled.push(CompiledRule {
            spec,
            pattern,
            path,
            allowlist,
            exclude_paths,
        });
    }
    ensure!(
        !compiled.is_empty(),
        "no rules selected at the requested confidence"
    );
    Ok(compiled)
}

fn load_path(path: &Path, specs: &mut BTreeMap<String, RuleSpec>) -> Result<()> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("reading rule path {}", path.display()))?;
    if metadata.is_dir() {
        let mut files = std::fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        files.sort();
        for file in files {
            // Avoid directory symlink cycles; explicit file symlinks still work.
            let kind = std::fs::symlink_metadata(&file)?.file_type();
            if kind.is_dir()
                || (kind.is_file() && file.extension().is_some_and(|ext| ext == "json"))
            {
                load_path(&file, specs)?;
            }
        }
    } else {
        let bytes =
            std::fs::read(path).with_context(|| format!("reading rules {}", path.display()))?;
        let file: RuleFile = serde_json::from_slice(&bytes).map_err(|error| {
            anyhow!(
                "invalid JSON rule configuration at {}:{}:{} ({:?})",
                path.display(),
                error.line(),
                error.column(),
                error.classify()
            )
        })?;
        for rule in file.rules {
            specs.insert(rule.id.clone(), rule);
        }
    }
    Ok(())
}

/// Independently authored assignment grammar. No entropy floor: weak literal
/// passwords are still credentials. Quoted literals may continue onto the next
/// physical line; blank lines, references and the following JSON key are not values.
fn generic_assignment_rules() -> Vec<RuleSpec> {
    let key = r#"(?im)\b(?:[a-z][a-z0-9_]{0,48}[_-])?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?[ \t]*[:=]"#;
    [
        ("double", r#"[ \t]*(?:\r?\n[ \t]*)?"([^"\r\n\\]{4,128})"[ \t]*(?:[,;})\]]|#|//|/\*|\r?$)"#),
        ("single", r"[ \t]*(?:\r?\n[ \t]*)?'([^'\r\n\\]{4,128})'[ \t]*(?:[,;})\]]|#|//|/\*|\r?$)"),
        ("unquoted", r#"[ \t]*([A-Za-z0-9][A-Za-z0-9!@#%^&*_.:/+=~-]{3,127})(?:[ \t]*(?:[,;#]|\r?$))"#),
    ].into_iter().map(|(syntax, value)| RuleSpec {
        id: format!("generic-credential-{syntax}"),
        name: "Literal assigned to a credential key".into(),
        pattern: format!("{key}{value}"),
        secret_group: 1,
        keywords: ["password", "passwd", "pwd", "secret", "api", "access", "auth", "client"]
            .into_iter().map(String::from).collect(),
        min_entropy: 0.0,
        confidence: Confidence::Medium,
        path: None,
        allowlist: [
            r"(?i)^(?:true|false|null|none|undefined)$",
            r"^\s*(?:\$|\{\{|<%|<|%[A-Z_]+%)",
            r"(?i)^(?:process\.env\.|(?:os\.)?environ\b|(?:getenv|env)\b|secrets\.|vars\.)",
            r"(?i)^(?:your[_ -].*|replace[_ -].*|insert[_ -].*|example|sample|dummy|placeholder|redacted|<redacted>)$",
        ].into_iter().map(String::from).collect(),
        exclude_paths: Vec::new(),
    }).collect()
}

/// Independently authored URI authority grammar: capture only a nonempty
/// password between userinfo's colon and @, without decoding source spelling.
fn uri_password_rule() -> RuleSpec {
    RuleSpec {
        id: "uri-userinfo-password".into(),
        name: "Password in URI authority userinfo".into(),
        pattern: r#"(?i)\b(?:postgres(?:ql)?|mysql|https?|rediss?)://[^:/@\s"'<>?#]*:([^/@\s"'<>?#]+)@(?:\[[0-9a-f:]+\]|[a-z0-9][a-z0-9.-]*)"#.into(),
        secret_group: 1,
        keywords: ["postgres", "mysql", "http", "redis"].into_iter().map(String::from).collect(),
        min_entropy: 0.0,
        confidence: Confidence::Medium,
        path: None,
        allowlist: [
            r"^(?:\$|\{\{|%[A-Z_]+%)",
            r"(?i)^(?:process\.env\.|(?:os\.)?environ\b|(?:getenv|env)\b|secrets\.|vars\.)",
            r"(?i)^(?:your[_ -].*|replace[_ -].*|insert[_ -].*|example|sample|dummy|placeholder|redacted|<redacted>)$",
        ].into_iter().map(String::from).collect(),
        exclude_paths: Vec::new(),
    }
}
