# secret-scan

An independent Rust secret detection engine, reusable library and offline CLI.
The matching, keyword dispatch, filtering, decoding, location mapping, Git
acquisition and agent interfaces are implemented here. This project does not
depend on Kingfisher or another secret scanner SDK. It uses general-purpose
Rust regex, Aho–Corasick, hashing and archive libraries.

The built-in catalog contains 221 rules adapted from the MIT-licensed Gitleaks
v8.30.1 catalog plus four independently written rules (three generic assignment
rules and one URI-password rule), for 225 rules in the default engine.
See [rule provenance and exclusions](docs/RULE_SOURCES.md) and
[third-party notices](THIRD_PARTY_NOTICES). This is not a Gitleaks-compatible
engine: rule semantics that cannot be preserved are explicitly excluded.
The [implementation decision](docs/DECISIONS.md) records the build/adapt boundary
and rejected SDK and wrapper alternatives.

## Use

```sh
cargo build --release --locked
target/release/secret-scan scan /path/to/project --format json
target/release/secret-scan staged /path/to/repository
target/release/secret-scan history /path/to/repository
target/release/secret-scan history /path/to/repository --range main..HEAD
target/release/secret-scan scan - --format jsonl
target/release/secret-scan scan /path/to/project --write-baseline baseline.json
target/release/secret-scan scan /path/to/project --baseline baseline.json
target/release/secret-scan rules
target/release/secret-scan serve
target/release/secret-scan mcp --root /path/to/project
```

Exit codes: **0** means the selected scan completed with no reported findings;
**1** means it completed with findings; **2** means an error or incomplete scan.
An ignored finding is not evidence that the original input contained no secret.
Baselines suppress existing fingerprints but preserve changed secret values.
An incomplete scan cannot replace a baseline. Baseline schema 2 binds the scan
mode, canonical roots, effective ignore policy (including Git/Jujutsu repository
boundaries), size budget and engine settings
(including rule content and fingerprint key identity). A different scope or
policy cannot compare against or overwrite that baseline. Create a separate
baseline when intentionally changing policy. Schema 1 baselines are rejected.
Canonical filesystem identity makes aliases such as `./` stable; reported paths
and rule path predicates remain relative to the selected source root.

Every finding is redacted and contains a rule, path, byte range, one-based line,
zero-based byte column, confidence, explanation and fingerprint. No raw secret
or source snippet is serialized. The default unkeyed fingerprint is a digest,
not encryption and not protection against guessing low-entropy secrets. Supply
`--fingerprint-key-file` with exactly 32 private bytes for keyed BLAKE3 identities.
Keep the same private key when comparing baselines.

Exact matches at the same secret byte span within one decoded view are merged.
`rule_id` identifies the primary rule: non-`generic-` IDs take precedence, then
higher confidence, then lexical rule ID. Merged findings include sorted
`matched_rule_ids` containing the primary and other matching rules; single-rule
findings omit that field. Adjacent occurrences, partial overlaps and distinct
positions inside one Base64 container stay separate. The primary rule determines
the fingerprint. This semantic update changes the engine configuration identity,
so previous baselines must be explicitly recreated rather than compared silently.

Scanning never contacts credential providers or validates whether a credential
is active. Filesystem scans respect ignore files by default; `--no-ignore`
includes ignored files, while Git metadata remains excluded. Oversized inputs
are reported as incomplete, not clean. Default file and archive expansion limits
are 64 MiB; `--max-bytes` changes the budget. Archive traversal never writes
members to disk. ZIP, tar and gzip have a shared expansion budget and at most
four nesting levels. Encrypted or damaged members remain visible as errors.

Staged mode reads the **index** version of each changed file, not the working
tree. It scans whole staged files to preserve credential-pair context. History
mode scans locally reachable commits, reads each unique blob once and retains
commit/path occurrences. It does not fetch LFS, submodules or remote refs, and
also unpacks supported archives in Git blobs, retaining commit/member paths. `stats.files/bytes` count
unique inputs; `detection_passes` counts actual path-sensitive engine calls.

## Library and custom rules

```rust
use secret_scan::{Engine, EngineConfig};

fn main() -> anyhow::Result<()> {
    let engine = Engine::new(EngineConfig::default())?;
    let findings = engine.scan_bytes("config.env", b"ordinary configuration")?;
    assert!(findings.is_empty());
    Ok(())
}
```

Reuse an engine across calls and threads to avoid repeated compilation. It does
not install a global runtime, logger or executor.

`Finding.path` and `Finding.explanation` are shared `Arc<str>` values. This is a
breaking Rust API change from `String`: use `.into()` when assigning an owned
string, `.as_ref()` to read `&str`, and replace the field to change its text.
JSON still contains ordinary strings; fingerprints, scan context and baseline
identity are unchanged. Generated findings share paths within one engine scan
and explanations across calls using the same engine. Deserialization does not
intern repeated strings.

Custom JSON rule files use
`{"rules": [...]}` and can be supplied with `--rules path.json` or a rules
directory. `--no-builtin` selects only custom rules. Each rule has `id`, `name`,
`pattern`, optional `secret_group`, `keywords`, `min_entropy`, `confidence`,
`path`, `allowlist` and `exclude_paths`. Keywords are case-insensitive OR-ed
necessary conditions; rules without keywords are always considered. Allowlist
groups have `condition` (`or`/`and`), `target` (`secret`/`match`/`line`),
`regexes`, `paths`, and `stopwords`. Groups are OR-ed; predicates within one
category are OR-ed, then populated categories are combined using `condition`.
Stopwords are case-insensitive substrings of the secret. Empty groups fail.
Omitted/null `secret_group` selects the first nonempty capture (or whole match);
explicit `0` selects the whole match. These rule-schema changes are breaking.
Unknown rule
fields and invalid regexes fail visibly. Rule patterns are never echoed in
compilation errors. Custom rule descriptions and identifiers are trusted
configuration and should not contain real secrets.

Generic API/access/auth token assignments suppress long explanatory prose
(at least eight words plus sentence/clause punctuation). This heuristic does not
suppress natural-language password/secret assignments, but a real token formatted
as a long punctuated phrase can still be missed. Provider rules retain upstream
limitations; see the rule provenance document.

## Agent interfaces

`serve` accepts one JSON object per line: `{"id":1,"path":"file.txt","text":"..."}`.
Responses contain the same id and a complete redacted scan report. Rules are
compiled once. Malformed JSON returns an error without echoing the payload;
an oversized request terminates this simple stream.

The MCP stdio server supports initialization, ping, tool listing and calls to
`scan_text` and `scan_paths`. File paths must resolve beneath the configured
root. The server does not perform writes or network verification. Root checks
are not an OS sandbox against another local process replacing paths concurrently.
MCP errors and tool failures are distinct, and malformed/oversized frames do not
turn into successful clean results. stdout contains protocol messages only.
One scan runs at a time while ping and cancellation remain responsive. Clients
may supply a progress token and cancel by request id; cancelled requests receive
no final response, and the session remains usable. Cancellation is checked at
file, Git blob and archive-member boundaries (also archive read chunks), not
inside a single regex operation. Tool results include at most 100 findings and
100 errors within a shared 512 KiB entry budget, plus total counts and
`output_truncated`; truncation is independent of scan completeness.

JSON, JSONL and SARIF are available. Ordinary filesystem/Git JSONL scans emit
`finding`, `error` and `progress` records during scanning, followed by a `summary`
with counts and completeness. Bounded worker queues avoid collecting all file
reports; output errors stop further acquisition. Each worker still buffers one
input and its findings, and Git history metadata remains resident. JSON/SARIF,
stdin, and JSONL scans using baselines collect reports; baseline validation must
finish before filtered results are emitted. SDK callers can use the `scan_*_stream`
APIs with `ScanControl` and a fallible event sink. Regular progress is emitted at
most once per 100 ms, with first and final snapshots retained. These are
event-driven updates, not a heartbeat during a single long regex operation.
The CLI flushes its first finding and each error immediately; later findings use
buffered writes, and progress/final records flush remaining output.

## Verification and comparison

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
python3 -m unittest discover -s bench -p test_run.py
python3 bench/fixtures/generate.py --self-test
python3 scripts/import_rules.py --check
python3 -m unittest discover -s bench -p test_holdout.py
python3 -m unittest discover -s scripts -p test_stress_benchmark.py
python3 scripts/check_package.py --allow-dirty
```

[Benchmark methodology and reproduction](bench/README.md) separates synthetic
labelled quality from unlabelled real-source throughput. Versions, commands,
hardware, binary fingerprints, time, memory, parser completeness and unsupported
capabilities are retained. Online verification is disabled. These measurements
do not establish production accuracy or universal speed leadership.

Measured results: [implementation and measured findings](docs/RESULTS.md),
[current duplicate/progress iteration](bench/results/v3/README.md),
[previous holdout comparison](bench/results/v2/holdout-current.md),
[current regression/performance comparison](bench/results/v2/regression-current.md),
[historical cross-tool comparison](bench/results/final.md),
[machine-readable evidence](bench/results/final.json),
[persistent agent latency](bench/results/agent-latency.json) and
[UTF-16 memory comparison](bench/results/utf16-memory.json) and
[current whole-version stress comparison](bench/results/v2/stress-comparison.json).

[Feature implementation matrix](docs/FEATURES.md) maps every item in the research
catalog to implemented, partial or unimplemented status. Cloud connectors,
credential validation/revocation, GPU/ML backends and language bindings are not
implied by the presence of a CLI or MCP server.
