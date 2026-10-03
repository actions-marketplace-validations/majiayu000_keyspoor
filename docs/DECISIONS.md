# Implementation decision

The [initial research catalog](https://chatgpt.com/space/page_6fe99c59b9b88191b231df9e6ca4f898) compares 22 open-source tools/assets and 60 candidate capabilities. The local [feature matrix](FEATURES.md) records current implementation evidence.

The required boundary is an independently implemented Rust detection library,
with filesystem and Git acquisition, safe machine-readable results and an
offline, reproducible comparison. Performance, coverage and agent integration
are separate objectives: a narrow scanner can be faster while missing more.

## Build the core; adapt rule data

The user's explicit constraint is that the core must be self-developed and must
not adopt Kingfisher SDK. Accordingly this repository owns keyword dispatch,
matching orchestration, filtering, coordinate mapping, fingerprints, acquisition
and public interfaces. General-purpose regex, Aho–Corasick, compression and
serialization crates are dependencies; another secrets scanner is not.

Adapting the MIT Gitleaks rule catalog provides a reviewable starting catalog.
The importer pins upstream source and license digests, retains supported
semantics and excludes rules requiring unsupported behavior. This does not
transfer Gitleaks' engine, integrations or accuracy guarantees. Details and
excluded rules are in [RULE_SOURCES.md](RULE_SOURCES.md).

Embedding Kingfisher was rejected because it violates the explicit core
constraint. Wrapping Gitleaks or TruffleHog was rejected because subprocess
orchestration would not provide the requested independent in-process engine.
Writing a new regex automaton or GPU backend was deferred because the present
implementation has no measured evidence requiring one. Commercial cloud
detection through GitGuardian is a separate service boundary and cannot be
treated as an offline open-source engine.

## Validation and risks

Correctness checks cover source coordinates, encoding, archive budgets, index
versus worktree contents, Git provenance, redaction, error completeness and
baseline preservation. Comparative measurements pin tool versions and record
commands, binary hashes, input hashes, runtime and memory. Synthetic labelled
quality is reported separately from unlabelled real-source performance.

The default rule sets and input processing differ between products. Measured
end-to-end CLI time is therefore a product comparison, not proof that one regex
engine is intrinsically faster. Changes informed by the labelled suite make
subsequent scores regression results, not an independent holdout evaluation.
Known limitations and all 60 research candidates are mapped in
[FEATURES.md](FEATURES.md); an implemented entry only means its stated subset.

## Scope safety and streaming update

The implementation keeps the existing `Engine` and collecting APIs, with a
small `ScanContext` value and synchronous event sink. Baselines compare scope
and effective detection/selection policy before suppressing or resolving any
finding. This rejects intentional policy changes rather than inventing an
implicit migration or treating a smaller scan as a clean full scan.

Filesystem acquisition uses standard-library scoped workers and bounded queues;
MCP uses one scan worker and a separate protocol reader. An async runtime,
persistent task service, pagination store and per-rule cancellation machinery
were not needed for the current requirement. File-level buffering and Git
metadata remain explicit limits. Cancellation is cooperative, and sink failures
retain the error contract. Baseline-filtered JSONL collects first because its
ignore-policy identity is only final after traversal.

Rule capture and allowlist semantics are adapted from the pinned Gitleaks source;
only its path-only PKCS12 rule remains excluded. Schema changes are intentional
breaking changes, with no legacy rule/baseline conversion layer. Quality checks
now distinguish uncertain localization from false positives and freeze an
independently generated synthetic holdout before scoring. These decisions are
validated with context mismatch, source identity, flow-control, protocol and
location tests, plus whole-version stress and cross-tool measurements.


## Exact occurrence merging and progress volume

Multiple rules may describe one secret occurrence. Merge only identical secret
byte spans inside the same decoded view, before mapping Base64 spans to their
source container. Keep all contributing rule IDs and select the primary by
non-generic prefix, confidence and lexical ID; keep adjacent/overlapping spans
separate. Construct fingerprints and findings after grouping to avoid redundant
allocation. A new engine semantic identity invalidates incompatible baselines.

Progress uses the existing scan event sink with a private 100 ms throttle; no
new public setting or task runtime is introduced. First/final progress stays,
while first findings and errors are flushed independently at the CLI boundary.

The 25 previous-holdout false positives are long descriptions assigned to
token-like keys. Byte-level input does not establish whether such a phrase is
documentation or an actual credential. Extending the exclusion to all long
phrases, or only quoted/hyphenated dictionary keys, was rejected because it
would sacrifice existing long-credential positives based on evaluation examples.
The filter is unchanged. That observed dataset is now regression data; a new
synthetic value/context corpus is frozen independently for this iteration.

## Fixed-offset candidate activation

The current requirement is to remove repeated matching work on frequent token
prefixes without sacrificing the corrected Airtable coverage or changing SDK
and Agent output. Adopt `regex-syntax` HIR byte-width information (already a
transitive dependency), and build only a small necessary-condition check on
existing Aho-Corasick occurrence positions. A proved initial literal must agree
with all configured keywords; a later mandatory literal must have a fixed byte
offset. Unknown structures keep the existing matching path. Successful candidate
activation still uses the complete original regex and haystack.

The relevant primary sources are the [HIR byte-length properties](https://docs.rs/regex-syntax/latest/regex_syntax/hir/struct.Properties.html)
and [regex search/capture API](https://docs.rs/regex/latest/regex/bytes/struct.Regex.html#method.captures_read_at).
The latter searches from an offset without anchoring there; invoking it once per
candidate can repeatedly scan the suffix. A new windowed matcher, regex backend
or provider-ID-specific predicate is unnecessary for this bounded requirement.
No scanner SDK or rule-schema extension is introduced.

The completeness argument is local: every actual regex match produces its
required AC prefix occurrence, and its required interior literal necessarily
passes the fixed-offset check. Bounds-safe failure rejects that occurrence only,
not later occurrences. ASCII keyword folding may admit extra candidates, which
the unchanged regex rejects. HIR parsing uses the byte regex's Unicode settings;
fixed width means bytes, not characters. Conditional branches are not used as
literal evidence. Differential tests compare full findings to an unconditional
regex oracle, including binary bytes, captures, decoding, keyword overlap and
custom overrides. Pair benchmarks measure the added per-occurrence check as
well as avoided regex work; unmeasured speedups are not assumed.

The initial eager derivation showed a small real-source CPU increase. Derive the
optional check on a rule's first keyword hit instead and retain it in an
engine-local `OnceLock`. Parallel scans share that one initialization; no global
cache or public option is added. Later hits still pay the initialized-cell read,
which is included in the final pair measurements. Rules and configuration
identity are unchanged because this is only a proved candidate optimization.

## Shared result metadata

Allocator instrumentation on the existing dense-result workload confirmed
repeated path and explanation allocations. Change only these two public
`Finding` fields to `Arc<str>`, using serde's existing `rc` support to preserve
plain JSON strings. The Rust field-type change is intentional and documented;
no compatibility wrapper or wire-format version is added.

Allocate a path only for the first finding in one scan and clone its Arc for
later findings, including decoded views. Each rule lazily retains at most four
explanation variants (plain, Base64, UTF-16 and both). These contain only rule
metadata and encoding annotations, never source buffers or captured secrets.
Keep the previous annotation text/order and mapping errors. Owned Arcs let
findings outlive the engine and move through existing worker queues without
introducing borrowing constraints or a global interning pool. Git commit-path
projection still constructs a display path per projected finding; that limit is
explicit rather than introducing another cache in this change.

Measure allocations separately from timing: a standalone, single-thread warmed
GlobalAlloc probe counts requested layout bytes, then ordinary CLI pair runs
measure CPU, RSS and output latency without that instrumentation. Complete
serialized findings must match between binaries; pointer-sharing assertions
check that the intended allocation reduction is actually connected to results.

## Public identity and distribution

Publish the initial release as **Keyspoor**, with `keyspoor` for the GitHub
repository, Cargo package, Rust import and CLI, and npm package. On 2026-10-04,
the npm and crates.io exact-name endpoints returned 404 and GitHub repository
name search returned no matches. This is an availability check, not a trademark
clearance. Historical benchmark reports retain their original `secret-scan`
name and binary hashes. Fingerprint/configuration domain separators also retain
their exact bytes: changing a product label must not change detection identity.

The Rust engine remains the implementation. npm distributes the same native
CLI, not a JavaScript SDK or a second scanner. Adapt the native-tool distribution
pattern used by [esbuild](https://github.com/evanw/esbuild/tree/main/npm) and
[vscode-ripgrep](https://github.com/microsoft/vscode-ripgrep): for this small
initial release, bundle all five supported binaries in one package rather than
introduce per-platform packages or installation-time downloads. This costs a
larger download but requires no lifecycle install script, network fetch or
compiler on the consumer machine. Node only forwards arguments, stdio, signals
and exit status. Linux assets target GNU libc; musl and Windows ARM64 are not
included. Rust users can build supported additional targets themselves.

Release binaries come from native GitHub-hosted runners. Publish source and
checksummed binaries on GitHub, validate the assembled npm tarball and an
independent Cargo consumer, then verify each registry independently. Search
metadata and a static Pages homepage improve crawlability; they do not establish
Google indexing or rankings. Registry login and Search Console ownership remain
separate external prerequisites, not application features.
