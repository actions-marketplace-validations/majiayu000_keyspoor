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
