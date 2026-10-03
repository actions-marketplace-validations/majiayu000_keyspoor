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
