# v5: fixed-offset keyword candidate gate

Baseline: v4 (`22546da` sources), binary SHA-256 `2f8029c58d3ad2ce1525cc2b3ab81e5799013057d9854a6b7e2e1cc6a51c0555`. Final candidate SHA-256 `aca1a038f1faaf485e054dc7e208ce49027624fd63542019afe8b29e8a3412e5`. [Commands and manifest](manifest.json).

## Change and proof boundary

At an existing Aho-Corasick keyword occurrence, check a mandatory interior literal at a proven byte offset before activating the rule. Derive this check from regex-syntax HIR; require every configured keyword to equal the mandatory starting literal under ASCII case folding. Flatten only concatenation/captures, skip zero-width assertions, and cross other components only when their minimum and maximum byte widths agree. Unknown structures retain the original candidate path. A passing occurrence still invokes the unchanged full regex on the full content view. No candidate windows, provider-ID predicates, scanner SDK, public config or changed rule data.

Every actual regex match supplies its required prefix and interior literal, so one of its AC occurrences must pass. Check every occurrence until activation; bounds-safe rejection cannot disable later valid occurrences. Derivation is cached in an engine-local OnceLock on first keyword hit, not eagerly parsed for every rule at Engine construction. Concurrent initial hits share initialization. See [decision and primary API sources](../../../docs/DECISIONS.md#fixed-offset-candidate-activation).

Current catalog: 7 of 225 rules qualify: 1password-secret-key, airtable-personnal-access-token, duffel-api-token, dynatrace-api-token, postman-api-token, sendinblue-api-token, shippo-api-token. The 128 MiB corpus has 1,980,022 `pat` occurrences, none followed by the required dot at byte offset 17. This permits avoiding the Airtable full-regex pass while keeping token detection enabled.

Provenance clarification: the reused manifest's `version` labels still say `v3 frozen candidate`; those inherited labels are stale. The executable paths and measured SHA-256 values above identify the actual v4/v5 binaries (package version 0.1.0). Raw stress metadata also inherits an older explanation for excluding fingerprints from its identity digest. Fingerprint policy did not change in this iteration; the separate full-contract comparison below verifies fingerprints and context explicitly. Original measurement metadata and hashes are retained rather than rewritten after the run.

## Detection and contract parity

| Observed regression corpus | Before TP / FP / FN | After TP / FP / FN |
|---|---|---|
| v3 synthetic | 600 / 25 / 0 | 600 / 25 / 0 |
| v2 synthetic | 600 / 25 / 0 | 600 / 25 / 0 |
| Original | 34 / 0 / 0 | 34 / 0 / 0 |
| Capability labels | 6 / 0 / 0 | 6 / 0 / 0 |

[Current quality](quality-regression.json), [previous corpus](previous-quality.json), [original/capability results](original-regression.json). All are previously observed synthetic regression data, not new blind holdouts or estimates of real-world precision. The 25 ambiguous description alerts remain. Competitors were not rerun for this engine-only optimization; [v4 all-tool results](../v4/quality-comparison.md) retain their own measurement provenance.

[Additional contract comparison](contract-parity.json) checks complete Finding objects, fingerprints, matched rule evidence and ScanContext across four corpora, beyond the benchmark scorer's location projection. All match. The capability scan has eight findings but six labelled positives (archive probes are evaluated separately). Configuration identity and baseline compatibility with v4 remain unchanged.

## Final paired throughput

20 alternating before/after pairs per dataset after one warmup per binary. Fresh processes, default threading/decoding, uncontrolled warm filesystem cache. CLI JSON goes to a temporary file; parsing/parity validation occurs after timing. [Raw runs](paired-throughput.json), [reproduction driver](paired-throughput.py). Timings are from one shared-machine batch, not isolated CPU-kernel measurements.

| Dataset | Wall median ms before → after | CPU user+system median ms before → after | Paired CPU reductions |
|---|---:|---:|---:|
| throughput-16mib | 62.80 → 61.61 | 133.70 → 130.24 | 20/20 |
| throughput-128mib | 236.40 → 228.63 | 813.31 → 784.68 | 20/20 |
| real-regex | 78.90 → 78.76 | 207.43 → 206.99 | 10/20 |

128 MiB CPU decreased 3.52%, wall median decreased 3.29%; 16 MiB CPU decreased 2.59%. Real-source CPU/wall are essentially unchanged. This reduces the cost relative to v4; it does not prove complete recovery of v4's historical 5.17% increment, and percentages from separate batches must not be subtracted. Peak RSS did not show a meaningful reduction.

## Stress and first result

Six cases, 20 alternating pairs each (240 measured processes), four threads, Base64 disabled. Exact coordinate/rule parity holds throughout. Wall and first-result timings include JSONL consumer validation/backpressure; RSS is per-child wait4 peak, not aggregate process-tree memory. All workloads ran after builds stopped.

| Case | Wall median ms before → after | First finding ms before → after | RSS median MiB before → after |
|---|---:|---:|---:|
| newline_dense_16mib | 76.58 → 77.07 | 74.47 → 74.72 | 37.13 → 37.07 |
| manyfiles_10000 | 251.90 → 232.00 | 36.25 → 36.06 | 20.11 → 20.06 |
| git_fixedblobs_1commits | 94.95 → 95.00 | 92.56 → 92.64 | 18.49 → 18.59 |
| git_fixedblobs_200commits | 96.46 → 96.97 | 93.74 → 94.10 | 18.58 → 18.61 |
| densefindings_10000 | 173.94 → 172.77 | 53.73 → 53.46 | 28.67 → 28.78 |
| densefindings_100000 | 1414.07 → 1411.85 | 227.22 → 228.24 | 99.73 → 100.01 |

[Files/Git raw runs](stress-files-git.json), [dense-output raw runs](stress-dense.json). Most cases are effectively flat; many-files wall median is lower in this batch, with large system-time and scheduling variation, so it is not attributed solely to this gate. Dense output still retains per-file findings; the change does not solve that memory limit.

## Retained initial experiment

[Eager-derivation pair results](paired-throughput-eager.json) identify the initial `156a0466…` binary. It reduced 128 MiB CPU by 2.78% but real-source CPU rose 1.54%; that prompted lazy derivation. Those measurements are historical, not the final candidate. Each batch retains its own contemporaneous baseline; compare each candidate to its paired baseline rather than absolute times across batches.

## Checks and reproduction

- 116 Rust tests passed, including HIR proof boundaries and full-Finding differential checks on 11 pattern families × 32 deterministic input variants, plus decoded views and real catalog regression.
- 59 Python tests passed. fmt, Clippy with warnings denied, Rust 1.96.1 and release build passed.
- Final .crate independent consumer validated clean/finding/error exits and redaction. No publication or push; Linux/Windows CI not executed.
- Independent code review found no blocking defects. Both measured executable hashes were verified; no real credentials or online provider validation were used.

Use new output paths to preserve original evidence. The old binary and fixed corpora must be present.

```sh
python3 bench/results/v5/paired-throughput.py /tmp/v5-throughput-new.json
python3 bench/run.py --manifest bench/results/v5/manifest.json --corpus bench/corpus-holdout-v3 --output /tmp/v5-quality-new.json --corpus-role regression --repeats 1
python3 scripts/stress_benchmark.py --before bench/tools/secret-scan-v4-2f8029c5 --after target/release/secret-scan --repeats 20 --cases newline manyfiles git --output /tmp/v5-files-new.json
python3 scripts/stress_benchmark.py --before bench/tools/secret-scan-v4-2f8029c5 --after target/release/secret-scan --repeats 20 --cases dense --output /tmp/v5-dense-new.json
```
