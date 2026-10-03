# v4: candidate-gate correction, JSONL allocation reduction and measurement repair

Core remains independently implemented in Rust. This iteration changes only the Airtable mandatory keyword, borrowed JSONL serialization, and the stress harness exit wait. It does not introduce an SDK, a new detection backend, or general HIR-derived filtering.

Baseline: `d332c9c`, SHA-256 `b607dd486f9a62670b0f42bb93e3739346ae4a27f1728f0be8e00851f5590239`. Candidate: SHA-256 `2f8029c58d3ad2ce1525cc2b3ab81e5799013057d9854a6b7e2e1cc6a51c0555`. [Pinned tools and commands](manifest.json).

## Detection quality

All previously inspected synthetic corpora are now regression sets, not new blind holdouts. No labels were changed. Scans are offline and tokens are synthetic format fixtures; this does not establish real-world precision or credential validity.

| Corpus | Before TP / FP / FN | After TP / FP / FN |
|---|---|---|
| Original regression | 34 / 0 / 0 | 34 / 0 / 0 |
| Previously observed v2 corpus | 599 / 25 / 1 | 600 / 25 / 0 |
| Previously observed v3 corpus | 595 / 25 / 5 | 600 / 25 / 0 |

The Airtable-specific detector now identifies all 24 v3 samples, versus 0 before (19 were previously generic-rule fallback hits). Its prefilter now uses the required `pat` prefix, not the optional context word `airtable`. The importer reproduces this local adaptation. Generic stopword semantics are unchanged: provider detection now also catches the synthetic hexadecimal token containing `feed`. The 25 ambiguous description-text alerts remain. Rule-content configuration hashing changes automatically, so prior scan baselines require explicit rebuilding; provider attribution changes also affect fingerprints.

[All-tool quality table](quality-comparison.md) and [raw normalized evidence](quality-comparison.json): 19 current filesystem scanners, plus the previous local binary, completed three scans each (first process, warmup, one measured repeat). These quality runs are not a robust speed ranking. Talisman has no filesystem adapter; three inventory entries remain unavailable/non-executable. Line-only localization ambiguities remain `unlocalized`, not definite false positives. [Earlier corpus regression](previous-quality.json) and [original regression](regression-performance.json) are retained separately.

## Corrected stress measurement

Both binaries use the same repaired harness. After pipe EOF, wait4 is polled without an empty-selector 100 ms delay; sleeps request at most 1 ms, but scheduler delays may be longer. Timeout, output draining, wait4 usage and failure propagation remain tested. Results below cannot be compared directly to historical harness timings to claim an engine speedup.

Each case ran 20 alternating before/after pairs, 240 measured scanner processes across six cases, after compilation stopped. Fresh processes, four threads, Base64 disabled, filesystem cache uncontrolled. Exact locations/rules match in all stress runs. Wall time includes JSONL parsing, validation, hashing and backpressure in the Python consumer; CPU and RSS refer to the scanner child. No machine isolation or statistical-significance claim.

| Case | Wall median ms before → after | CPU user+system median ms before → after | RSS median MiB before → after |
|---|---:|---:|---:|
| newline_dense_16mib | 76.98 → 77.05 | 72.96 → 73.85 | 37.25 → 37.01 |
| manyfiles_10000 | 185.83 → 185.55 | 610.30 → 608.02 | 20.23 → 20.10 |
| git_fixedblobs_1commits | 103.09 → 99.37 | 88.12 → 87.25 | 19.01 → 18.70 |
| git_fixedblobs_200commits | 98.09 → 99.06 | 85.56 → 85.82 | 18.90 → 18.73 |
| densefindings_10000 | 181.39 → 179.67 | 79.62 → 64.64 | 28.80 → 28.72 |
| densefindings_100000 | 1436.16 → 1424.66 | 376.91 → 290.14 | 100.05 → 99.85 |

For 100,000 findings, scanner CPU decreases 23.0% (all 20 paired CPU measurements lower), but consumer-inclusive wall time decreases only 0.8% (12/20 pairs lower). RSS is essentially unchanged. The output remains 51,235,415 bytes. Removing intermediate JSON objects reduces work without shrinking the retained Finding representation or the payload. The collected JSONL path also no longer clones findings/errors/stats/context. JSON object key order changes, but field values, omission, null context, newline/flush semantics and output errors are preserved.

Raw runs and ranges: [filesystem/Git](stress-files-git.json), [dense output](stress-dense.json).

## Throughput and the cost of fixing recall

The initial five-repeat, version-blocked run is retained in [regression-performance.json](regression-performance.json). Because its direction varied across workloads, a separate [20-pair alternating measurement](paired-throughput.json) was run; [reproduction driver](paired-throughput.py) reuses the existing benchmark measurement/parser. CLI JSON is written to a temporary file, and parsing/parity checks run after timing. Both versions use their default thread count and decoding settings. One warmup per version/dataset is excluded.

| Dataset | Wall median ms before → after | CPU user+system median ms before → after |
|---|---:|---:|
| throughput-16mib | 76.30 → 75.16 | 141.36 → 146.02 |
| throughput-128mib | 309.36 → 342.44 | 826.73 → 869.44 |
| real-regex | 116.28 → 127.83 | 231.90 → 234.87 |

128 MiB CPU increases 5.17%, with all 20 paired CPU measurements higher; median wall time increases 10.69%, with substantial scheduling variation. This is a measured tradeoff, not a universal performance improvement. Verified corpus inspection finds `pat` in all 512 files (1,980,022 occurrences), while `airtable` occurs in none. Therefore the corrected rule runs where the old incorrect gate skipped it; the extra candidate work is consistent with the CPU increase. No isolated backend profiling was performed, so this is not a per-function cost attribution. The next bounded algorithm experiment should target frequent false prefix candidates while maintaining equivalence to the full regex.

Throughput locations remain identical (16/16 and 128/128 injected positions); the fixed real-regex source has no findings in either version and is unlabelled. The current result does not establish a universal speed or accuracy lead over competitors.

## Checks completed

- 110 Rust tests across all targets; doc tests completed (zero examples).
- 59 Python tests (37 benchmark/corpus and 22 stress harness).
- cargo fmt, Clippy with warnings denied, release build and Rust 1.96.1 check.
- Pinned upstream rule regeneration/check and corpus generator self-test.
- Real .crate independent consumer: clean/finding/error exits 0/1/2 and redaction verified.
- Independent diff review found no blocking defects; added buffered-output-after-exit regression.
- macOS measured locally. Linux/Windows CI was not executed in this iteration. No publication or push.

## Reproduce

Preserve the pinned old executable and corpus/tool installations. Output paths must be new; original artifacts are never overwritten.

```sh
python3 bench/run.py --manifest bench/results/v4/manifest.json --corpus bench/corpus-holdout-v3 --output /tmp/v4-quality-new.json --corpus-role regression --repeats 1
python3 scripts/stress_benchmark.py --before bench/tools/secret-scan-d332c9c --after target/release/secret-scan --repeats 20 --cases newline manyfiles git --output /tmp/v4-files-new.json
python3 scripts/stress_benchmark.py --before bench/tools/secret-scan-d332c9c --after target/release/secret-scan --repeats 20 --cases dense --output /tmp/v4-dense-new.json
python3 bench/results/v4/paired-throughput.py /tmp/v4-throughput-new.json
```
