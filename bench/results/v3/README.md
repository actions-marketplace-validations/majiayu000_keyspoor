# Iteration v3 measured results

**Final candidate:** `b607dd486f9a62670b0f42bb93e3739346ae4a27f1728f0be8e00851f5590239`. See the final measurements below and [current quality table](fresh-holdout-current.md). The intermediate first batch is preserved at the end as historical evidence.


## Final performance-only revision and recheck

Final release SHA-256: `b607dd486f9a62670b0f42bb93e3739346ae4a27f1728f0be8e00851f5590239`; [optimized manifest](manifest-optimized.json). A single-keyword candidate fast path avoids a temporary vector/sort. It does not change detection/allowlist/dedup semantics. After 104 Rust tests, fmt, clippy and Rust 1.96.1 check completed, both 9da912a and the final candidate reran all three quality sets, three throughput datasets and six stress scenarios with three repeats. This is a separate measured batch; the intermediate evidence below remains historical.

The previously fresh v3 corpus is now declared `regression` in the final rerun because its first results had been observed. No rules or labels were adjusted from those results. TP/FP/FN remained 34/0/0, 599/25/1 and 595/25/5 respectively; final duplicates remained zero on all three. [Final all-tool quality table](fresh-holdout-current.md) combines the original competitor measurements and the final local verification without producing a duplicated merged JSON.

| Final throughput comparison | Before median ms | After median ms |
|---|---:|---:|
| throughput-16mib | 68.284 | 60.183 |
| throughput-128mib | 213.437 | 221.011 |
| real-regex | 71.210 | 71.256 |

| Final stress scenario | Wall ms before → after | First finding ms before → after | Peak RSS MiB before → after | Progress events before → after | Stdout bytes before → after |
|---|---:|---:|---:|---:|---:|
| newline_dense_16mib | 72.230 → 73.149 | 70.298 → 70.578 | 37.500 → 37.266 | 2 → 2 | 1,222 → 1,222 |
| manyfiles_10000 | 156.583 → 148.719 | 33.932 → 33.931 | 20.203 → 20.141 | 10,001 → 3 | 1,144,455 → 50,527 |
| densefindings_10000 | 167.481 → 167.257 | 51.110 → 51.283 | 28.203 → 28.969 | 2 → 2 | 5,084,187 → 5,084,187 |
| densefindings_100000 | 1416.584 → 1387.889 | 235.012 → 223.160 | 98.797 → 100.094 | 2 → 2 | 51,235,415 → 51,235,415 |
| git_fixedblobs_1commits | 89.805 → 90.300 | 87.461 → 87.750 | 18.734 → 18.797 | 18 → 2 | 2,862 → 1,236 |
| git_fixedblobs_200commits | 85.289 → 83.220 | 82.464 → 80.715 | 18.922 → 18.844 | 18 → 2 | 109,729 → 108,103 |

The initial dense-100k regression did not recur in the final batch: wall medians were 1416.6 → 1387.9 ms and first finding 235.0 → 223.2 ms. Wall ranges overlap (1382.6–1557.2 ms before, 1386.4–1411.2 ms after); this does not demonstrate a statistically significant speedup or isolate the fast path’s effect. Final peak RSS still rose by about 1.30 MiB in this scenario. The 128 MiB throughput case was 3.5% slower; real-source wall time was essentially unchanged. 10,000-file progress output fell from 10,001 to 3 events and stdout fell 95.6%, with the first finding unchanged at about 33.93 ms. Comparing initial and final absolute times directly would confound separate machine-state batches; each batch retains its contemporaneously measured baseline.

Final raw artifacts: [original quality](regression-quality-optimized.json), [former v2 holdout](previous-holdout-regression-optimized.json), [observed v3 corpus recheck](fresh-holdout-optimized.json), [throughput](performance-optimized.json), [stress](stress-comparison-optimized.json). The binary SHA-256 was verified unchanged afterward. Six stress fixtures retained exact-coordinate/detection parity.

## Intermediate 72dc6272 batch — historical evidence

The following measurements precede the final performance-only revision. They are not the final candidate results. Original JSON and generated Markdown artifacts remain unchanged.

Release SHA-256: `72dc62725996cb927cbd5416a867864cf815c6df34d9ff6ee4b296fd64065ee3`. Baseline: `9da912a`, SHA-256 `9c6c2052d33d7479ae9ce998e0565e9faa9daf617826ed9b4cb1f1624872e85d`. Both use independent Rust scan engines. Rule and corpus updates were frozen before the fresh holdout was first run. All commands ran sequentially after tests/builds stopped, on Apple M2 Max / macOS; each quality/performance row has a first process, one warmup and three warm-filesystem repeats. Stress alternates before/after execution order for three repeats.

## Quality and duplicate suppression

| Dataset | Before TP/FP/FN | After TP/FP/FN | Duplicate findings before → after |
|---|---|---|---:|
| [Original regression](regression-quality.md) | 34/0/0 | 34/0/0 | 28 → 0 |
| [Former v2 holdout, now regression](previous-holdout-regression.md) | 599/25/1 | 599/25/1 | 421 → 0 |
| [Fresh synthetic v3 holdout](fresh-holdout.md) | 595/25/5 | 595/25/5 | 369 → 0 |

Confirmed location recall and unique false positives did not change in these measured sets. Removing overlapping generic detections removed all scorer duplicates here; this is not a claim that arbitrary cross-rule duplicates are universally removed. All 25 fresh-holdout false positives are in the catalog-description negative family. The fresh synthetic set contains 600 positive locations (580 distinct positive values) and 300 negative positions; it does not estimate real-code precision or test live credentials.

[All-tool fresh-holdout table](fresh-holdout.md) records 19 current filesystem scanners actually run, plus the baseline version (20 successful rows). Talisman has no filesystem adapter. Three other inventory entries are unavailable or not executable. Competing scanners retain their pinned versions and default rules. The scorer retains line-only ambiguity as `unlocalized`, so differing localization capabilities affect confirmed recall; do not rank raw recall as pure detection ability.

## Throughput

[Full repeated measurements](performance.md). Before/after medians include process startup, file traversal and JSON serialization. No new competitor throughput run was made in this iteration; earlier competitor timing belongs to its own run and is not substituted here.

| Dataset | Before median ms | After median ms |
|---|---:|---:|
| throughput-16mib | 105.398 | 65.859 |
| throughput-128mib | 306.693 | 226.552 |
| real-regex | 110.159 | 78.156 |

## Stress and output cost

All six fixtures passed exact finding-coordinate validation and before/after finding parity. Values are medians; raw repeats and their ranges remain in [stress-comparison.json](stress-comparison.json). The timings include JSONL consumption/validation and backpressure, not only scanner execution.

| Scenario | Wall ms before → after | First finding ms before → after | Peak RSS MiB before → after | Progress events before → after | Stdout bytes before → after |
|---|---:|---:|---:|---:|---:|
| newline_dense_16mib | 77.327 → 76.058 | 75.238 → 74.163 | 37.312 → 37.016 | 2 → 2 | 1,222 → 1,222 |
| manyfiles_10000 | 273.934 → 275.341 | 37.679 → 38.368 | 20.234 → 20.328 | 10,001 → 4 | 1,148,399 → 50,637 |
| densefindings_10000 | 190.774 → 179.453 | 57.639 → 57.096 | 28.219 → 29.516 | 2 → 2 | 5,084,187 → 5,084,187 |
| densefindings_100000 | 1566.592 → 1831.670 | 255.286 → 285.004 | 97.516 → 102.531 | 2 → 2 | 51,235,415 → 51,235,415 |
| git_fixedblobs_1commits | 170.544 → 168.256 | 160.916 → 164.213 | 18.844 → 18.922 | 18 → 2 | 2,880 → 1,238 |
| git_fixedblobs_200commits | 196.813 → 168.171 | 192.345 → 162.325 | 18.797 → 19.219 | 18 → 2 | 109,748 → 108,106 |

10,000-file progress records fell from 10,001 to 4 and stdout fell 95.6%; measured end-to-end wall and first-finding times did not improve. The 100,000-finding workload regressed by 16.9% in median wall time, 11.6% in first-finding time and about 5.0 MiB in peak RSS. Its wall-time ranges were 1459–1766 ms before and 1768–2278 ms after. This workload has no duplicate findings to eliminate, so the evidence does not justify a universal speedup claim. The 200-commit median improved, with overlapping ranges (173–201 ms before, 142–226 ms after). Whole-version differences and only three repeats prevent isolated causal attribution.

## Evidence and checks

- [Frozen manifests](manifest-final.json) identify both binaries and installed tools; the baseline-only preparation manifest is also retained.
- Quality/performance artifacts use schema/scoring 2; `v3` is an iteration directory. Stress keeps its separate existing schema 1.
- 16 stress harness tests passed, including coordinate, duplicate, incomplete-output, progress-count and summary contracts.
- Raw scanner text is discarded; retained per-run evidence is redacted normalized location data. No additional merged JSON duplicates these artifacts.
- The candidate binary hash was rechecked after all measurements and remained unchanged.
