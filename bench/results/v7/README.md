# v7: credential assignment context corrections (0.1.4)

Measured on 2026-10-08 (Asia/Shanghai), macOS ARM64 / Apple M2 Max. Baseline:
public native Keyspoor **0.1.3**; candidate: release build of **0.1.4**. Binary
hashes, commands, pinned sources, process runs, normalized findings and scoring
records are retained in [compressed raw evidence](results.json.gz).

## Real-source findings

The same pinned snapshots from [the adoption trial](../../../docs/ADOPTION.md)
were scanned without building projects or contacting credential providers.

| Snapshot | 0.1.3 findings | 0.1.4 findings | Confirmed non-secret spans removed | Other removed |
|---|---:|---:|---:|---|
| remem | 73 | 33 | 40 | 0 |
| argus | 46 | 28 | 16 | 2 previously unresolved tokens in reviewer notes |
| rclean | 0 | 0 | 0 | 0 |

All **56 confirmed non-secret spans** in the [location review](../../../docs/FINDING_REVIEW.md)
are removed. All 34 intentional test fixtures and 24 evaluation-artifact
occurrences remain. Two previously unresolved reviewer-note spans also disappear;
they are not counted as confirmed false positives or established credentials.
The three unresolved JWT-shaped dataset values remain. No new finding locations
appear; every scan completes with zero errors. This is context review, not a
production precision or recall estimate.

## Synthetic regression and comparison

Each cell is **TP / FP / FN / unlocalized** under existing scorer-v2 semantics.
These are previously used diagnostic/regression sets, including the former v2
and v3 holdouts; neither is a new independent holdout for this change. Synthetic
formats do not establish live validity, production accuracy or universal ranking.
An unlocalized report cannot be assumed incorrect and reduces confirmed-location
recall. Versions are pinned installed versions, not claims about latest upstream.

| Tool | Original quality | Previous v2 holdout | Previous v3 holdout |
|---|---|---|---|
| Keyspoor 0.1.3 | 34 / 0 / 0 / 0 | 600 / 25 / 0 / 0 | 600 / 25 / 0 / 0 |
| Keyspoor 0.1.4 | 34 / 0 / 0 / 0 | 600 / 25 / 0 / 0 | 600 / 25 / 0 / 0 |
| Gitleaks 8.30.1 | 31 / 0 / 3 / 0 | 493 / 14 / 107 / 0 | 414 / 15 / 186 / 76 |
| Kingfisher 2.9.1 | 24 / 0 / 10 / 0 | 409 / 0 / 191 / 0 | 340 / 0 / 260 / 68 |
| detect-secrets 1.5.0 | 34 / 4 / 0 / 0 | 400 / 75 / 200 / 0 | 377 / 75 / 223 / 46 |

The 1,234 labelled positive occurrences across these three sets are retained,
with zero candidate false negatives or unlocalized findings. Existing synthetic
false positives remain 0, 25 and 25; this fix addresses separate real-source
metadata/reference cases. Scans use default rules and offline verification
flags; Kingfisher uses `--no-dedup` to retain occurrences. The runner performs a
first process run, one warmup and three repetitions with uncontrolled OS caches.

**Root/cwd requirement:** run the scorer from the directory containing the
source corpora. detect-secrets's default root is its cwd; it silently omits
outside-root paths. Its manifest cwd is explicitly that source repository, and
the scorer is launched there so returned relative paths localize correctly.
Early outside-root and mismatched-cwd diagnostic runs are excluded from this
published comparison. Only verified, localized runs are included above.

## Paired native performance

Five workloads use 20 alternating before/after pairs, after one warmup per
binary/workload. All builds and quality runs finish before timing. Each run
starts a new native process; times include startup, traversal and JSON output.
Filesystem caches are uncontrolled. CPU is process user + system time; RSS is
wait4 scanner-process peak, not aggregate process-tree memory. No universal
speedup is inferred from shared-machine measurements.

| Workload | Wall median ms before → after | CPU median ms before → after | RSS median MiB before → after |
|---|---:|---:|---:|
| remem | 534.83 → 507.94 | 2073.89 → 1969.05 | 73.04 → 66.33 |
| rclean | 49.47 → 49.48 | 100.01 → 99.73 | 28.28 → 27.43 |
| argus | 276.96 → 260.80 | 631.82 → 597.67 | 56.66 → 50.94 |
| throughput-16mib | 57.99 → 58.14 | 122.98 → 123.02 | 22.82 → 22.81 |
| throughput-128mib | 211.57 → 212.14 | 741.22 → 742.42 | 23.93 → 23.85 |

The 16/128 MiB synthetic throughput workloads change by less than 0.3% in wall
median, while the two finding-heavy public snapshots are about 5% faster. These
observations support no material throughput regression in the measured workloads;
they do not isolate rule matching from output work or prove production speedups.
Finding-location digests are deterministic across every pair. Synthetic
throughput locations and processed file/byte counts match before and after.

## Reproduce

Download the three pinned archives linked in ADOPTION.md and initialize a
local temporary Git repository in each for ignore behavior. Put their
`repository`, `commit` and absolute `directory` in the same JSON-array metadata
shape as the `paired.sources` field of results.json.gz. Restore corpora/tools
using [the benchmark guide](../../README.md), and build the candidate with
`cargo build --release --locked`. The public 0.1.3 release asset is the baseline.

```sh
python3 bench/results/v7/measure.py --before /absolute/path/to/keyspoor-0.1.3 \
  --after /absolute/path/to/keyspoor-0.1.4 --sources /absolute/path/to/sources.json \
  --corpus /absolute/path/to/corpus-final --pairs 20 --output /tmp/fresh-paired.json
```

Extract the quality manifest from `quality[0].tools` into `{"schema_version":1,
"tools":[...]}`, updating absolute executable/cwd paths for your machine. From
the source-corpus repository directory, run the current `bench/run.py` with
`--manifest <manifest> --corpus <corpus> --datasets quality --corpus-role regression
--repeats 3 --timeout 60 --output <fresh-path>` once for each of the three corpora.
The raw quality records retain corpus/worktree hashes and scoring labels.
No recorded raw output, match text, source snippet or credential value is
published; report hashes refer to privately captured redacted scanner outputs.

## Behavior and baseline impact

No provider SDK, new configuration or directory-wide suppression is added.
The generic API rule requires a credential term at the end of the field and
exempts the specific `topic_key` metadata field. Comma syntax is accepted for
quoted tuples, and the two affected contextual rules reject a captured next
JSON property name. Only the unquoted generic assignment rule excludes
`config.<identifier>` references: quoted values and other dotted literals remain
findings. Provider-format detection still catches tokens inside metadata fields.
These are bounded heuristics, not a language parser or a proof of no leaks.

Engine configuration identity moves to v4 because contextual matching semantics
change. Existing baselines are rejected rather than compared silently; review
findings again and create a new baseline file. `--write-baseline` also refuses
to overwrite a file with a mismatched identity. CLI exits 0/1/2 and incomplete-scan
behavior are unchanged. The imported catalog remains reproducible through
`python3 scripts/import_rules.py --check`.
