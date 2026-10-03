# Reproducible offline benchmark

`run.py` compares installed tools with their default rule sets. It measures complete CLI invocations, so it includes startup, rule compilation, traversal and serialization. These results do not isolate regex engine speed. Cloud-only engines without credentials and rule databases remain `unavailable` or `not_applicable`; they never receive a zero score.

```sh
python3 -m unittest discover -s bench -p test_run.py
python3 bench/run.py --corpus /absolute/path/to/generated-corpus --repeats 3 --output bench/results/v2/latest.json
```

Run the measured suite only after builds/installations and other concurrent agents have stopped CPU-heavy work. The runner executes tools sequentially. Every tool/dataset receives a first new-process measurement, an explicit unmeasured-in-summary warmup and repeated new processes with warm filesystem caches. **`cold_process` does not mean cold disk or a purged OS cache.** Records include wall time, process CPU time, peak RSS, exit status, completion state, version/installation metadata, command, hardware and manifest hashes. RSS uses child `getrusage`: Darwin returns bytes, Linux KiB. For tools that start children it is not a simultaneous aggregate process-tree peak. No monetary or energy estimate is inferred from time alone.

Tool output is captured privately in temporary files, parsed and removed. Schema v2 reports retain each run’s `normalized_findings`, output byte counts/hashes, scanner statistics and completion state. These evidence records include only path, rule ID, source coordinates and revision; they omit raw values, snippets, match text, messages and stderr. Quality results add the per-finding classification and matched label ID. Evidence remains available for partial/failed scans, which receive no aggregate quality or throughput score. Only an allowlist of ordinary process environment variables is inherited; online credential verification must be disabled by each tool's confirmed command (`offline: true`). This is not an OS-level network sandbox.

## Tool manifest

`bench/tools/manifest.json` has a `tools` array. Installed tools use:

```json
{
  "id": "secret-scan",
  "status": "available",
  "version": "0.1.0",
  "source_url": "local",
  "commit_or_digest": "sha256-of-binary",
  "offline": true,
  "parser": "secret_scan",
  "accepted_exit_codes": [0, 1],
  "commands": {
    "fs": ["/absolute/path/secret-scan", "scan", "{input}", "--format", "json"]
  }
}
```

Modes are `fs`, `git` and `staged`. Missing mode commands are explicitly `unsupported`. Templates support `{input}`, `{repo}`, `{root}` (corpus root) and `{output}` (private report path). JSON report files take precedence over stdout when a tool uses `{output}`. A `cwd` and explicit noncredential `env` map can be supplied. Supported parsers are `secret_scan`, `normalized`, `gitleaks`, `betterleaks`, `detect_secrets`, `trufflehog`, `secretlint`, `sarif`, `ripsecrets`, `whispers` and `git_secrets`. Additional tool formats require an actual adapter, not a guessed empty result.

## Corpus and correctness

A generated corpus has `manifest.json` with `entries` and `datasets`. Entries carry `id`, `path` relative to corpus, half-open UTF-8 byte offsets `start/end`, `label: positive|negative`, `provider`, `group`, optional `line`, optional `revision`, and `dataset` (defaults to `quality`). Datasets map names to `{path, mode, bytes?}`. By default every declared dataset is run, including `quality`, `capabilities`, size-specific `throughput-*`, `git_history`, `staged` and `git_worktree`; `--datasets` selects a subset.

Ground truth is matched **one-to-one by file and location**, not by result counts or differing rule names. Exact byte ranges are preferred. A range overlapping at least half the labelled secret and at most four times its width can count as an overlapping span only if it identifies one label. A line-only finding can match only when exactly one positive or negative label occupies that line; two candidates on the same line are not resolved by guessing or by counting repeated outputs. Revision is checked when both sides supply it. Columns in tool-specific character units are retained as metadata and are not guessed to be UTF-8 byte offsets.

Scoring v2 separates `unlocalized` from false positives and duplicates. Missing/invalid coordinates, coordinates outside known filesystem input bounds, ambiguous lines/windows and non-source coordinate spaces are unlocalized. Invalid coordinate payloads are not copied to output. Duplicate locations or multiple detections of the same labelled occurrence are counted separately, including duplicate negative detections. Unresolved negative labels do not count as true negatives. **Precision is conditional on localized unique findings; recall is a confirmed-location lower bound.** An unlocalized output proves neither a correct detection nor a false positive. Reports show unlocalized counts and localization rate alongside the quality metrics.

Missed label IDs, per-provider/per-group recall and sanitized per-finding evidence remain in JSON. Synthetic precision is not a population estimate of real-world false positives, and no live credential validity is tested. Filesystem location bounds are checked against corpus bytes/lines; Git/index positions do not use the current working-tree size as a false bound for historical content.

Failed, timed-out and incomplete scans receive **no accuracy or throughput score**. Required JSON outputs must exist and conform to the expected top-level shape; only explicitly streaming/text parsers accept empty clean output. Secretlint file-result arrays expose its scanned file count; `[]` on nonempty input is incomplete. Its adapter requires `--no-gitignore` for these generated corpora, whose parent repository ignores generated artifacts. An accepted process exit code alone is insufficient: the output parser must succeed and the result must be complete. The first-run quality result is used; normalized location hashes must agree across repetitions, otherwise the row is marked `nondeterministic` and excluded from scored summaries. A scanner with only line output is not claimed to have byte-accurate localization.

## Real-source corpus

`prepare_real.py` adds a public source archive to a generated corpus, resolves the requested reference to a fixed commit, records source URL, archive SHA-256 and byte count, and marks it explicitly unlabelled. The measured report retains these dataset metadata. For example:

```sh
python3 bench/prepare_real.py --corpus bench/corpus-final --repository rust-lang/regex --ref 72d650cb0a880a01ab6dc2137c0888e8f89740f7
```

No precision, recall or false-positive conclusion is computed on this source tree. Git/staged reports omit MiB/s because the working-directory size is not a valid denominator for history or index scanning.

The Git fixture places index and unstaged working-tree candidates on different lines, so redacted outputs can prove which content was scanned. Historical scanners that also scan index/worktree objects report those known-positive locations as `extra_scope_findings`, separately from false positives. Extra results from the working tree in a staged-only command remain a scope violation. Archive probes separately report archive/member location evidence; they are not folded into byte-span precision when the output lacks decoded offsets. Kingfisher uses its documented `--no-dedup` option so all occurrences, rather than nondeterministic representatives, can be compared.

Historical regression-corpus limitation: three AWS-labelled synthetic candidates contain `9` in their suffix, outside the imported Gitleaks AWS-specific `[A-Z2-7]` format. These labels are broad configuration candidates, not validated AWS credential formats or live credentials. They remain in the corpus and missed-label lists; candidate-label P/R must not be described as real AWS credential recall. Later scanner changes used these observations, so final synthetic comparisons are explicitly regression results, not a holdout benchmark.

## Schema v2 and preserved history

`run.py` now writes `schema_version: 2` and `method.scoring_version: 2`. Its default destination is `results/v2/latest.json`; both the runner and merger refuse to overwrite an existing JSON or Markdown artifact. Choose a fresh path for a rerun. Historical `results/final.json`, its source artifacts and their schema-v1 scoring remain unchanged; they must not be silently reinterpreted as v2 scores.

The merger accepts only v2 artifacts with the same corpus manifest hash and evaluation role. It rejects mixed binary hashes for a tool across retained datasets. Regression and holdout tables stay separate even if both datasets are named `quality`.

```sh
python3 bench/merge_results.py bench/results/v2/regression.json bench/results/v2/performance.json --output bench/results/v2/regression-table.json
python3 bench/merge_results.py bench/results/v2/holdout.json --output bench/results/v2/holdout-table.json
```

A holdout run uses `--corpus-role holdout`. This records the declared evaluation role; it cannot prove that development never inspected the samples. Freeze the engine and corpus before the first run, keep the holdout unavailable to implementation agents until then, and move samples used to guide a fix into future regression testing.
## Reproduce on this machine

Run from the project root after building the release binary and restoring tools with the instructions in `tools/README.md`. Use a new, empty corpus directory; the fixture generator deliberately refuses to overwrite an existing corpus. The pinned real-source download is unlabelled.

```sh
python3 bench/fixtures/generate.py --output bench/corpus-reproduce --sizes 1,16,128
python3 bench/prepare_real.py --corpus bench/corpus-reproduce --repository rust-lang/regex --ref 72d650cb0a880a01ab6dc2137c0888e8f89740f7
python3 bench/run.py --manifest bench/run-manifest-v2.json --corpus bench/corpus-reproduce --corpus-role regression --datasets quality,capabilities,throughput-1mib,throughput-16mib,git_history,staged,real-regex --repeats 3 --timeout 60 --output bench/results/v2/reproduced-main.json
python3 bench/run.py --manifest bench/run-manifest-v2.json --corpus bench/corpus-reproduce --corpus-role regression --datasets throughput-128mib --tools secret-scan,gitleaks,kingfisher,betterleaks,titus,trivy,keyhog,secretlint,rusty-hog,credential-digger,scratch-scanner-rs --repeats 3 --timeout 60 --output bench/results/v2/reproduced-128mib.json
python3 bench/merge_results.py bench/results/v2/reproduced-main.json bench/results/v2/reproduced-128mib.json --output bench/results/v2/reproduced-final.json
```

`run-manifest-v2.json` must freeze the current local scanner binary digest before a v2 run; the canonical `tools/manifest.json` contains only the 22 comparison projects. Tool executable, configuration, wrapper and rule paths in frozen manifests are absolute paths on the measured machine. Relocate these paths when using another checkout/machine, restore matching dependencies and rebuild local binaries; do not reuse the old version/digest fields after changing an executable. Old `run-manifest.json` and `results/runner-first-batch.py` preserve the initial experiment, while `results/final.json` preserves the original corrected schema-v1 measurements. That historical table has 20 actually launched scanners, including the local implementation; Talisman supplies file-level Git/index evidence only.

## Scheduled v2 evaluation scope

Completed v2 tables are [regression and six-tool performance](results/v2/regression-current.md) and [independent synthetic holdout](results/v2/holdout-current.md), with adjacent JSON retaining every run and sanitized location evidence. They include 19 actually launched filesystem scanners; Talisman has no confirmed filesystem adapter, and three inventory projects remain unavailable or non-executable. The final local binary is frozen in `run-manifest-v2-final.json` at SHA-256 `9c6c2052d33d7479ae9ce998e0565e9faa9daf617826ed9b4cb1f1624872e85d`.

The first all-tool run remains in `regression.json`, `holdout.json` and `performance.json`. A subsequent local-only rerun replaced all five local datasets after Git-root/baseline-scope fixes; the scan engine and rules stayed frozen. The `*-ours-final.json` artifacts preserve that rerun, and the current tables contain only its local binary hash. Synthetic holdout results remain candidate-label results: 599/600 confirmed positive locations and 25/300 flagged negative labels for the local implementation, plus 421 duplicate findings recorded separately. This is not a natural-code false-positive rate or live-credential validation.

Only start these commands after the release binary and manifest are frozen and compilation/installation work is stopped. The first two commands evaluate every tool with a confirmed filesystem adapter; unsupported modes remain explicit. The six-tool performance comparison uses the existing corpus, separately from the held-out quality table. These paths are intentionally new and must not already exist.

```sh
python3 bench/run.py --manifest bench/run-manifest-v2.json --corpus bench/corpus-final --datasets quality --corpus-role regression --repeats 3 --timeout 60 --output bench/results/v2/regression.json
python3 bench/run.py --manifest bench/run-manifest-v2.json --corpus bench/corpus-holdout --datasets quality --corpus-role holdout --repeats 3 --timeout 60 --output bench/results/v2/holdout.json
python3 bench/run.py --manifest bench/run-manifest-v2.json --corpus bench/corpus-final --datasets throughput-16mib,throughput-128mib,real-regex --tools secret-scan,gitleaks,betterleaks,trivy,kingfisher,scratch-scanner-rs --corpus-role regression --repeats 3 --timeout 60 --output bench/results/v2/performance.json
```

To reproduce the current binary, use `run-manifest-v2-final.json` and new output paths. The current tables were assembled without rewriting either earlier v2 artifacts or historical v1 results:

```sh
python3 bench/merge_results.py bench/results/v2/regression.json bench/results/v2/performance.json bench/results/v2/regression-ours-final.json bench/results/v2/performance-ours-final.json --output bench/results/v2/regression-current.json
python3 bench/merge_results.py bench/results/v2/holdout.json bench/results/v2/holdout-ours-final.json --output bench/results/v2/holdout-current.json
```
