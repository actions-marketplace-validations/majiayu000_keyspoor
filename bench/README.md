# Reproducible offline benchmark

`run.py` compares installed tools with their default rule sets. It measures complete CLI invocations, so it includes startup, rule compilation, traversal and serialization. These results do not isolate regex engine speed. Cloud-only engines without credentials and rule databases remain `unavailable` or `not_applicable`; they never receive a zero score.

```sh
python3 -m unittest discover -s bench -p test_run.py
python3 bench/run.py --corpus /absolute/path/to/generated-corpus --repeats 3 --output bench/results/latest.json
```

Run the measured suite only after builds/installations and other concurrent agents have stopped CPU-heavy work. The runner executes tools sequentially. Every tool/dataset receives a first new-process measurement, an explicit unmeasured-in-summary warmup and repeated new processes with warm filesystem caches. **`cold_process` does not mean cold disk or a purged OS cache.** Records include wall time, process CPU time, peak RSS, exit status, completion state, version/installation metadata, command, hardware and manifest hashes. RSS uses child `getrusage`: Darwin returns bytes, Linux KiB. For tools that start children it is not a simultaneous aggregate process-tree peak. No monetary or energy estimate is inferred from time alone.

Tool output is captured privately in temporary files, parsed and removed. Reports retain output byte counts/hashes and normalized location metadata, never raw findings or stderr. Only an allowlist of ordinary process environment variables is inherited; online credential verification must be disabled by each tool's confirmed command (`offline: true`). This is not an OS-level network sandbox.

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

Ground truth is matched **one-to-one by file and location**, not by result counts or differing rule names. Exact byte ranges are preferred. A range overlapping at least half the labelled secret and at most four times its width counts as an overlapping span. If a tool only exposes a line, it is matched by line with that weaker precision explicitly recorded. Revision is checked when both sides supply it. Different detectors reporting one labelled occurrence count as duplicates and do not inflate recall; unmatched findings are false positives within this fully labelled synthetic suite. Missed label IDs and per-provider/per-group recall remain in JSON. Synthetic precision is not a population estimate of real-world false positives, and no live credential validity is tested.

Failed, timed-out and incomplete scans receive **no accuracy or throughput score**. Required JSON outputs must exist and conform to the expected top-level shape; only explicitly streaming/text parsers accept empty clean output. Secretlint file-result arrays expose its scanned file count; `[]` on nonempty input is incomplete. Its adapter requires `--no-gitignore` for these generated corpora, whose parent repository ignores generated artifacts. An accepted process exit code alone is insufficient: the output parser must succeed and the result must be complete. The first-run quality result is used; normalized location hashes must agree across repetitions, otherwise the row is marked `nondeterministic` and excluded from scored summaries. A scanner with only line output is not claimed to have byte-accurate localization.

## Real-source corpus

`prepare_real.py` adds a public source archive to a generated corpus, resolves the requested reference to a fixed commit, records source URL, archive SHA-256 and byte count, and marks it explicitly unlabelled. The measured report retains these dataset metadata. For example:

```sh
python3 bench/prepare_real.py --corpus bench/corpus-final --repository rust-lang/regex --ref 72d650cb0a880a01ab6dc2137c0888e8f89740f7
```

No precision, recall or false-positive conclusion is computed on this source tree. Git/staged reports omit MiB/s because the working-directory size is not a valid denominator for history or index scanning.

The Git fixture places index and unstaged working-tree candidates on different lines, so redacted outputs can prove which content was scanned. Historical scanners that also scan index/worktree objects report those known-positive locations as `extra_scope_findings`, separately from false positives. Extra results from the working tree in a staged-only command remain a scope violation. Archive probes separately report archive/member location evidence; they are not folded into byte-span precision when the output lacks decoded offsets. Kingfisher uses its documented `--no-dedup` option so all occurrences, rather than nondeterministic representatives, can be compared.

Corpus limitation: three AWS-labelled synthetic candidates contain `9` in their suffix, outside the imported Gitleaks AWS-specific `[A-Z2-7]` format. These labels are broad configuration candidates, not validated AWS credential formats or live credentials. They remain in the corpus and missed-label lists; candidate-label P/R must not be described as real AWS credential recall. Later scanner changes used these observations, so final synthetic comparisons are explicitly regression results, not a holdout benchmark.

To make a current table from measured artifacts, pass them oldest to newest. The merger retains each source artifact, supersedes only the same tool/dataset, and rejects a tool whose retained datasets mix binary hashes. The first-batch artifact stays intact as a baseline.

```sh
python3 bench/merge_results.py bench/results/benchmark.json bench/results/benchmark-128mib.json bench/results/benchmark-final.json --output bench/results/final.json
```

## Reproduce on this machine

Run from the project root after building the release binary and restoring tools with the instructions in `tools/README.md`. Use a new, empty corpus directory; the fixture generator deliberately refuses to overwrite an existing corpus. The pinned real-source download is unlabelled.

```sh
python3 bench/fixtures/generate.py --output bench/corpus-reproduce --sizes 1,16,128
python3 bench/prepare_real.py --corpus bench/corpus-reproduce --repository rust-lang/regex --ref 72d650cb0a880a01ab6dc2137c0888e8f89740f7
python3 bench/run.py --manifest bench/run-manifest-final.json --corpus bench/corpus-reproduce --corpus-role regression --datasets quality,capabilities,throughput-1mib,throughput-16mib,git_history,staged,real-regex --repeats 3 --timeout 60 --output bench/results/reproduced-main.json
python3 bench/run.py --manifest bench/run-manifest-final.json --corpus bench/corpus-reproduce --corpus-role regression --datasets throughput-128mib --tools secret-scan,gitleaks,kingfisher,betterleaks,titus,trivy,keyhog,secretlint,rusty-hog,credential-digger,scratch-scanner-rs --repeats 3 --timeout 60 --output bench/results/reproduced-128mib.json
python3 bench/merge_results.py bench/results/reproduced-main.json bench/results/reproduced-128mib.json --output bench/results/reproduced-final.json
```

`run-manifest-final.json` includes the local scanner; the canonical `tools/manifest.json` contains only the 22 comparison projects. Tool executable, configuration, wrapper and rule paths in frozen manifests are absolute paths on the measured machine. Relocate these paths when using another checkout/machine, restore matching dependencies and rebuild local binaries; do not reuse the old version/digest fields after changing an executable. Old `run-manifest.json` and `results/runner-first-batch.py` preserve the initial experiment, while `results/final.json` merges the corrected measurements without mixing local scanner binary hashes. The current table has 20 actually launched scanners, including the local implementation; Talisman supplies file-level Git/index evidence only.
