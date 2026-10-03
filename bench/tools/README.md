# Benchmark tool installation record

`manifest.json` is the canonical current inventory for 22 projects: 20 scanners, ggshield's cloud-backed CLI, and a non-executable rule database. `manifest.pending.json` preserves the final recovery deltas. Availability means the tool starts and an adapter command exists; actual benchmark success is established only by `bench/results/`.

All tools, environments, source checkouts and native dependencies are local to this directory. No global package installation was performed. Preserve the small scripts, JSON metadata, help transcripts and lock files in Git; binaries, source trees, virtual environments and node_modules remain ignored.

## Reproduction

Run `python3 bench/tools/restore_tools.py TOOL_ID ...` to restore specific tools from the canonical manifest. The script uses exact release asset URLs and SHA-256 digests, source commits, package locks and two Cargo build jobs. It does not run scans. Python 3.12, uv, npm, Git and a Rust/C toolchain are prerequisites. The recorded commands contain installation-specific absolute paths; if relocating the workspace, regenerate those prefixes before running the benchmark. The restore script itself resolves all installation paths relative to its own directory.

- Python tools: `python-requirements.lock`.
- Credential Digger: `credentialdigger-requirements.lock`, including Transformers 4.57.6 and setuptools 80.10.2 required to resolve the observed import failures.
- Secretlint: `npm-package.json` and `npm-package-lock.json` preserve all versions and integrity digests.
- Rusty Hog: `rusty-hog-Cargo.lock`; the pinned source had no lock file, so the successful build's generated lock is preserved.
- KeyHog: pinned source commit and its checked-in Cargo.lock, default portable release features.
- scratch-scanner-rs: pinned source commit/Cargo.lock, contemporaneous pinned Gossip-rs sibling, and Boost 1.88.0 headers downloaded and SHA-256 checked under `source/`. The current Gossip HEAD had incompatible Vectorscan linkage; the matching historical commit built successfully without modifying upstream code.

`install_releases.py` and `configure_manifest.py` record the initial acquisition process. They are not the reproduction entry points: they originally asked for latest releases and do not recreate the subsequently reviewed inventory. Use `restore_tools.py` and the final pinned manifest instead.

## Offline behavior and adapter boundaries

Offline scan commands disable live verification and update checks where supported. Titus accessibility is private to avoid its automatic remote visibility lookup. KeyHog uses an explicit CPU backend and no verification. Credential Digger uses its official bundled rules, no ML models or similarity processing, and a fresh in-memory SQLite database. This run makes no claims about its ML false-positive reduction.

git-secrets uses upstream AWS rules in a temporary isolated Git config. Its local-credential provider is removed to avoid reading user AWS credentials. Nosey Parker gets a fresh datastore for each invocation; scan and SARIF report generation are included in measured cost. Kingfisher's `--no-dedup` preserves occurrences for location scoring. Its code 200 means unvalidated findings, as verified against the pinned source; validated-finding code 205 is not accepted in this offline benchmark.

Talisman runs in native Git-history and staged pre-commit modes. Its output has file-level locations without structured lines. The adapter deliberately omits line numbers; file-level results must not be mixed with occurrence-level quality scores or used to infer which version of a same-named file was detected.

Rusty Hog's original release binary failed because OpenSSL 1.1 was absent. The pinned source now builds successfully against this host without source changes. Its adapter requires valid JSON even when native exit code is zero, since upstream can log an error and still return zero.

## Remaining unavailable cases

- Deepfence SecretScanner: cloned its YaraHunter sibling and initialized both required submodules, then retried the build. Go compilation failed because pkg-config could not find YARA. Official YARA 4.5.8 source was downloaded locally; it provides configure.ac without a generated configure script. The latest five official releases exposed no downloadable release assets. Local bootstrap actually failed with `autoreconf: command not found`. We did not bootstrap a complete autotools stack or alter upstream code. The manifest retains exact source/native references and the observed errors.
- ggshield requires an authenticated external detection service; no cloud scan was attempted.
- Secrets Patterns DB is a rule asset, not an executable engine.
