# Reproducible synthetic scan corpus

```sh
python3 bench/fixtures/generate.py --self-test
python3 bench/fixtures/generate.py --output bench/generated --sizes 1,16,128
```

Python standard library and Git are the only requirements. The output directory must be empty. Use `--no-git` to omit Git scenarios and `--sizes ''` to omit throughput inputs. Generated files are disposable benchmark inputs; keep them out of source control and never use remote credential validation on them.

Every candidate is fabricated from a fixed PRNG seed. A positive label means a **secret-shaped candidate in a controlled example**, not a known active credential. Synthetic format tests do not establish production recall or precision. Provider families were selected independently of the implementation being evaluated; the generator does not import scanner code or read scanner rules. Tokens within a provider are intentionally reused across the three presentation variants, so metrics must count locations rather than deduplicated secret values.

## Datasets

| Dataset | Content | Intended measurement |
| --- | --- | --- |
| `quality` / `common` | 9 provider families × quoted, Unicode prefix, and CRLF variants | Static provider-format recall, separately by provider |
| `quality` / `generic` | 7 cases: password assignment, JSON, YAML, multiline assignment, Unicode value, unquoted environment file, URI password | Context-dependent candidate recall; reported separately from providers |
| `quality` / `negative` | 10 benign regions: placeholders, redaction, environment references, checksum, UUID, color, public-key envelope, URL, example password | False positives and case-level specificity |
| `capabilities` | Base64, UTF-16LE, 64 KiB read boundary, NUL prefix, no trailing newline, PEM private-key envelope, ZIP and tar.gz | Individual capability probes, excluded from basic plaintext recall |
| `throughput-Nmib` | Exact N MiB, 256 KiB files, sparse GitHub-shaped candidates | End-to-end throughput with a recall sanity check |
| `git_history` | Three fixed-date commits, candidate added then removed from HEAD | Deleted historical-secret detection |
| `staged` | Index contains one candidate while worktree contains a different one | Scan index rather than current file contents |
| `git_worktree` | Worktree-only candidate replacing the staged candidate | Distinguish working tree and staged data |

Provider families are AWS access-key IDs, classic GitHub PATs, GitLab PATs, Slack bot tokens, Stripe secret keys, Google API keys, SendGrid API keys, npm tokens, and Twilio API-key IDs. This is a deliberately small common-format subset, not the full set of providers supported by any product. API-key identifiers may need a paired secret for authentication; they remain format-detection probes. The PEM data has an appropriate envelope and random body, not a valid cryptographic private key; it measures envelope recognition only.

Throughput text is deliberately repetitive, source-like, UTF-8 plaintext with one injected candidate per MiB. It is useful for reproducible scanning and allocation comparisons, but cannot represent real repositories, binary-heavy inputs, compression behavior, or network sources. Collect additional diverse real-world public corpora before broad performance claims. Distinguish process startup, steady-state scanning, cache state, peak RSS, and decoded bytes when interpreting results.

## Manifest protocol

`manifest.json` is outside every scan dataset. Schema version 1 includes `datasets` and `entries`. Dataset paths and entry paths are relative to the corpus root. Each entry contains:

- `id`, `dataset`, `path`, `provider`, `group`, `class`, `case`, and `purpose`.
- `label`: `positive` or `negative`.
- `start`, `end`: half-open **byte** offsets into the original file bytes, not Unicode character indices.
- `line`, `end_line`: one-based line numbers computed from LF bytes; CRLF is one newline.
- `sha256`: hash of the exact labeled byte region, for self-validation without duplicating the candidate in the manifest.
- Optional `revision`: committed Git revision, or `:index` for staged contents. Offsets refer to that revision's bytes, not HEAD or the current file.

For archive member expectations, `datasets.capabilities.archives` lists `path`, `member`, `provider`, and `candidate_sha256`. These are separate from file spans because a decoded member's location is not an offset into the compressed archive. For Base64 the labeled region is the encoded payload; for UTF-16 the region contains UTF-16 bytes. A scanner may report a decoded location or decoded hash; a capability-specific adapter is required for those cases.

Negative labels identify controlled benign regions, not the entire universe of possible false positives. Count every unmatched finding as a false positive when evaluating the complete labeled plaintext quality corpus. If a tool only reports a line, use line-level matching and label that metric separately; do not imply byte-span agreement. Generic detectors may include assignment context in their reported match; prefer overlap with the labeled candidate to requiring equal start/end offsets, while retaining exact-span results when available.

`--self-test` generates two isolated corpora, checks deterministic manifests and all non-Git file bytes, validates every span/hash/line against original, historical, or staged bytes, compares archive payloads, checks exact throughput size, and ensures nonempty output directories are rejected. Git commit identities, timestamps, and branch names are fixed, signing and hooks are disabled, and user/global Git configuration is ignored during generation.
