# Built-in rule provenance and import boundaries

The scanner implementation is our Rust code. The built-in catalogue is **third-party rule data**, transformed from Gitleaks; there is no Gitleaks, Kingfisher, or other scanner SDK dependency. Reusing a detector's patterns does not establish parity with that detector's complete runtime.

## Pinned source

| Item | Value |
| --- | --- |
| Project | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| Release | `v8.30.1` |
| Commit | `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` |
| Configuration | [config/gitleaks.toml](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/config/gitleaks.toml) |
| Configuration SHA-256 | `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf` |
| License | [MIT, Copyright (c) 2019 Zachary Rice](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/LICENSE) |
| License SHA-256 | `e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6` |
| Upstream rules | 222 |
| Imported rules | 217 |
| Explicit exclusions | 5 |
| Additional independently written rules | 4 (3 generic assignments, 1 URI password) |
| Total default runtime rules | 221 |

The full upstream MIT notice is retained in `THIRD_PARTY_NOTICES`. The importer reads only these pinned source bytes and never inspects benchmark fixtures, scores, or scanner findings. The release tag was resolved to the commit above through GitHub's Git reference API; regeneration fetches by commit, not by mutable branch or tag.

## Transformations

- Preserve rule IDs, descriptions, regexes, keyword gates, entropy thresholds, and positive path constraints.
- Escape unescaped Go literal braces where Rust's regex parser requires escaping. Quantifiers retain their original meaning.
- Map explicit `secretGroup` to `secret_group`. Without an explicit group, choose capture 1 when present and whole match otherwise. The two rules whose alternatives require first-nonempty capture selection are excluded below; nested captures in remaining rules retain their original first-capture behavior.
- Merge the upstream global secret allowlist into each rule, including the two case-insensitive substring stopwords, which become escaped substring regexes. Preserve rule-specific secret regex allowlists. These are OR conditions.
- Preserve all 25 global path exclusions and rule-specific path exclusions through `exclude_paths`. These filters are distinct from a rule's required `path` match.
- Mark every imported rule `medium` confidence. This is our neutral output classification, not an upstream confidence score or empirical precision estimate.

Runtime expectations are based on upstream [capture and entropy handling](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/detect/detect.go) and [allowlist behavior](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/config/allowlist.go). Keywords are case-insensitive candidate gates. Nonzero entropy requires **strictly greater** entropy than the threshold. Zero disables the entropy gate. Stopwords match substrings of the extracted secret, not of the entire source line.

The Rust byte-regex engine uses ASCII character classes and boundaries (`unicode(false)`), preserving Go's ASCII `\w`, `\d`, `\s`, and `\b` behavior for ASCII credentials. This is not a proof of complete Go/Rust regular-expression equivalence: Unicode case folding under `(?i)` can differ, and this catalogue has not undergone exhaustive differential testing of every pattern. Path regexes are evaluated on the reported path. Rule parsing/compilation and fixture tests establish only the behaviors actually tested.

Scanner-level behavior such as Gitleaks inline suppression comments, Git selection, decoding, extraction, limits, and reporting is separate from rule data and must be evaluated independently. No claim of full Gitleaks feature equivalence follows from the count of imported rules.

## Rules deliberately excluded

| Upstream rule ID | Reason |
| --- | --- |
| `atlassian-api-token` | Alternatives require selecting the first nonempty capture; the current schema has a fixed capture index. |
| `curl-auth-header` | Eight alternative capture groups require first-nonempty capture selection. |
| `generic-api-key` | Allowlists target the full match and source line, include stopwords, and combine path/line constraints with AND. A secret-only OR allowlist cannot preserve the behavior. |
| `kubernetes-secret-yaml` | Full-match allowlist and alternative capture selection are unsupported by the current rule schema. |
| `pkcs12-file` | A path-only finding has no content regex or secret byte span. |

No excluded rule is silently reintroduced with weaker filtering. The pinned source contains no compound `required` rule definitions. The importer rejects unknown rule/allowlist fields rather than silently dropping constraints; an upstream update requires revisiting the pinned hashes and these transformation boundaries.

## Reproduce

Requires Python 3.11+ (`tomllib`). From the repository root:

```sh
python3 scripts/import_rules.py
python3 scripts/import_rules.py --check
```

For offline regeneration, place the pinned configuration at `config_gitleaks.toml` and the license at `LICENSE` in one directory, then pass `--source-dir /path/to/directory`. Both inputs are hash-checked before transformation. `--check` verifies the checked-in JSON and third-party notice byte-for-byte; it does not run a scanner or tune rules from benchmark results.
