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
| Imported rules | 221 |
| Explicit exclusions | 1 |
| Additional independently written rules | 4 (3 generic assignments, 1 URI password) |
| Total default runtime rules | 225 |

The full upstream MIT notice is retained in `THIRD_PARTY_NOTICES`. The importer reads only these pinned source bytes and never inspects benchmark fixtures, scores, or scanner findings. The release tag was resolved to the commit above through GitHub's Git reference API; regeneration fetches by commit, not by mutable branch or tag.

## Transformations

- Preserve rule IDs, descriptions, regexes, entropy thresholds, and positive path constraints. Preserve keyword gates except for the documented correction below.
- For `airtable-personnal-access-token` (upstream spelling retained), replace the contextual keyword `airtable` with the required token prefix `pat`. The regex accepts standalone `pat`-prefixed tokens without the provider name; requiring that name suppresses valid matches. This local adaptation changes candidate selection only, retaining the token format, captures and allowlists. The importer applies it during regeneration. Regression tests cover standalone and adjacent tokens, hexadecimal content containing a generic stopword, and malformed near-matches; this is not an audit of every rule's keyword gate.
- Escape unescaped Go literal braces where Rust's regex parser requires escaping. Quantifiers retain their original meaning.
- Map a positive explicit `secretGroup` to `secret_group`. An omitted or zero upstream value becomes `null`: select the first nonempty capture and fall back to the whole match if none exists. This preserves alternative-branch captures in the Atlassian and curl-header rules. Explicit `0` in our custom schema means whole match and is therefore different from upstream zero.
- Keep each upstream allowlist as an independent structured group. Groups are ORed. Within a group, each nonempty category (`regexes`, `paths`, `stopwords`) matches any item, then category results are combined according to `condition: "or"` or `"and"`. Absent categories do not participate. Preserve each regex target as `secret`, `match`, or `line`; stopwords always match the extracted secret as case-insensitive substrings, regardless of regex target.
- Include the upstream global allowlist as the first group of every imported rule, retaining its 25 path exclusions, secret regexes, and two stopwords. Preserve rule-specific groups separately. Path exclusions remain distinct from a rule's required `path` match; imported rules have empty standalone `exclude_paths` because those constraints are already carried by allowlist groups.
- Mark every imported rule `medium` confidence. This is our neutral output classification, not an upstream confidence score or empirical precision estimate.

Runtime expectations are based on upstream [capture and entropy handling](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/detect/detect.go) and [allowlist behavior](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/config/allowlist.go). Keywords are case-insensitive candidate gates. Nonzero entropy requires **strictly greater** entropy than the threshold. Zero disables the entropy gate. Stopwords match substrings of the extracted secret, not of the entire source line.

The Rust byte-regex engine uses ASCII character classes and boundaries (`unicode(false)`) for credential content. This is not a proof of complete Go/Rust regular-expression equivalence: Unicode case folding under `(?i)`, byte-versus-character matching, and whitespace classes at uncommon control characters can differ. This catalogue has not undergone exhaustive differential testing of every pattern. Path regexes are evaluated on the reported path. Rule parsing/compilation and fixture tests establish only the behaviors actually tested.

Scanner-level behavior such as Gitleaks inline suppression comments, Git selection, decoding, extraction, limits, and reporting is separate from rule data and must be evaluated independently. No claim of full Gitleaks feature equivalence follows from the count of imported rules.

## Rules deliberately excluded

| Upstream rule ID | Reason |
| --- | --- |
| `pkcs12-file` | A path-only finding has no content regex or secret byte span. |

The content catalogue includes `atlassian-api-token`, `curl-auth-header`, `generic-api-key`, and `kubernetes-secret-yaml` with their upstream capture-selection and allowlist constraints. The generic rule retains full-match and line targets, its stopword list, and its AND-combined path/line group. The Kubernetes rule retains its upstream full-match exclusion for matches spanning separate YAML documents. That expression requires content between the document separator and `data:`; a `data:` line immediately after `---` is not guaranteed to be suppressed. We preserve this upstream limitation rather than claim full YAML document semantics.

The pinned source contains no compound `required` rule definitions. The importer rejects unknown rule/allowlist fields, conditions, and targets rather than silently dropping constraints; an upstream update requires revisiting the pinned hashes and these transformation boundaries.

## Reproduce

Requires Python 3.11+ (`tomllib`). From the repository root:

```sh
python3 scripts/import_rules.py
python3 scripts/import_rules.py --check
```

For offline regeneration, place the pinned configuration at `config_gitleaks.toml` and the license at `LICENSE` in one directory, then pass `--source-dir /path/to/directory`. Both inputs are hash-checked before transformation. `--check` verifies the checked-in JSON and third-party notice byte-for-byte; it does not run a scanner or tune rules from benchmark results.
