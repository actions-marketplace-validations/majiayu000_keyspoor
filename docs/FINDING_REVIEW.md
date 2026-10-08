# Review of the three public repository scans

Reviewed on 2026-10-08 (Asia/Shanghai), using the published native **Keyspoor
0.1.3** executable. Repeated scans reproduced **119 findings**, zero errors and
`complete=true`: remem 73, argus 46, rclean 0. The exact snapshots and timing
methodology are in [ADOPTION.md](ADOPTION.md#real-repository-trial).

This is a manual context review of reported spans, not an estimate of production
precision or recall. It has no independent census of missed secrets. Public
repositories, tests and evaluation corpora are not representative deployment
samples. No credential-provider requests, authentication tests or revocations
were performed. This document publishes locations and reasoning, never matched
values or source snippets. Byte ranges are half-open source-byte offsets.

## Results

| Snapshot | Confirmed non-secret | Intentional test fixture | Evaluation artifact | Unresolved | Total |
|---|---:|---:|---:|---:|---:|
| remem | 40 | 30 | 0 | 3 | 73 |
| argus | 16 | 4 | 24 | 2 | 46 |
| rclean | 0 | 0 | 0 | 0 | 0 |
| **Total** | **56** | **34** | **24** | **5** | **119** |

- **Confirmed non-secret** means the matched span has an established non-credential
  role: prose, metadata, a property name, a version constant or an unquoted
  Python identifier in an expression. These are detection false positives for
  this workload. Classification uses the parsed record or source expression,
  rather than a test/eval path alone.
- **Intentional test fixture** means code deliberately exercises a scanner,
  redactor, URI parser or certificate verifier. Matching a credential-like test
  fixture is expected detector behavior. This is not proof that the fixture
  cannot authenticate elsewhere; test keys must never be reused in production.
- **Evaluation artifact** means the span occurs in a stored detector context or
  review record. Corpus provenance is established, but the original credential's
  ownership/activity is unknown. It is not counted as a confirmed false positive.
- **Unresolved** requires more context or owner review. The three JWT-shaped
  conversation-data values and two tokens in reviewer notes stay unresolved.

## What this changes about the optimization priorities

1. The imported `generic-api-key` rule is broad: its pattern permits bare `key`
   and `token` fragments and treats a comma as an assignment delimiter. In remem
   it captures 38 `topic_key` values, one prose span and one estimator version
   constant. Narrowing it needs positive tests for custom credential names;
   deleting `key`/`token` globally or ignoring all documentation could hide real
   leaks. The current release still reports these 40 findings.
2. Fifteen argus CSV findings are unquoted qualified Python identifiers before
   `or` expressions. The independent unquoted assignment rule does not establish
   literal-vs-reference semantics for arbitrary qualified identifiers. Context
   interpretation should be validated against real literals containing dots,
   while preserving detection of weak passwords.
3. One imported LinkedIn client-ID match captures a JSON property name. Provider
   rules need negative metadata examples as well as positive format fixtures.
4. Test fixtures and copied evaluation contexts need owner review before any
   baseline is accepted. Do not silently exclude every test or corpus directory.

These are review results and a concrete correction backlog. This documentation
change does **not** alter rule behavior or claim the false positives are fixed.
Use the synthetic demo for onboarding; inspect real-repository findings locally.

## Correction verified in 0.1.4

The [v7 regression and performance results](../bench/results/v7/README.md)
record the fix against these exact snapshots. remem changes **73 → 33**, argus
**46 → 28**, and rclean remains **0**. All 56 confirmed non-secret spans are
removed; all 34 intentional fixtures and 24 evaluation-artifact occurrences
remain. No new locations appear and all scans complete without errors.

Two previously unresolved tokens in argus reviewer notes (argus-015 and
argus-040) also disappear under the narrower generic context. Their unresolved
classification is retained; removal does not establish that they were false
positives or safe credentials. The three unresolved JWT-shaped values remain.
The table below preserves the original 0.1.3 review rather than rewriting it
as candidate output. Baselines must be reviewed and recreated for the new
engine configuration identity; 0.1.3 reports remain historical evidence.

## Reproduce the review

Download the pinned snapshots linked below, initialize a temporary Git repository
in each to reproduce ignore handling, and run `keyspoor scan <snapshot> --format
json` with the native 0.1.3 executable. Compare `(path, rule_id, start, end)` to
this table. Inspect each location privately. For JSON/JSONL use parsed property
paths; for CSV use a full CSV reader because quoted fields span physical lines.
For Rust tests inspect the enclosing test function and assertions. Never paste
raw values into an issue, report or benchmark log.

## Every reported location

IDs below use the report order and are local review IDs, not stable fingerprints.
Multiple rows may represent separate occurrences of copied detector contexts.
They are not necessarily distinct credentials.

| ID | Pinned source location | Rule | Byte range | Classification | Context evidence |
|---|---|---|---|---|---|
| remem-001 | [docs/specs/GH935/TECH.md:803](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/docs/specs/GH935/TECH.md#L803) | generic-api-key | 71477–71494 | Confirmed non-secret | Ordinary prose after a comma |
| remem-002 | [eval/cross-host/tasks/claude-to-codex/cc2cx-negative-constraint.json:23](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/cross-host/tasks/claude-to-codex/cc2cx-negative-constraint.json#L23) | generic-api-key | 822–847 | Confirmed non-secret | JSON topic_key metadata value |
| remem-003 | [eval/cross-host/tasks/codex-to-claude/cx2cc-negative-constraint.json:23](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/cross-host/tasks/codex-to-claude/cx2cc-negative-constraint.json#L23) | generic-api-key | 816–841 | Confirmed non-secret | JSON topic_key metadata value |
| remem-004 | [eval/golden.json:313](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L313) | generic-api-key | 11791–11814 | Confirmed non-secret | JSON topic_key metadata value |
| remem-005 | [eval/golden.json:328](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L328) | generic-api-key | 12312–12333 | Confirmed non-secret | JSON topic_key metadata value |
| remem-006 | [eval/golden.json:343](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L343) | generic-api-key | 12833–12856 | Confirmed non-secret | JSON topic_key metadata value |
| remem-007 | [eval/golden.json:358](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L358) | generic-api-key | 13360–13384 | Confirmed non-secret | JSON topic_key metadata value |
| remem-008 | [eval/golden.json:373](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L373) | generic-api-key | 13885–13908 | Confirmed non-secret | JSON topic_key metadata value |
| remem-009 | [eval/golden.json:388](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L388) | generic-api-key | 14403–14425 | Confirmed non-secret | JSON topic_key metadata value |
| remem-010 | [eval/golden.json:403](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L403) | generic-api-key | 14928–14950 | Confirmed non-secret | JSON topic_key metadata value |
| remem-011 | [eval/golden.json:418](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L418) | generic-api-key | 15454–15476 | Confirmed non-secret | JSON topic_key metadata value |
| remem-012 | [eval/golden.json:433](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L433) | generic-api-key | 15976–15996 | Confirmed non-secret | JSON topic_key metadata value |
| remem-013 | [eval/golden.json:448](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L448) | generic-api-key | 16493–16515 | Confirmed non-secret | JSON topic_key metadata value |
| remem-014 | [eval/golden.json:1330](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1330) | generic-api-key | 47617–47640 | Confirmed non-secret | JSON topic_key metadata value |
| remem-015 | [eval/golden.json:1337](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1337) | generic-api-key | 47866–47887 | Confirmed non-secret | JSON topic_key metadata value |
| remem-016 | [eval/golden.json:1344](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1344) | generic-api-key | 48110–48133 | Confirmed non-secret | JSON topic_key metadata value |
| remem-017 | [eval/golden.json:1351](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1351) | generic-api-key | 48359–48383 | Confirmed non-secret | JSON topic_key metadata value |
| remem-018 | [eval/golden.json:1358](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1358) | generic-api-key | 48610–48633 | Confirmed non-secret | JSON topic_key metadata value |
| remem-019 | [eval/golden.json:1365](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1365) | generic-api-key | 48855–48877 | Confirmed non-secret | JSON topic_key metadata value |
| remem-020 | [eval/golden.json:1372](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1372) | generic-api-key | 49104–49126 | Confirmed non-secret | JSON topic_key metadata value |
| remem-021 | [eval/golden.json:1379](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1379) | generic-api-key | 49353–49375 | Confirmed non-secret | JSON topic_key metadata value |
| remem-022 | [eval/golden.json:1386](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1386) | generic-api-key | 49603–49623 | Confirmed non-secret | JSON topic_key metadata value |
| remem-023 | [eval/golden.json:1393](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1393) | generic-api-key | 49845–49867 | Confirmed non-secret | JSON topic_key metadata value |
| remem-024 | [eval/golden.json:1845](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1845) | generic-api-key | 65197–65218 | Confirmed non-secret | JSON topic_key metadata value |
| remem-025 | [eval/golden.json:1853](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1853) | generic-api-key | 65453–65474 | Confirmed non-secret | JSON topic_key metadata value |
| remem-026 | [eval/golden.json:1861](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1861) | generic-api-key | 65709–65730 | Confirmed non-secret | JSON topic_key metadata value |
| remem-027 | [eval/golden.json:1869](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1869) | generic-api-key | 65969–65990 | Confirmed non-secret | JSON topic_key metadata value |
| remem-028 | [eval/golden.json:1877](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1877) | generic-api-key | 66227–66248 | Confirmed non-secret | JSON topic_key metadata value |
| remem-029 | [eval/golden.json:1885](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1885) | generic-api-key | 66485–66506 | Confirmed non-secret | JSON topic_key metadata value |
| remem-030 | [eval/golden.json:1893](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1893) | generic-api-key | 66741–66762 | Confirmed non-secret | JSON topic_key metadata value |
| remem-031 | [eval/golden.json:1901](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1901) | generic-api-key | 67001–67022 | Confirmed non-secret | JSON topic_key metadata value |
| remem-032 | [eval/golden.json:1909](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1909) | generic-api-key | 67261–67282 | Confirmed non-secret | JSON topic_key metadata value |
| remem-033 | [eval/golden.json:1917](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1917) | generic-api-key | 67519–67540 | Confirmed non-secret | JSON topic_key metadata value |
| remem-034 | [eval/golden.json:1933](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1933) | generic-api-key | 68037–68058 | Confirmed non-secret | JSON topic_key metadata value |
| remem-035 | [eval/golden.json:1941](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1941) | generic-api-key | 68299–68320 | Confirmed non-secret | JSON topic_key metadata value |
| remem-036 | [eval/golden.json:1949](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1949) | generic-api-key | 68565–68586 | Confirmed non-secret | JSON topic_key metadata value |
| remem-037 | [eval/golden.json:1957](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1957) | generic-api-key | 68831–68852 | Confirmed non-secret | JSON topic_key metadata value |
| remem-038 | [eval/golden.json:1965](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1965) | generic-api-key | 69095–69116 | Confirmed non-secret | JSON topic_key metadata value |
| remem-039 | [eval/golden.json:1973](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/golden.json#L1973) | generic-api-key | 69359–69380 | Confirmed non-secret | JSON topic_key metadata value |
| remem-040 | [eval/locomo/locomo10.json:43896](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/locomo/locomo10.json#L43896) | jwt | 1852519–1852980 | Unresolved | JWT-shaped value in imported conversation dataset; ownership and activity unknown |
| remem-041 | [eval/locomo/locomo10.json:64751](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/locomo/locomo10.json#L64751) | jwt | 2709460–2710093 | Unresolved | JWT-shaped value in imported conversation dataset; ownership and activity unknown |
| remem-042 | [eval/locomo/locomo10.json:64846](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/eval/locomo/locomo10.json#L64846) | jwt | 2714562–2714974 | Unresolved | JWT-shaped value in imported conversation dataset; ownership and activity unknown |
| remem-043 | [specs/GH932/tech.md:203](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/specs/GH932/tech.md#L203) | generic-api-key | 15705–15724 | Confirmed non-secret | Estimator version constant |
| remem-044 | [src/adapter/common/tests.rs:110](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L110) | curl-auth-header | 3509–3529 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-045 | [src/adapter/common/tests.rs:137](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L137) | generic-api-key | 4218–4234 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-046 | [src/adapter/common/tests.rs:138](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L138) | curl-auth-header | 4292–4312 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-047 | [src/adapter/common/tests.rs:152](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L152) | generic-credential-double | 4705–4717 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-048 | [src/adapter/common/tests.rs:181](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L181) | generic-credential-double | 5631–5643 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-049 | [src/adapter/common/tests.rs:182](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L182) | curl-auth-header | 5701–5711 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-050 | [src/adapter/common/tests.rs:262](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L262) | curl-auth-header | 8315–8323 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-051 | [src/adapter/common/tests.rs:275](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L275) | generic-credential-double | 8716–8728 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-052 | [src/adapter/common/tests.rs:276](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L276) | generic-credential-double | 8756–8767 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-053 | [src/adapter/common/tests.rs:308](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L308) | curl-auth-user | 9714–9722 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-054 | [src/adapter/common/tests.rs:322](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L322) | uri-userinfo-password | 10197–10199 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-055 | [src/adapter/common/tests.rs:751](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L751) | generic-api-key | 26216–26232 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-056 | [src/adapter/common/tests.rs:753](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/adapter/common/tests.rs#L753) | generic-api-key | 26300–26320 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-057 | [src/api/tests/candidate_safe_review.rs:445](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/api/tests/candidate_safe_review.rs#L445) | generic-api-key | 14686–14700 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-058 | [src/api/tests/candidates.rs:522](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/api/tests/candidates.rs#L522) | generic-api-key | 19041–19061 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-059 | [src/api/tests/candidates.rs:693](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/api/tests/candidates.rs#L693) | generic-credential-double | 25970–25999 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-060 | [src/cli/actions/codex_memory_import/tests.rs:383](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/cli/actions/codex_memory_import/tests.rs#L383) | generic-api-key | 13765–13797 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-061 | [src/cli/actions/review.rs:427](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/cli/actions/review.rs#L427) | generic-api-key | 16553–16573 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-062 | [src/db/capture/tests.rs:235](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/db/capture/tests.rs#L235) | generic-credential-double | 8112–8127 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-063 | [src/db/capture/tests.rs:273](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/db/capture/tests.rs#L273) | generic-credential-double | 9310–9347 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-064 | [src/db/capture/tests.rs:401](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/db/capture/tests.rs#L401) | generic-credential-double | 14292–14307 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-065 | [src/install/cursor_config/tests.rs:206](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/install/cursor_config/tests.rs#L206) | generic-credential-double | 7129–7135 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-066 | [src/migrate/tests_job_queue_atomicity.rs:352](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/migrate/tests_job_queue_atomicity.rs#L352) | generic-credential-double | 12242–12246 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-067 | [src/migrate/tests_job_queue_atomicity.rs:373](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/migrate/tests_job_queue_atomicity.rs#L373) | generic-credential-double | 13046–13050 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-068 | [src/migrate/tests_job_queue_atomicity.rs:427](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/migrate/tests_job_queue_atomicity.rs#L427) | generic-credential-double | 15090–15094 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-069 | [src/migrate/tests_job_queue_atomicity.rs:433](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/migrate/tests_job_queue_atomicity.rs#L433) | generic-credential-double | 15438–15450 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-070 | [src/migrate/tests_job_queue_atomicity.rs:444](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/migrate/tests_job_queue_atomicity.rs#L444) | generic-credential-double | 15780–15784 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-071 | [src/migrate/tests_job_queue_atomicity.rs:549](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/migrate/tests_job_queue_atomicity.rs#L549) | generic-credential-double | 19796–19805 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-072 | [src/migrate/tests_job_queue_atomicity.rs:561](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/migrate/tests_job_queue_atomicity.rs#L561) | generic-credential-double | 20255–20264 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| remem-073 | [src/migrate/tests_job_queue_atomicity.rs:611](https://github.com/majiayu000/remem/blob/3722f8083d08774a58d5234ceda817ec3951b7d7/src/migrate/tests_job_queue_atomicity.rs#L611) | generic-credential-double | 22210–22230 | Intentional test fixture | Rust unit test for redaction, security behavior or fixture persistence |
| argus-001 | [corpus/agent/labeling-worklists/detector-hit-001.jsonl:147](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-001.jsonl#L147) | generic-credential-single | 179204–179215 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-002 | [corpus/agent/labeling-worklists/detector-hit-001.jsonl:147](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-001.jsonl#L147) | generic-credential-single | 179531–179542 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-003 | [corpus/agent/labeling-worklists/detector-hit-001.jsonl:173](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-001.jsonl#L173) | generic-credential-unquoted | 208496–208504 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-004 | [corpus/agent/labeling-worklists/detector-hit-001.jsonl:173](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-001.jsonl#L173) | generic-credential-unquoted | 208720–208728 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-005 | [corpus/agent/labeling-worklists/detector-hit-001.jsonl:173](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-001.jsonl#L173) | generic-credential-unquoted | 208834–208842 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-006 | [corpus/agent/labeling-worklists/detector-hit-002.jsonl:172](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-002.jsonl#L172) | uri-userinfo-password | 246789–246797 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-007 | [corpus/agent/labeling-worklists/detector-hit-002.jsonl:172](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-002.jsonl#L172) | uri-userinfo-password | 246849–246857 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-008 | [corpus/agent/labeling-worklists/detector-hit-002.jsonl:172](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-002.jsonl#L172) | uri-userinfo-password | 247103–247111 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-009 | [corpus/agent/labeling-worklists/detector-hit-002.jsonl:172](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-002.jsonl#L172) | uri-userinfo-password | 247163–247171 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-010 | [corpus/agent/labeling-worklists/detector-hit-003.jsonl:29](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-003.jsonl#L29) | generic-credential-single | 40769–40777 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-011 | [corpus/agent/labeling-worklists/detector-hit-003.jsonl:29](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-hit-003.jsonl#L29) | generic-credential-single | 41031–41039 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-012 | [corpus/agent/labeling-worklists/detector-non-block-001.jsonl:222](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/corpus/agent/labeling-worklists/detector-non-block-001.jsonl#L222) | linkedin-client-id | 205162–205176 | Confirmed non-secret | JSON property name captured as a client ID |
| argus-013 | [crates/argus-core/src/url.rs:334](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/crates/argus-core/src/url.rs#L334) | uri-userinfo-password | 12039–12045 | Intentional test fixture | Unit test exercises URI rejection / literal matching |
| argus-014 | [crates/argus-rules/src/session/tests.rs:78](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/crates/argus-rules/src/session/tests.rs#L78) | generic-credential-unquoted | 2194–2199 | Intentional test fixture | Unit test exercises URI rejection / literal matching |
| argus-015 | [eval/labeling/frozen/final_labels.jsonl:1141](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/final_labels.jsonl#L1141) | generic-api-key | 842085–842097 | Unresolved | Dotted token in reviewer notes; local context insufficient to establish credential meaning |
| argus-016 | [eval/labeling/frozen/reviewer.csv:161](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L161) | generic-credential-unquoted | 20327–20357 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-017 | [eval/labeling/frozen/reviewer.csv:799](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L799) | generic-credential-unquoted | 93006–93036 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-018 | [eval/labeling/frozen/reviewer.csv:1830](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L1830) | generic-credential-unquoted | 215609–215639 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-019 | [eval/labeling/frozen/reviewer.csv:2407](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L2407) | generic-credential-unquoted | 282579–282587 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-020 | [eval/labeling/frozen/reviewer.csv:2409](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L2409) | generic-credential-unquoted | 282684–282692 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-021 | [eval/labeling/frozen/reviewer.csv:3215](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L3215) | generic-credential-unquoted | 379644–379652 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-022 | [eval/labeling/frozen/reviewer.csv:3854](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L3854) | generic-credential-unquoted | 451028–451058 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-023 | [eval/labeling/frozen/reviewer.csv:3910](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L3910) | generic-credential-single | 458486–458494 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-024 | [eval/labeling/frozen/reviewer.csv:4022](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L4022) | generic-credential-unquoted | 471169–471173 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-025 | [eval/labeling/frozen/reviewer.csv:4049](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L4049) | generic-credential-unquoted | 474653–474657 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-026 | [eval/labeling/frozen/reviewer.csv:4360](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L4360) | generic-credential-unquoted | 515663–515669 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-027 | [eval/labeling/frozen/reviewer.csv:4362](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L4362) | generic-credential-unquoted | 515786–515792 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-028 | [eval/labeling/frozen/reviewer.csv:5193](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L5193) | generic-credential-unquoted | 609297–609327 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-029 | [eval/labeling/frozen/reviewer.csv:6675](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L6675) | generic-credential-unquoted | 781276–781280 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-030 | [eval/labeling/frozen/reviewer.csv:6762](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L6762) | generic-credential-unquoted | 791440–791444 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-031 | [eval/labeling/frozen/reviewer.csv:6806](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L6806) | generic-credential-unquoted | 797488–797518 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-032 | [eval/labeling/frozen/reviewer.csv:7156](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L7156) | generic-credential-unquoted | 833066–833096 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-033 | [eval/labeling/frozen/reviewer.csv:8614](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L8614) | generic-credential-unquoted | 1011607–1011637 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-034 | [eval/labeling/frozen/reviewer.csv:8813](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L8813) | uri-userinfo-password | 1034181–1034189 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-035 | [eval/labeling/frozen/reviewer.csv:8814](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L8814) | uri-userinfo-password | 1034240–1034248 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-036 | [eval/labeling/frozen/reviewer.csv:9167](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L9167) | generic-credential-single | 1075581–1075592 | Evaluation artifact | Credential-like example in stored detector context; original ownership/activity not established |
| argus-037 | [eval/labeling/frozen/reviewer.csv:9212](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L9212) | generic-credential-unquoted | 1082948–1082978 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-038 | [eval/labeling/frozen/reviewer.csv:9451](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L9451) | generic-credential-unquoted | 1113806–1113836 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-039 | [eval/labeling/frozen/reviewer.csv:9743](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L9743) | generic-credential-unquoted | 1147053–1147083 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-040 | [eval/labeling/frozen/reviewer.csv:9758](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L9758) | generic-api-key | 1147939–1147951 | Unresolved | Dotted token in reviewer notes; local context insufficient to establish credential meaning |
| argus-041 | [eval/labeling/frozen/reviewer.csv:10150](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L10150) | generic-credential-unquoted | 1197615–1197645 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-042 | [eval/labeling/frozen/reviewer.csv:10680](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L10680) | generic-credential-unquoted | 1261714–1261744 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-043 | [eval/labeling/frozen/reviewer.csv:11225](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L11225) | generic-credential-unquoted | 1322878–1322908 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-044 | [eval/labeling/frozen/reviewer.csv:12162](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/eval/labeling/frozen/reviewer.csv#L12162) | generic-credential-unquoted | 1422694–1422724 | Confirmed non-secret | Bare qualified Python identifier before an or-expression; not a literal |
| argus-045 | [third_party/sigstore-verify/test_data/x509/nonroot-privkey.pem:1](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/third_party/sigstore-verify/test_data/x509/nonroot-privkey.pem#L1) | private-key | 0–1703 | Intentional test fixture | Vendored certificate verification test key; not assessed for other uses |
| argus-046 | [third_party/sigstore-verify/test_data/x509/root-privkey.pem:1](https://github.com/majiayu000/argus/blob/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09/third_party/sigstore-verify/test_data/x509/root-privkey.pem#L1) | private-key | 0–1703 | Intentional test fixture | Vendored certificate verification test key; not assessed for other uses |
