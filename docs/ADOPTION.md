# Keyspoor trial guide and launch material

Start with the [60-second CLI example](../README.md#try-it-in-60-seconds),
[Agent setup](AGENT_SETUP.md), or [complete CI setup](CI_SETUP.md).
Use synthetic values for demonstrations and reports. Never send credentials,
private source snippets, or raw provider responses as feedback.

## Acceptance checks

- Fresh public npm installation reports the pinned release version.
- Clean, synthetic-finding and incomplete/error CLI scans return 0, 1 and 2.
- Reports omit the synthetic value and contain locations, completeness and errors.
- Published MCP startup, initialization, tool discovery, clean/finding scans,
  root enforcement and incomplete scans work through the npm launcher.
- Published Action checks pass on Linux, macOS and Windows, and reports survive
  expected finding/error step failures.
- Agent setup examples serialize correctly in isolated client configurations.
  Configuration parsing is distinct from an actual client/model tool invocation.

## Real repository trial

The release trial uses pinned public snapshots of `majiayu000/remem`,
`majiayu000/rclean` and `majiayu000/argus`, extracted into temporary directories.
No project build scripts run and no source changes are pushed to those projects.
The source snapshots have no original Git history; a local Git marker enables
repository ignore behavior. This experiment measures checked-out file scanning,
not history or PR-diff scanning.

Measured on 2026-10-04 using the **public npm 0.1.3 package**, on macOS 26.5.2
ARM64. A fresh npm cache took **5.01 seconds** to install and finish the first
synthetic stdin scan. Five subsequent offline npm-launcher scans had a median
of **0.323 seconds**. Installation time depends on the registry and network.

Each repository row below is the median of five end-to-end runs through
`npx --offline --yes keyspoor@0.1.3 scan <snapshot> --format json`, after package
installation. Times include launcher and scanner startup; filesystem caches
were not flushed. This is an adoption smoke benchmark, not a cold-disk or
cross-tool performance comparison. Byte counts are the scanner's processed
bytes, not downloaded archive sizes.

| Public snapshot | Files | Processed bytes | Median seconds | Findings | Errors / complete |
|---|---:|---:|---:|---:|---|
| [remem @ 3722f808](https://github.com/majiayu000/remem/tree/3722f8083d08774a58d5234ceda817ec3951b7d7) | 2,687 | 163,358,510 | 0.824 | 73 | 0 / true |
| [rclean @ 3ea1704d](https://github.com/majiayu000/rclean/tree/3ea1704d05363c67b46b4e7619eeb02a3400862d) | 351 | 2,064,038 | 0.359 | 0 | 0 / true |
| [argus @ f2f0490e](https://github.com/majiayu000/argus/tree/f2f0490e94c3972cc86a52b6e2b38fc336c8bf09) | 658 | 10,572,461 | 0.552 | 46 | 0 / true |

Run durations in seconds, in execution order:

- remem: 0.933, 0.818, 0.817, 0.827, 0.824.
- rclean: 0.428, 0.365, 0.359, 0.359, 0.351.
- argus: 0.563, 0.551, 0.546, 0.552, 0.559.

A follow-up using the **public macOS ARM64 native 0.1.3 release binary** on
the same snapshots removed npm-launcher overhead. Five sequential new-process
runs per repository, with filesystem caches uncleared, produced:

| Snapshot | Native median seconds | Cached npm median seconds |
|---|---:|---:|
| remem | 0.532 | 0.824 |
| rclean | 0.047 | 0.359 |
| argus | 0.258 | 0.552 |

Native run durations in seconds, in execution order:

- remem: 1.838, 0.532, 0.530, 0.530, 0.533.
- rclean: 0.060, 0.047, 0.047, 0.048, 0.047.
- argus: 0.295, 0.255, 0.260, 0.256, 0.258.

The first remem native invocation was slower; its cause was not isolated, so
the median must not be presented as guaranteed first-launch latency. All runs
were complete and had zero errors, with the same file/byte and finding counts
as the npm trials. Invoke the downloaded platform binary directly with
`scan <snapshot> --format json` to reproduce. These were separate sequential
sessions, not an alternating paired experiment; differences do not establish
an exact constant npm overhead. Native CLI hooks and persistent MCP servers
avoid paying an npm launcher startup on each scan.

All three snapshots passed baseline suppression, detection of a newly inserted
synthetic finding, and staged scanning against Git index contents differing
from the working file. Baselines were temporary test artifacts; existing
findings were not reviewed or accepted as safe. Do not automatically baseline
unreviewed findings in a production repository.

To reproduce the snapshot workload, download the linked commits as source
archives, extract each into a temporary directory, run `git init` there to
activate repository ignore behavior, install the pinned package once, and run
the scan command above five times. No project build or original Git history is
needed. Existing cross-tool evaluations and ground-truth methodology are in
[bench/README.md](../bench/README.md).

Raw credential values were not collected in the published measurements.
Findings in these unlabelled repositories are detection counts, not a measured
false-positive rate; classifying them needs a separately reviewed ground truth.

## Client and distribution results

- CLI clean/finding/incomplete exits 0/1/2 and redaction passed through the
  published npm package.
- Published npm MCP passed initialization, tool discovery, text and path scans,
  an absolute root containing spaces, rejection of paths outside that root,
  missing-path errors and incomplete scans. stdout contained JSON-RPC only.
- A real Codex 0.160.0 model invoked `scan_text` against the native 0.1.3 server:
  one finding, complete=true, zero errors, no truncation and `[REDACTED]`.
  This one-call model smoke test took 33.78 seconds, including model/tool startup;
  it is distinct from scanner throughput. The first test prompt prevented tool
  discovery; permitting discovery for that exact tool made the retry pass.
- Claude Code 2.1.234 project configuration and native MCP connection passed.
  Its model invocation was not tested because the client was not logged in.
  Cursor configuration JSON parsed successfully; its UI/model invocation was
  not exercised.
- The [0.1.3 release run](https://github.com/majiayu000/keyspoor/actions/runs/37183934247)
  passed Linux/macOS/Windows CI, five native builds, registry installation and
  public `uses: majiayu000/keyspoor@v1` scans on all three operating systems.
  All nine clean/finding/error SARIF reports survived expected failing scan
  steps and were downloaded and parsed after the run.

- Homebrew updated automatically to 0.1.3; the official tap upgrade,
  `brew test` and strict audit passed. The updater now uses its existing short-lived
  GitHub token for release metadata, avoiding anonymous API rate limits.

These checks establish working installation and specific integrations. They
are not evidence of external user retention or production detection accuracy.

## Invite a first-time user

Suggested invitation (adapt the greeting and send only to an intended recipient):

> I am building Keyspoor, an offline Rust secret scanner for CI and AI coding
> agents. Could you try one scan or add its read-only MCP tools to your project?
> Installation and setup: https://github.com/majiayu000/keyspoor
> I am especially interested in where setup is confusing, findings that are hard
> to interpret, and whether you would keep it in your workflow. Please send only
> synthetic examples and version/platform details, never actual credentials.

Chinese invitation:

> 我在做 Keyspoor，一个用于 CI 和 AI 编程助手的离线 Rust 密钥扫描器。想请你试一次仓库扫描，或者给 Agent 接入它的只读 MCP 工具。安装和接入步骤：https://github.com/majiayu000/keyspoor 。最想知道哪些步骤难理解、哪些结果不好处理，以及你是否愿意继续用。反馈请用合成样例，不要发真实凭证或私有源码。

## Feedback to collect

Copy this into a GitHub issue or private message:

```text
Keyspoor version:
Operating system / architecture:
Installation channel:
Use case: CLI / staged hook / CI / Rust / MCP client
Time until first successful scan:
Command or configuration with sensitive values removed:
Expected result:
Actual exit code / complete / error_count / output_truncated:
Synthetic reproduction, if available:
Would you keep using it? Why?
```

Do not infer active users from package downloads or stars. The next validation
milestone is five real repository integrations and three still running after a
week. That is a future target, not a result established by automated tests.

## Public announcement draft

**Keyspoor: offline secret scanning for Rust, CI and AI coding agents**

Keyspoor scans files, staged Git changes, local history and supported archives.
It provides redacted JSON/JSONL/SARIF reports, a reusable Rust engine, a GitHub
Action and read-only MCP tools. Detection does not call credential providers;
installation through npm requires registry access. It does not establish whether
matched credentials are active.

Try the pinned package with `npx -y keyspoor@0.1.3 scan . --format json`.
Setup guides cover Codex, Claude Code, Cursor, CI and local staged hooks.
Rules, exclusions and versioned benchmark methodology are documented in the
repository. Performance findings are workload-specific; no universal fastest
scanner or production-accuracy claim is made.

Source and setup: https://github.com/majiayu000/keyspoor
Website: https://majiayu000.github.io/keyspoor/

## Directory and outreach status

[MCP Registry registration](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.majiayu000%2Fkeyspoor)
for `io.github.majiayu000/keyspoor` version 0.1.3 is public and was verified via
the registry API. GitHub Marketplace publishing still requires its separate
web confirmation flow; no listing has been claimed. External
invitations and community posts need an intended audience/account; prepared
material is not evidence that those messages have been sent or users recruited.
