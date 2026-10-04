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

Measurements and source commits will be recorded here after testing the public
0.1.3 package. Raw private credentials are not collected. Findings in these
unlabelled repositories are detection counts, not a measured false-positive
rate; classifying them needs a separate reviewed ground truth.

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

MCP Registry registration and public release checks are part of this release.
GitHub Marketplace publishing has a separate web confirmation flow. External
invitations and community posts need an intended audience/account; prepared
material is not evidence that those messages have been sent or users recruited.
