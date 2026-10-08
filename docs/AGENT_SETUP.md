# Keyspoor for Codex, Claude Code and Cursor

Give your coding assistant two read-only scanning tools: `scan_paths` reads
files under a selected project root; `scan_text` scans text supplied by the
assistant. Results are redacted and detection stays offline. The assistant and
its provider can still receive tool arguments, paths and report metadata;
Keyspoor does not change the client's data handling.

MCP makes tools available. It does not guarantee that the assistant calls them
on every edit or before every commit. Use a [required CI check](CI_SETUP.md) or a
Git hook when a scan must run before changes are accepted.

## Prepare once

Install Node.js 20+ and warm the pinned package before starting the assistant:

```sh
npx -y keyspoor@0.1.4 --version
```

Expected: `keyspoor 0.1.4`. First-time installation needs npm registry access;
the installed scanner does not contact credential providers. Replace
`/absolute/path/to/project` below with an existing absolute directory you want
to scan. Quote paths with spaces in shell commands. Keyspoor resolves requested
file paths relative to this root and rejects paths outside it.

If you installed a standalone binary, use its absolute path as `command` and
remove `-y` and `keyspoor@0.1.4` from `args`. Keep `mcp --root ...`.
On Windows, use `npx.cmd` as the command; JSON paths use escaped backslashes or
forward slashes, for example `C:/work/project`.

## Codex

Register the server using the Codex CLI:

```sh
codex mcp add keyspoor -- npx -y keyspoor@0.1.4 mcp --root /absolute/path/to/project
codex mcp get keyspoor
codex mcp list
```

This writes the user MCP configuration in `~/.codex/config.toml`. Alternatively,
merge this table into that file, preserving other settings:

```toml
[mcp_servers.keyspoor]
command = "npx"
args = ["-y", "keyspoor@0.1.4", "mcp", "--root", "/absolute/path/to/project"]
```

Start a new Codex session in the project and use `/mcp` to inspect active tools.
`mcp get` and `mcp list` confirm configuration; they do not prove a tool call
succeeded. If startup times out after warming the package, check the executable
and root path; Codex also supports `startup_timeout_sec` in the table.
[Official OpenAI MCP documentation](https://developers.openai.com/codex/mcp/).

## Claude Code

From your project directory, register a server scoped to your own use in that
project:

```sh
claude mcp add --transport stdio --scope local keyspoor -- npx -y keyspoor@0.1.4 mcp --root /absolute/path/to/project
claude mcp get keyspoor
```

For a shared configuration, use `--scope project` instead; this writes
`.mcp.json`. Review machine-specific paths before committing it. Claude Code
requires approval for project configurations, so a newly shared server may be
shown as pending approval. Open `/mcp` in a new Claude Code session, approve the
reviewed server if requested and confirm it connects.
[Official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

## Cursor

Merge this entry into your project's `.cursor/mcp.json`, preserving any existing
servers:

```json
{
  "mcpServers": {
    "keyspoor": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "keyspoor@0.1.4", "mcp", "--root", "${workspaceFolder}"]
    }
  }
}
```

Cursor expands `${workspaceFolder}` to the directory containing `.cursor`.
Open the project's MCP settings, enable the server if needed and confirm that
`scan_text` and `scan_paths` appear. Use Agent mode and approve tool calls when
requested. Current Cursor CLI users can inspect discovery with
`agent mcp list-tools keyspoor` (some installations name the executable
`cursor-agent`). [Official Cursor MCP documentation](https://cursor.com/docs/mcp).

## Verify a scan before relying on it

Ask the assistant to run this synthetic check explicitly:

> Call Keyspoor's scan_text with path "demo.env" and text
> "password=KspDemo_7zQ2mX9pL4vN6sR8". This is a made-up demo value.
> Report complete, finding_count, error_count and output_truncated, then the
> finding's rule, line, byte column and redacted field. Do not repeat the value.

Expected tool data: `complete=true`, `finding_count=1`, `error_count=0`,
`output_truncated=false`; the finding has `rule_id=generic-credential-unquoted`,
`line=1`, `column=9`, `redacted=[REDACTED]`. A successful MCP tool result has
`isError=false` even when findings exist; the CLI's exit code `1` does not apply
to a persistent MCP process.

Next ask:

> Call Keyspoor's scan_paths with paths ["."] under the configured root.
> Summarize completeness, total counts and reported file locations. Explain any
> errors before interpreting the findings. Do not print source snippets.

For a clean synthetic check, call `scan_text` with `text="ordinary configuration"`:
expect `complete=true`, `finding_count=0`, `error_count=0`.
Treat `complete=false` or `isError=true` as a failed/incomplete scan. Read
`error_count` even if the visible error list is empty, and inspect
`output_truncated`: previews have at most 100 findings and 100 errors within a
shared 512 KiB entry budget. A truncated preview is not the full report; use
[the CLI](../README.md#cli-and-repository-scans) to save a complete redacted report.

Keyspoor respects ignore files and never live-validates credentials. A clean
scan cannot establish that all secrets were absent. Do not feed real credentials
into chat to test integration; use the synthetic text above.

## If tools do not appear

Run `npx -y keyspoor@0.1.4 --version` in the same environment that starts the
client, check the configured root exists and restart the client. GUI apps may
have a different PATH; configure the absolute path to `npx`, `npx.cmd` or the
standalone binary if needed. Inspect the client's MCP status and stderr rather
than pasting credentials or private configuration into an issue. `mcp` is a
stdio server, so running it in a terminal without a client waits for protocol
messages; do not add banners or debug output to stdout.

These setup shapes follow the linked official documentation. Verification
covers isolated Codex/Claude CLI configuration parsing, Cursor JSON parsing and
Keyspoor protocol responses. It does not establish an end-to-end model-driven
scan in every client version; perform the explicit tool checks above in your
own client.
