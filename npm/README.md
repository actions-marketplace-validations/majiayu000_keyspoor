# Keyspoor — offline secret scanning for AI coding workflows

Keyspoor finds API keys, passwords and other credentials in source code, local
Git history and supported archives. Its independent Rust engine includes 225
rules, redacted findings, baseline support, JSON/JSONL/SARIF output and an MCP
stdio server for AI agents. Connect agents through MCP; use Git hooks or required
CI checks for enforcement.

This npm package provides the **native command-line tool**, not a JavaScript SDK.
For the Rust library, source, rule provenance and measured benchmarks, see the
[Keyspoor repository](https://github.com/majiayu000/keyspoor).

## Try it in 60 seconds

With Node.js 20+, run this in a macOS/Linux terminal. The input is deliberately
made up for the demo and is not a credential:

```sh
printf 'password=KspDemo_7zQ2mX9pL4vN6sR8\n' | npx -y keyspoor@0.1.3 scan - --format json
echo "exit=$?"
```

Expected: `exit=1`, `complete=true`, one `generic-credential-unquoted` finding
at line 1, byte column 9, and `redacted="[REDACTED]"`. The report contains no
raw value or source snippet. PowerShell users can pipe the same string through
`npx.cmd` and check `$LASTEXITCODE`.

[Watch the complete commit-blocking demo](https://majiayu000.github.io/keyspoor/#demo)
and [run its script](https://github.com/majiayu000/keyspoor/blob/main/examples/first-scan.sh).
The demo uses an isolated temporary Git repository and synthetic input.

| Use case | Guide |
| --- | --- |
| CLI and Git scans | [Repository commands](https://github.com/majiayu000/keyspoor#cli-and-repository-scans) |
| Pull request checks | [Complete CI workflow](https://github.com/majiayu000/keyspoor/blob/main/docs/CI_SETUP.md) |
| Codex, Claude Code, Cursor | [MCP setup](https://github.com/majiayu000/keyspoor/blob/main/docs/AGENT_SETUP.md) |
| Embed in Rust | [Rust API](https://docs.rs/keyspoor) |

## Install and scan

```sh
npm install --global keyspoor@0.1.3
keyspoor scan . --format json
keyspoor staged .
keyspoor history .
keyspoor scan - --format jsonl
keyspoor mcp --root /absolute/path/to/project
```

You can also run `npx -y keyspoor@0.1.3 scan . --format sarif` without a global
installation. A standalone npm-format tarball is available on GitHub Releases.

The package bundles native binaries for Linux x64/ARM64 (GNU libc), macOS
x64/ARM64 and Windows x64. Node.js 20 or later is required for the launcher.
It has no install scripts, install-time binary downloads or runtime JavaScript
dependencies. Alpine/musl and Windows ARM64 are not supported by these binaries.
Linux builds use Ubuntu 24.04 and dynamically link glibc; older glibc systems
are not guaranteed to run them. See the [release guide](https://github.com/majiayu000/keyspoor/blob/main/docs/RELEASING.md).
Git must be installed for staged and history scans.

Exit codes are **0** for a completed scan with no reported findings, **1** for a
completed scan with findings, and **2** for errors or an incomplete scan. The
launcher passes arguments and standard streams directly to the Rust CLI.
Check the other outcomes with synthetic input:

```sh
printf 'ordinary configuration\n' | npx -y keyspoor@0.1.3 scan - --format json
echo "exit=$?" # 0: complete=true, findings=[]
printf 'ordinary configuration\n' | npx -y keyspoor@0.1.3 scan - --max-bytes 4 --format json
echo "exit=$?" # 2: complete=false, errors contains "input exceeds 4 byte limit"
```

Investigate errors before treating a scan as complete. Review findings locally
at their reported positions and rotate real credentials that have been exposed.
MCP offers tools to agents; use required CI checks or Git hooks for enforcement.
First-time package installation accesses npm; detection itself stays offline.

Scanning is offline and does not verify whether credentials are active. Findings
are redacted; the scanner does not print raw secrets. Detection has false positives
and false negatives; a clean result is not proof that an input contains no secrets.
See the [documentation](https://github.com/majiayu000/keyspoor#readme) for scan
limits, ignore behavior, custom rules and baseline semantics.

## License

Apache-2.0. Adapted Gitleaks rule data retains its MIT license and attribution in
`THIRD_PARTY_NOTICES`.
