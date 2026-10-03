# Keyspoor — offline secret scanner

Keyspoor finds API keys, passwords and other credentials in source code, local
Git history and supported archives. Its independent Rust engine includes 225
rules, redacted findings, baseline support, JSON/JSONL/SARIF output and an MCP
stdio server for AI agents.

This npm package provides the **native command-line tool**, not a JavaScript SDK.
For the Rust library, source, rule provenance and measured benchmarks, see the
[Keyspoor repository](https://github.com/majiayu000/keyspoor).

## Install and scan

```sh
npm install --global keyspoor
keyspoor scan . --format json
keyspoor staged .
keyspoor history .
keyspoor scan - --format jsonl
keyspoor mcp --root /absolute/path/to/project
```

You can also run `npx keyspoor scan . --format sarif` without a global
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

Scanning is offline and does not verify whether credentials are active. Findings
are redacted; the scanner does not print raw secrets. Detection has false positives
and false negatives; a clean result is not proof that an input contains no secrets.
See the [documentation](https://github.com/majiayu000/keyspoor#readme) for scan
limits, ignore behavior, custom rules and baseline semantics.

## License

Apache-2.0. Adapted Gitleaks rule data retains its MIT license and attribution in
`THIRD_PARTY_NOTICES`.
