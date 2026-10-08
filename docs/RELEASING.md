# Releasing Keyspoor

Push a full version tag to publish GitHub binaries, npm and crates.io through
[release.yml](../.github/workflows/release.yml). No local `npm login`, browser
confirmation or stored registry token is needed for this workflow. Both
registries must have a trusted publisher configured for repository
`majiayu000/keyspoor`, workflow `release.yml`, with no environment name.

Update `Cargo.toml`, `Cargo.lock`, `npm/package.json` and the two version fields
in `server.json` together, add versioned release notes below, then commit the
change, then push the release commit and tag:

```sh
git push origin main
git tag v0.1.3
git push origin v0.1.3
gh run list --workflow release.yml
```

The workflow checks the tag against Cargo and npm versions, reuses the complete
three-platform CI workflow, and builds the five native binaries below. It then
stages those binaries with `npm/scripts/stage.mjs`, runs npm tests, packs one
tarball and installs that tarball in a temporary directory. The installed CLI
must report the correct version, return clean/finding/error exits 0/1/2 and
redact a synthetic secret. All five bundled platform binaries must be present.

Only after CI and packaging pass do npm and crates.io publication run. npm uses
Node 24 and pinned npm 11.21.0 with OIDC trusted publishing and provenance;
crates.io uses the pinned official `rust-lang/crates-io-auth-action` to obtain
a short-lived token. npm publishes the exact tested tarball, then the workflow
performs a fresh registry install and repeats the CLI checks in a separate job,
so a failed installation can be retried without republishing. npm may take a
few minutes to make an accepted publication visible: this job waits up to ten
minutes for the version in npm's installation index, retrying HTTP 404 or an
index that does not yet list the version. It requests the same abbreviated
metadata format as npm install because the separate exact-version endpoint can
become visible earlier. Other errors, malformed metadata and the actual CLI
verification fail immediately. Cargo publishes
with `--locked`. The GitHub release is created after both registry jobs succeed.
It includes the same npm tarball, five binaries, license files and `SHA256SUMS`.

| Target | Asset for v0.1.3 | Native runner |
|---|---|---|
| Linux x64, glibc | `keyspoor-v0.1.3-x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| Linux ARM64, glibc | `keyspoor-v0.1.3-aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| macOS Intel | `keyspoor-v0.1.3-x86_64-apple-darwin` | `macos-15-intel` |
| macOS Apple Silicon | `keyspoor-v0.1.3-aarch64-apple-darwin` | `macos-15` |
| Windows x64 | `keyspoor-v0.1.3-x86_64-pc-windows-msvc.exe` | `windows-2025` |

On Linux, verify downloaded assets with `sha256sum --check SHA256SUMS`; on
macOS, use `shasum -a 256 --check SHA256SUMS`. Mark a downloaded Unix binary
executable with `chmod +x`. Linux artifacts use Ubuntu 24.04 glibc; build from
source for Alpine/musl or unsupported older glibc systems.

Run a build-only rehearsal before tagging:

```sh
gh workflow run release.yml --ref main
```

A manual run performs version checks, CI, native builds and npm packaging,
uploading the verified `release-assets` Actions artifact. It does not publish
to a registry or create a GitHub release. The `v1` scanner Action alias does
not trigger publication: only full numeric version tags do.

After the GitHub release succeeds, the workflow updates the maintained scanner
Action `v1` alias to the published commit and runs the public Action consumer
checks on Linux, macOS and Windows. Full numeric version tags remain immutable.
A failed alias/consumer job can be retried independently of registry publication.

The MCP Registry job runs after the npm registry installation check. It uses
pinned `mcp-publisher` 1.8.1, verifies its download hash, authenticates through
GitHub OIDC, and publishes `server.json`. The npm package's `mcpName` matches
`io.github.majiayu000/keyspoor`. Registry metadata describes the stdio command
and a required project-root argument; the registry stores metadata, not binaries.

The Homebrew tap has its own scheduled workflow that reads the published
GitHub release and updates the formula using the tap repository's temporary
`GITHUB_TOKEN`. It can also be run manually in the tap after a release. No
cross-repository personal access token is required; scheduled updates can lag
behind GitHub publication.

Registry versions are immutable. If a release partially succeeds, inspect the
failed job and registry state before retrying; do not move a published version
tag or attempt to overwrite a published package. A fresh version is required
for changed package contents.

Trusted publisher references: [npm](https://docs.npmjs.com/trusted-publishers/),
[crates.io](https://crates.io/docs/trusted-publishing), and
[official crates.io authentication action](https://github.com/rust-lang/crates-io-auth-action).

## v0.1.4 release notes

Fix credential-context false positives in generic API assignment matching,
LinkedIn client-ID capture across JSON fields, and unquoted `config.*` references.
The three pinned public snapshots drop all 56 reviewed non-secret spans;
intentional fixtures and evaluation-artifact matches remain. Two unresolved
reviewer-note tokens also drop and remain explicitly unresolved.

The three existing synthetic regression sets retain 1,234 labelled positives
with zero candidate false negatives. Twenty alternating native performance
pairs show less than 0.3% wall-median change on the 16/128 MiB synthetic workloads.
[Raw results, comparison and limits](../bench/results/v7/README.md) are recorded.
No universal accuracy or speed claim follows from these samples.

**Baseline change:** engine configuration identity is v4. Review findings and
create a new baseline file; older identities are rejected and cannot be
overwritten by `--write-baseline`. Report schemas and CLI
exits 0/1/2 remain unchanged. The npm package includes the updated first-use and
agent setup documentation.

```sh
npm install -g keyspoor@0.1.4
# Or: cargo install keyspoor --version 0.1.4 --locked
# Or: brew upgrade keyspoor
```

### 0.1.4 publication verification — 2026-10-08

[Release workflow](https://github.com/majiayu000/keyspoor/actions/runs/37753455879)
passed all 20 jobs: three-platform tests/package checks, MSRV/lints, five native
builds, npm assembly and publication, crates.io publication, fresh registry
installation, GitHub release, MCP Registry metadata, maintained `v1` update and
three public Action consumers. Release commit and `v1` are
`5290c044fea2a0e3bb9d1295780dc28e6753cbcc`.

The [GitHub release](https://github.com/majiayu000/keyspoor/releases/tag/v0.1.4),
exact npm/crates.io version endpoints and public MCP Registry all confirm 0.1.4.
An independent fresh npm install passed exits 0/1/2 and redaction locally; its
three snapshot scans returned 33/0/28 findings, complete with zero errors, and
exactly the candidate's source locations. The native demo and old-baseline
rejection/new-baseline acceptance also passed.

[Homebrew update](https://github.com/majiayu000/homebrew-tap/actions/runs/37754483344)
passed installation, test and strict audit, and its public formula points to
0.1.4 assets. [Pages deployment](https://github.com/majiayu000/keyspoor/actions/runs/37754494174)
passed; the live homepage is byte-identical to the versioned site source and
shows the new release and correction results. These checks do not establish
new external users, search ranking or active credential validity.

## v0.1.3 release notes

Keyspoor now has a complete first-use path: a pinned npm demo with expected
redacted output, setup guides for Codex, Claude Code and Cursor, and a copyable
PR/push workflow that retains reports after failed scans. A native staged Git
hook and reviewed local-baseline examples explain how to introduce scanning
into existing repositories.

The MCP concurrency test no longer assumes filesystem work remains active
long enough for a ping to be one of the first two responses. Dispatch behavior
is checked with a held job queue; the real-process test permits legitimate
completion/cancellation ordering. Scanner production behavior is unchanged.

Release automation now publishes MCP Registry metadata using GitHub OIDC,
advances the maintained `v1` scanner Action after package publication, and
checks that public Action on Linux, macOS and Windows. npm registry verification
waits for newly published versions to become visible.

Install the native CLI:

```sh
npm install -g keyspoor@0.1.3
# Or: brew install majiayu000/tap/keyspoor
# Or: cargo install keyspoor --version 0.1.3 --locked
```

Start with the [Agent setup guide](https://github.com/majiayu000/keyspoor/blob/main/docs/AGENT_SETUP.md)
or [complete CI setup](https://github.com/majiayu000/keyspoor/blob/main/docs/CI_SETUP.md).
Google API Key example literals inherited from the Gitleaks allowlist remain
unchanged; their Firebase example provenance is now documented. They are not
scanner authentication settings and their present validity has not been checked.
