# Releasing Keyspoor

Push a full version tag to publish GitHub binaries, npm and crates.io through
[release.yml](../.github/workflows/release.yml). No local `npm login`, browser
confirmation or stored registry token is needed for this workflow. Both
registries must have a trusted publisher configured for repository
`majiayu000/keyspoor`, workflow `release.yml`, with no environment name.

Update `Cargo.toml`, `Cargo.lock` and `npm/package.json` together, commit the
change, then push the release commit and tag:

```sh
git push origin main
git tag v0.1.2
git push origin v0.1.2
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
so a failed installation can be retried without republishing. Cargo publishes
with `--locked`. The GitHub release is created after both registry jobs succeed.
It includes the same npm tarball, five binaries, license files and `SHA256SUMS`.

| Target | Asset for v0.1.2 | Native runner |
|---|---|---|
| Linux x64, glibc | `keyspoor-v0.1.2-x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| Linux ARM64, glibc | `keyspoor-v0.1.2-aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| macOS Intel | `keyspoor-v0.1.2-x86_64-apple-darwin` | `macos-15-intel` |
| macOS Apple Silicon | `keyspoor-v0.1.2-aarch64-apple-darwin` | `macos-15` |
| Windows x64 | `keyspoor-v0.1.2-x86_64-pc-windows-msvc.exe` | `windows-2025` |

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
