# Releasing Keyspoor

The release workflow builds native CLI binaries when a `v*` tag is pushed. It
does not publish to npm or crates.io; those registries are separate release steps.

Before tagging, update the Cargo and npm package versions together, run the
repository checks, and wait for CI on the release commit. Then push the tag:

```sh
git tag v0.1.1
git push origin v0.1.1
gh run list --workflow release.yml
```

Each native build runs `cargo +stable build --release --locked --target ...`
and checks that `keyspoor --version` matches the tag. After all five builds
succeed, the workflow creates a GitHub release with these raw binary assets:

| Target | Asset for v0.1.1 | Native runner |
|---|---|---|
| Linux x64, glibc | `keyspoor-v0.1.1-x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| Linux ARM64, glibc | `keyspoor-v0.1.1-aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| macOS Intel | `keyspoor-v0.1.1-x86_64-apple-darwin` | `macos-15-intel` |
| macOS Apple Silicon | `keyspoor-v0.1.1-aarch64-apple-darwin` | `macos-15` |
| Windows x64 | `keyspoor-v0.1.1-x86_64-pc-windows-msvc.exe` | `windows-2025` |

`LICENSE` and `THIRD_PARTY_NOTICES` accompany the binaries.
`SHA256SUMS` contains SHA-256 hashes of those five binaries and license files. On Linux, downloaded
files can be checked with `sha256sum --check SHA256SUMS`; on macOS, use
`shasum -a 256 --check SHA256SUMS`. After downloading a Unix binary, mark it
executable with `chmod +x`, then run `--version` before installation.

The Linux artifacts are dynamically linked glibc binaries built on Ubuntu
24.04. They do not target Alpine/musl or promise compatibility with older glibc
systems. Build from source on platforms outside the published target set.

Runner labels follow [GitHub's hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Official artifact actions are pinned to commits. Only the final release job has
`contents: write`, using the workflow's temporary GitHub token. Registry
credentials are not required by this workflow.

## npm assembly

Download the release files to a fresh directory, verify `SHA256SUMS`, then run:

```sh
node npm/scripts/stage.mjs /path/to/release-assets
npm test --prefix npm
npm pack --dry-run --json ./npm
npm pack ./npm --pack-destination /path/to/release-assets
```

Verify the tarball contains five real native binaries, then install it in a
temporary prefix and test `--version`, scan exits 0/1/2 and redaction. Upload
the verified `.tgz` to the corresponding GitHub release. For registry
publication, authenticate locally with `npm login`, then publish that exact
tarball with `npm publish /path/to/keyspoor-0.1.1.tgz --access public`. Verify
`npm view keyspoor` and a clean registry install before replacing pending
publication notices with registry installation commands. Never commit tokens.
