# Keyspoor publication and discoverability

Verified on 2026-10-04 (Asia/Shanghai). Product identity: **Keyspoor**, an offline
Rust secret scanner for Git, CI and AI agents. `key` + `spoor` describes tracing
credential footprints. Distribution decisions are recorded in [DECISIONS.md](DECISIONS.md).

## Public surfaces

| Surface | Result | Evidence |
|---|---|---|
| GitHub | Public repository, description, homepage and 12 relevant topics configured | [Repository](https://github.com/majiayu000/keyspoor) |
| GitHub Release | v0.1.3 published; five native targets, npm tarball, license notices and checksums; every public asset hash verified | [Release](https://github.com/majiayu000/keyspoor/releases/tag/v0.1.3) |
| crates.io | 0.1.3 published by GitHub Actions using a temporary OIDC token; registry API verified | [Crate](https://crates.io/crates/keyspoor) |
| Rust API docs | 0.1.3 URL returned HTTP 404 at verification time; publication/build visibility pending | [docs.rs](https://docs.rs/keyspoor/0.1.3/keyspoor/) |
| npm registry | 0.1.3 published through OIDC with provenance; fresh registry install passes exits 0/1/2 and redaction on Linux CI and local macOS | [npm package](https://www.npmjs.com/package/keyspoor) |
| npm provenance | Registry attestation identifies this repository, release.yml and refs/tags/v0.1.3 | [Attestation](https://registry.npmjs.org/-/npm/v1/attestations/keyspoor@0.1.3) |
| Scanning Action | v1 points to the release commit; Linux, macOS and Windows public consumers pass exits 0/1/2, failure semantics, SARIF and redaction | [Action verification](https://github.com/majiayu000/keyspoor/actions/runs/37183934247) |
| Homebrew | 0.1.3 formula automatically committed; official local upgrade, brew test and strict audit passed after authenticating release metadata queries | [Update run](https://github.com/majiayu000/homebrew-tap/actions/runs/37184919966) · [Formula commit](https://github.com/majiayu000/homebrew-tap/commit/68592110af2e11d31812ba70488f383438555d28) |
| Project homepage | HTTP 200; live v0.1.3 content, Homebrew installation and scanning Action verified | [Website](https://majiayu000.github.io/keyspoor/) |
| MCP Registry | 0.1.3 registered through GitHub OIDC; public API entry matches npm package and version | [Registry API](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.majiayu000%2Fkeyspoor) |
| GitHub Marketplace | Verified on 2026-10-05: Keyspoor secret scan v0.1.3 publicly listed in Security and Continuous integration; installation button resolves to `majiayu000/keyspoor@v0.1.3` | [Marketplace listing](https://github.com/marketplace/actions/keyspoor-secret-scan) |
| Search Console / Google indexing | **Unverified**; no authenticated property access or indexing submission performed | Crawlable content is not proof of indexing or ranking |

Release commit: `a0dc5d5b3d1ee1743fa41a75ed00228db3e5fd79`.
The [release workflow](https://github.com/majiayu000/keyspoor/actions/runs/37183934247)
passed three-platform CI, Linux GNU x64/ARM64, macOS x64/ARM64 and Windows x64
native builds, packaging, both registry publications and the GitHub release.
The first registry installation check failed with ETARGET: npm's exact-version
endpoint was visible before the installation index included 0.1.3. Rerunning
only failed jobs after install-index visibility completed the release without
republishing. Commit `983dbe15a4be7a518d7781645f182e00c8351f58` now waits up to ten
minutes for the target version in npm's abbreviated installation index. Only
404 or an index temporarily missing the version is retried; other failures
and actual CLI validation fail immediately. Focused checks, the live index
and actionlint passed.

Published crate SHA-256:
`c74acdc0ad32a3b3c624a3a57fd2720ea8a5538c0e7489e42843a3971a658c9a`.
GitHub and npm registry tarballs are byte-identical, 8,959,961 bytes, SHA-256:
`4a6e8d4125362e9e6b823f5a2220cadb0d66a73050bdaf2a065df8bda3443371`.
All five binaries, tarball and license notices match the public `SHA256SUMS`.
The installation-index fix also passed [three-platform CI](https://github.com/majiayu000/keyspoor/actions/runs/37184752250).
Registry provenance identifies this repository, release workflow, tag and
release commit. Three real public repository trials and client verification
limits are recorded in [ADOPTION.md](ADOPTION.md).

## Search surfaces implemented

- English and Chinese README introductions identify the product, inputs,
  installation channels, Rust library, CLI and MCP interface.
- Primary phrases are **Rust secret scanner**, **offline secret scanning**,
  **Git credential scanning**, and **MCP for AI agents**. They appear naturally
  in relevant text; no search-volume or ranking claims are made.
- Cargo metadata supplies repository, homepage, documentation, readme, keywords,
  categories and license. npm metadata includes repository directory, issues,
  homepage, keywords, bin entry and a package-files allowlist.
- GitHub topics cover secret-scanning, secrets-detection, credential-scanning,
  rust, security, git, devsecops, sarif, mcp, model-context-protocol, ai-agents
  and command-line.
- The static homepage has a descriptive title and meta description, canonical
  URL, Open Graph and Twitter metadata, SoftwareSourceCode JSON-LD, semantic
  headings, linked capability comparisons and benchmark evidence. Its primary
  content requires no JavaScript to crawl.
- [Sitemap](https://majiayu000.github.io/keyspoor/sitemap.xml) and
  [project robots file](https://majiayu000.github.io/keyspoor/robots.txt) return
  HTTP 200. The host-root `/robots.txt` returns 404; a project-subpath robots
  file does not replace host-root crawler policy. Page metadata is index/follow.
- Competitor and performance statements link to versioned evidence. Historical
  `secret-scan` names and binary hashes are preserved; no fastest-tool or
  production-accuracy claims were introduced.

GitHub, crates.io and npm are published; Homebrew and the reusable scanning
Action are recorded above with their installation checks.
Google indexing requires separate verification through Search Console or observed
search results; no property verification file or indexing request was invented.
