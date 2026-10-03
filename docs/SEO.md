# Keyspoor publication and discoverability

Verified on 2026-10-04 (Asia/Shanghai). Product identity: **Keyspoor**, an offline
Rust secret scanner for Git, CI and AI agents. `key` + `spoor` describes tracing
credential footprints. Distribution decisions are recorded in [DECISIONS.md](DECISIONS.md).

## Public surfaces

| Surface | Result | Evidence |
|---|---|---|
| GitHub | Public repository, description, homepage and 12 relevant topics configured | [Repository](https://github.com/majiayu000/keyspoor) |
| GitHub Release | v0.1.2 published; five native targets, npm tarball, license notices and checksums; every public asset hash verified | [Release](https://github.com/majiayu000/keyspoor/releases/tag/v0.1.2) |
| crates.io | 0.1.2 published by GitHub Actions using a temporary OIDC token; registry API verified | [Crate](https://crates.io/crates/keyspoor) |
| Rust API docs | Version 0.1.2 returns HTTP 200 | [docs.rs](https://docs.rs/keyspoor/0.1.2/keyspoor/) |
| npm registry | 0.1.2 published through OIDC with provenance; fresh registry install passes exits 0/1/2 and redaction on Linux CI and local macOS | [npm package](https://www.npmjs.com/package/keyspoor) |
| npm provenance | Registry attestation identifies this repository, release.yml and refs/tags/v0.1.2 | [Attestation](https://registry.npmjs.org/-/npm/v1/attestations/keyspoor@0.1.2) |
| Scanning Action | v1 points to the release commit; Linux, macOS and Windows public consumers pass exits 0/1/2, failure semantics, SARIF and redaction | [Action verification](https://github.com/majiayu000/keyspoor/actions/runs/37152835692) |
| Homebrew | 0.1.2 formula automatically committed; tap CI and local upgrade, brew test and strict audit pass | [Update run](https://github.com/majiayu000/homebrew-tap/actions/runs/37152837292) · [Formula commit](https://github.com/majiayu000/homebrew-tap/commit/ffbf3c27d064597a38576b6e224895d446547664) |
| Project homepage | HTTP 200; live v0.1.2 content, Homebrew installation and scanning Action verified | [Website](https://majiayu000.github.io/keyspoor/) |
| Search Console / Google indexing | **Unverified**; no authenticated property access or indexing submission performed | Crawlable content is not proof of indexing or ranking |

Release commit: `6bce73fa5e9b20dd8510821ac50277d8ab23b9ab`.
The [release workflow](https://github.com/majiayu000/keyspoor/actions/runs/37151811766)
passed three-platform CI, Linux GNU x64/ARM64, macOS x64/ARM64 and Windows x64
native builds, packaging, both registry publications and the GitHub release.
The first registry installation check ran before npm made the accepted package
visible and failed with ETARGET. Rerunning only failed jobs after visibility
completed the release; no package was republished. The next-release workflow
now waits up to ten minutes for exact-version visibility, retrying only 404.
This wait passed focused checks; it was added after the v0.1.2 tag.

Published crate SHA-256:
`28b0dcd79fc04cbf1bb25f84d184ee5032b02bfd1305c0d56670732bcacec9a2`.
GitHub and npm registry tarballs are byte-identical, 8,959,656 bytes, SHA-256:
`14c99943c2d0277296502c13a526718482ab0d672ce93a247c6d7115b2fd5c9a`.
All five binaries, tarball and license notices match the public `SHA256SUMS`.

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
