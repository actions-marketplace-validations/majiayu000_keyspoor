# Keyspoor publication and discoverability

Verified on 2026-10-04 (Asia/Shanghai). Product identity: **Keyspoor**, an offline
Rust secret scanner for Git, CI and AI agents. `key` + `spoor` describes tracing
credential footprints. Exact package-name availability checks and distribution
tradeoffs are recorded in [DECISIONS.md](DECISIONS.md).

## Public surfaces

| Surface | Result | Evidence |
|---|---|---|
| GitHub | Public repository, description, homepage and 12 relevant topics configured | [majiayu000/keyspoor](https://github.com/majiayu000/keyspoor) |
| GitHub Release | v0.1.1 published; five native targets, npm tarball, license notices and checksums | [Release](https://github.com/majiayu000/keyspoor/releases/tag/v0.1.1) |
| crates.io | 0.1.1 published, latest API version verified; fresh registry install passes clean/finding/error exits and redaction | [Crate](https://crates.io/crates/keyspoor) |
| Rust API docs | Version 0.1.1 returns HTTP 200 | [docs.rs](https://docs.rs/keyspoor/0.1.1/keyspoor/) |
| npm distribution | Real five-platform tarball, 8,959,704 bytes, installed successfully from public GitHub URL with scripts disabled | [Tarball](https://github.com/majiayu000/keyspoor/releases/download/v0.1.1/keyspoor-0.1.1.tgz) |
| npm registry | **0.1.1 published** by lifcc after browser authentication; fresh registry installation with scripts disabled passes exits 0/1/2 and redaction | [npm package](https://www.npmjs.com/package/keyspoor) |
| Project homepage | HTTP 200; v0.1.1 content verified; installation links updated to the published npm package | [Website](https://majiayu000.github.io/keyspoor/) |
| Search Console / Google indexing | **Unverified**; no authenticated property access or indexing submission performed | Crawlable content is not proof of indexing or ranking |

The Rust release commit is `eb1df810ae0368bf7f7495c3d501b21deafb30b8`.
[CI](https://github.com/majiayu000/keyspoor/actions/runs/37144648049) passed on
Linux, macOS and Windows, including package consumers and npm launcher tests.
[Release builds](https://github.com/majiayu000/keyspoor/actions/runs/37144890196)
passed for Linux GNU x64/ARM64, macOS x64/ARM64 and Windows x64. Windows CI caught
a path-separator bug before the cross-platform release; it was fixed in 0.1.1.
crates.io 0.1.0 was uploaded earlier; 0.1.1 is the corrected current version.

Published crate SHA-256:
`c5d9dec419f9065100abce1ea1f24aad5a2edb51204293269a0b8b7e68ea2fb7`.
GitHub-hosted npm tarball SHA-256:
`d189b9aaf65de5d506aede097503d3bc83146e15e4fa7f69b9eadcc11a2f1d00`.
npm registry tarball SHA-256:
`96f4efca974587b917771782a2a2edbb46a03e8b2c77327b895911f3481d0792`.
The registry tarball differs from the earlier GitHub tarball only in README
installation instructions; all five binaries, launcher and metadata match.

All release binary hashes and license files were verified against SHA256SUMS;
the tarball was added to the same checksum manifest after assembly.

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

All three distribution surfaces (GitHub, crates.io and npm) are published.
Google indexing requires separate verification through Search Console or observed
search results; no property verification file or indexing request was invented.
