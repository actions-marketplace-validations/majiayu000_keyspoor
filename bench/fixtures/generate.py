#!/usr/bin/env python3
"""Generate offline, deterministic scanner inputs and byte-span ground truth.

All credentials are fabricated format candidates, never evidence of live keys.
No detector implementation or detector output is consulted by this generator.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import random
import string
import subprocess
import tarfile
import tempfile
import zipfile

SEED = 104729
ALNUM = string.ascii_letters + string.digits


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Corpus:
    def __init__(self, root: Path):
        self.root = root
        self.rng = random.Random(SEED)
        self.entries: list[dict] = []
        self.datasets: dict[str, dict] = {}

    def token(self, size: int, alphabet: str = ALNUM) -> str:
        return "".join(self.rng.choice(alphabet) for _ in range(size))

    def write(self, path: str, data: str | bytes) -> bytes:
        data = data.encode("utf-8") if isinstance(data, str) else data
        dest = self.root / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return data

    def mark(self, path: str, data: bytes, candidate: str | bytes, *,
             provider: str, group: str, case: str, label: str = "positive",
             dataset: str = "quality", purpose: str = "static-format-detection",
             revision: str | None = None) -> None:
        candidate = candidate.encode("utf-8") if isinstance(candidate, str) else candidate
        start = data.index(candidate)
        entry = dict(id=f"{dataset}-{len(self.entries):05d}", path=path,
                     start=start, end=start + len(candidate), label=label,
                     provider=provider, group=group, case=case, dataset=dataset,
                     purpose=purpose, sha256=digest(candidate),
                     line=data[:start].count(b"\n") + 1,
                     end_line=data[:start + len(candidate)].count(b"\n") + 1)
        entry["class"] = ("benign" if label == "negative" else
                          "context-dependent" if group == "generic" else "credential-format")
        if revision is not None:
            entry["revision"] = revision
        self.entries.append(entry)

    def providers(self) -> dict[str, str]:
        # Independent public credential format families, not rules copied from our scanner.
        return {
            "aws-access-key": "AKIA" + self.token(16, string.ascii_uppercase + string.digits),
            "github-pat": "ghp_" + self.token(36),
            "gitlab-pat": "glpat-" + self.token(20, ALNUM + "-_"),
            "slack-bot": "xoxb-" + self.token(12, string.digits) + "-" + self.token(12, string.digits) + "-" + self.token(24),
            "stripe-secret": "sk_live_" + self.token(24),
            "google-api": "AIza" + self.token(35, ALNUM + "-_"),
            "sendgrid-api": "SG." + self.token(22, ALNUM + "-_") + "." + self.token(43, ALNUM + "-_"),
            "npm-token": "npm_" + self.token(36),
            "twilio-api": "SK" + self.token(32, "0123456789abcdef"),
        }

    def quality(self) -> None:
        self.datasets["quality"] = {"path": "quality", "mode": "fs"}
        for provider, candidate in self.providers().items():
            for case, prefix, suffix in (
                ("quoted", 'credential = "', '"\n'),
                ("unicode", '# 部署配置 🧪\ncredential = "', '"\n'),
                ("crlf", '# configuration\r\ncredential = "', '"\r\n'),
            ):
                path = f"quality/common/{provider}-{case}.conf"
                data = self.write(path, prefix + candidate + suffix)
                self.mark(path, data, candidate, provider=provider, group="common", case=case)

        generic_cases = [
            ("password-assignment", "database_password", self.token(30), ' = "', '"\n'),
            ("api-key-json", '"api_key"', self.token(40), ': "', '"\n'),
            ("secret-yaml", "client_secret", self.token(32), ': "', '"\n'),
            ("multiline-assignment", "api_key", self.token(40), ' =\n    "', '"\n'),
            ("unicode-value", "database_password", "密钥" + self.token(28), ' = "', '"\n'),
            ("unquoted-env", "DATABASE_PASSWORD", self.token(32), '=', '\n'),
            ("password-uri", "dsn", self.token(24), ' = "postgres://operator:', '@localhost:5432/app"\n'),
        ]
        for case, name, candidate, middle, suffix in generic_cases:
            path = f"quality/generic/{case}.conf"
            data = self.write(path, name + middle + candidate + suffix)
            self.mark(path, data, candidate, provider="generic", group="generic", case=case,
                      purpose="context-dependent-secret-candidate")

        negative_cases = [
            ("placeholder", 'api_key = "', "YOUR_API_KEY_HERE", '"\n'),
            ("redacted", 'password = "', "[REDACTED]", '"\n'),
            ("env-reference", 'api_key = "', "${SERVICE_API_KEY}", '"\n'),
            ("process-env", "api_key = ", "process.env.SERVICE_API_KEY", ";\n"),
            ("sha256", 'sha256 = "', digest(b"public build artifact"), '"\n'),
            ("uuid", 'request_id = "', "e5506923-0474-4a66-969c-58f073a9dd6d", '"\n'),
            ("hex-color", 'color = "', "#a1b2c3", '"\n'),
            ("public-key", "", "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(bytes(range(64))).decode() + "\n-----END PUBLIC KEY-----", "\n"),
            ("public-url", 'homepage = "', "https://example.invalid/docs?version=2026", '"\n'),
            ("example-password", 'password = "', "changeme", '"\n'),
        ]
        for case, prefix, candidate, suffix in negative_cases:
            path = f"quality/negative/{case}.conf"
            data = self.write(path, prefix + candidate + suffix)
            self.mark(path, data, candidate, provider="none", group="negative", case=case,
                      label="negative", purpose="false-positive-control")

    def capabilities(self) -> None:
        self.datasets["capabilities"] = {"path": "capabilities", "mode": "fs"}
        candidate = self.providers()["github-pat"]
        payload = ('credential = "' + candidate + '"\n').encode()
        # Keep these out of primary plaintext recall: each requires separate capabilities.
        for case, data, needle in (
            ("base64", base64.b64encode(payload), base64.b64encode(payload)),
            ("utf16le", b"\xff\xfe" + payload.decode().encode("utf-16le"), candidate.encode("utf-16le")),
            ("read-boundary", b" " * 65528 + candidate.encode() + b"\n", candidate.encode()),
            ("nul-prefix", b"\x00\x00" + payload, candidate.encode()),
            ("no-final-newline", payload.rstrip(b"\n"), candidate.encode()),
        ):
            path = f"capabilities/{case}.dat"
            data = self.write(path, data)
            self.mark(path, data, needle, provider="github-pat", group="capability", case=case,
                      dataset="capabilities", purpose="encoded-or-boundary-feature-probe")
        private_key = ("-----BEGIN PRIVATE KEY-----\n" +
                       base64.b64encode(bytes(self.rng.randrange(256) for _ in range(96))).decode() +
                       "\n-----END PRIVATE KEY-----\n").encode()
        path = "capabilities/private-key.pem"
        self.write(path, private_key)
        self.mark(path, private_key, private_key.rstrip(), provider="private-key",
                  group="capability", case="pem-envelope", dataset="capabilities",
                  purpose="synthetic-pem-envelope-not-valid-cryptographic-key")
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo("nested/config.conf", (2000, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
        self.write("capabilities/archive.zip", zipped.getvalue())
        tarred = io.BytesIO()
        with tarfile.open(fileobj=tarred, mode="w") as archive:
            info = tarfile.TarInfo("nested/config.conf")
            info.size = len(payload)
            info.mtime = 946684800
            archive.addfile(info, io.BytesIO(payload))
        self.write("capabilities/archive.tar.gz", gzip.compress(tarred.getvalue(), mtime=0))
        self.datasets["capabilities"]["archives"] = [
            {"path": "capabilities/archive.zip", "member": "nested/config.conf", "provider": "github-pat", "candidate_sha256": digest(candidate.encode())},
            {"path": "capabilities/archive.tar.gz", "member": "nested/config.conf", "provider": "github-pat", "candidate_sha256": digest(candidate.encode())},
        ]

    def throughput(self, sizes: list[int]) -> None:
        for size in sizes:
            dataset = f"throughput-{size}mib"
            directory = f"throughput/{size}mib"
            remaining = size * 1024 * 1024
            self.datasets[dataset] = {"path": directory, "mode": "fs", "bytes": remaining,
                                      "content": "deterministic-repetitive-source-like-text",
                                      "warm_cache_expected": True}
            index = 0
            while remaining:
                length = min(256 * 1024, remaining)
                line = (f'const route_{index} = {{ method: "GET", path: "/products", retries: 3 }};\n').encode()
                data = (line * ((length + len(line) - 1) // len(line)))[:length]
                candidate = None
                if index % 4 == 0:
                    candidate = "ghp_" + self.token(36)
                    trailer = ('\ncredential = "' + candidate + '"\n').encode()
                    data = data[:-len(trailer)] + trailer
                path = f"{directory}/source-{index:05d}.js"
                self.write(path, data)
                if candidate:
                    self.mark(path, data, candidate, provider="github-pat", group="throughput",
                              case="sparse-injection", dataset=dataset, purpose="throughput-recall-sanity")
                remaining -= length
                index += 1
            self.datasets[dataset]["files"] = index

    def git(self) -> None:
        repo = self.root / "git-repo"
        repo.mkdir()
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_AUTHOR_NAME="Synthetic Corpus", GIT_COMMITTER_NAME="Synthetic Corpus",
                   GIT_AUTHOR_EMAIL="corpus@example.invalid", GIT_COMMITTER_EMAIL="corpus@example.invalid",
                   GIT_AUTHOR_DATE="2000-01-01T00:00:00+00:00", GIT_COMMITTER_DATE="2000-01-01T00:00:00+00:00")

        def git(*args: str) -> str:
            return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args],
                                  cwd=repo, env=env, check=True, capture_output=True, text=True).stdout.strip()

        git("init", "-q", "--initial-branch=main")
        self.write("git-repo/config.conf", "service = catalog\n")
        git("add", "config.conf")
        git("commit", "-qm", "Initial public configuration")
        historical = "ghp_" + self.token(36)
        data = self.write("git-repo/config.conf", f'credential = "{historical}"\n')
        git("add", "config.conf")
        git("commit", "-qm", "Add fabricated credential candidate")
        revision = git("rev-parse", "HEAD")
        self.mark("git-repo/config.conf", data, historical, provider="github-pat", group="history",
                  case="deleted-from-head", dataset="git_history", revision=revision)
        self.write("git-repo/config.conf", "service = catalog\n")
        self.write("git-repo/partial.conf", "service = inventory\n")
        git("add", "config.conf", "partial.conf")
        git("commit", "-qm", "Remove candidate and add public configuration")
        staged = "ghp_" + self.token(36)
        staged_data = self.write("git-repo/partial.conf", f'credential = "{staged}"\n')
        git("add", "partial.conf")
        self.mark("git-repo/partial.conf", staged_data, staged, provider="github-pat", group="staged",
                  case="index-only-candidate", dataset="staged", revision=":index")
        unstaged = "ghp_" + self.token(36)
        # Distinct location also proves index-vs-worktree selection for redacted
        # scanner output, where comparing the two different values is impossible.
        data = self.write("git-repo/partial.conf", f'# Worktree-only edit after staging\n\ncredential = "{unstaged}"\n')
        self.mark("git-repo/partial.conf", data, unstaged, provider="github-pat", group="worktree",
                  case="worktree-only-candidate", dataset="git_worktree")
        self.datasets.update({"git_history": {"path": "git-repo", "mode": "git", "commits": 3},
                              "staged": {"path": "git-repo", "mode": "staged"},
                              "git_worktree": {"path": "git-repo", "mode": "fs"}})

    def finish(self) -> dict:
        manifest = {"schema_version": 1, "seed": SEED, "synthetic": True,
                    "network_verification_allowed": False,
                    "ground_truth": "format candidates; no credential is known or intended to be active",
                    "offset_unit": "byte", "span_convention": "half-open",
                    "datasets": self.datasets, "entries": self.entries}
        self.write("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        return manifest


def generate(root: Path, sizes: list[int], with_git: bool = True) -> dict:
    if root.exists() and any(root.iterdir()):
        raise ValueError(f"output directory must be empty: {root}")
    if any(size <= 0 for size in sizes) or len(set(sizes)) != len(sizes):
        raise ValueError("sizes must be distinct positive MiB values")
    root.mkdir(parents=True, exist_ok=True)
    corpus = Corpus(root)
    corpus.quality()
    corpus.capabilities()
    corpus.throughput(sizes)
    if with_git:
        corpus.git()
    return corpus.finish()


def validate(root: Path, manifest: dict) -> None:
    """Validate labels against original bytes, index contents, and committed history."""
    seen = set()
    for item in manifest["entries"]:
        assert item["id"] not in seen
        seen.add(item["id"])
        revision = item.get("revision")
        if revision:
            relative = str(Path(item["path"]).relative_to("git-repo"))
            spec = f":{relative}" if revision == ":index" else f"{revision}:{relative}"
            data = subprocess.run(["git", "show", spec], cwd=root / "git-repo", check=True, capture_output=True).stdout
        else:
            data = (root / item["path"]).read_bytes()
        assert 0 <= item["start"] < item["end"] <= len(data), item["id"]
        assert digest(data[item["start"]:item["end"]]) == item["sha256"], item["id"]
        assert data[:item["start"]].count(b"\n") + 1 == item["line"]
    for dataset in manifest["datasets"].values():
        if "bytes" in dataset:
            files = list((root / dataset["path"]).iterdir())
            assert sum(path.stat().st_size for path in files) == dataset["bytes"]
            assert len(files) == dataset["files"]
    with zipfile.ZipFile(root / "capabilities/archive.zip") as archive:
        zipped = archive.read("nested/config.conf")
    with tarfile.open(root / "capabilities/archive.tar.gz") as archive:
        assert archive.extractfile("nested/config.conf").read() == zipped


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="secret-corpus-") as temp:
        first, second = Path(temp) / "first", Path(temp) / "second"
        m1, m2 = generate(first, [1]), generate(second, [1])
        validate(first, m1)
        validate(second, m2)
        assert m1 == m2, "manifest and Git revisions must be deterministic"
        for path in first.rglob("*"):
            if path.is_file() and ".git" not in path.parts:
                assert path.read_bytes() == (second / path.relative_to(first)).read_bytes()
        try:
            generate(first, [1])
        except ValueError:
            pass
        else:
            raise AssertionError("must reject nonempty output directory")
        assert sum(e["group"] == "common" for e in m1["entries"]) == 27
        assert sum(e["label"] == "negative" for e in m1["entries"]) == 10
        staged = next(e for e in m1["entries"] if e["dataset"] == "staged")
        worktree = next(e for e in m1["entries"] if e["dataset"] == "git_worktree")
        assert staged["line"] != worktree["line"]
        assert staged["start"] != worktree["start"]
        print(f"PASS: deterministic corpus, {len(m1['entries'])} valid byte spans, archives, Git history/index/worktree, exact 1 MiB")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "generated")
    parser.add_argument("--sizes", default="1,16,128", help="comma-separated throughput sizes in MiB; empty skips")
    parser.add_argument("--no-git", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    sizes = [int(size) for size in args.sizes.split(",") if size]
    manifest = generate(args.output.resolve(), sizes, not args.no_git)
    validate(args.output.resolve(), manifest)
    print(json.dumps({"output": str(args.output.resolve()), "entries": len(manifest["entries"]),
                      "datasets": list(manifest["datasets"]), "validated": True}))


if __name__ == "__main__":
    main()
