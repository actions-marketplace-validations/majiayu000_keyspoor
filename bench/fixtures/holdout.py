#!/usr/bin/env python3
"""Frozen synthetic holdout, independent of scanner code and detector output.

Generate: python3 bench/fixtures/holdout.py --output bench/corpus-holdout
No network activity, scanners, real credentials, or existing fixture values are used.
Format-valid means the published *syntactic* pattern, not checksum or server validity.
The format source is shared with the scanner's rule catalogue: this is independent
values/templates, not an independent distribution or a real-world accuracy estimate.
Once measured, these inputs become regression data; do not tune then call them unseen.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
import string
import tempfile

SEED = 32416190071
SOURCE_COMMIT = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
SOURCE_URL = f"https://github.com/gitleaks/gitleaks/blob/{SOURCE_COMMIT}/config/gitleaks.toml"
SOURCE_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
URLSAFE = ALNUM + "_-"
# A segment is a literal string or (alphabet, length). These grammars are limited
# synthetic representatives of upstream formats, not copies of whole detector regexes.
FORMATS = {
    "aws-access-token": ["AKIA", (string.ascii_uppercase + "234567", 16)],
    "github-pat": ["ghp_", (ALNUM, 36)],
    "gitlab-pat": ["glpat-", (URLSAFE, 20)],
    "slack-bot-token": ["xoxb-", (string.digits, 12), "-", (string.digits, 12), "-", (ALNUM, 24)],
    "stripe-access-token": ["sk_live_", (ALNUM, 32)],
    "sendgrid-api-token": ["SG.", (URLSAFE, 22), ".", (URLSAFE, 43)],
    "npm-access-token": ["npm_", (ALNUM, 36)],
    "twilio-api-key": ["SK", (HEX, 32)],
    "digitalocean-pat": ["dop_v1_", (HEX, 64)],
    "doppler-api-token": ["dp.pt.", (ALNUM, 43)],
    "huggingface-access-token": ["hf_", (string.ascii_letters, 34)],
    "linear-api-key": ["lin_api_", (ALNUM, 40)],
    "postman-api-token": ["PMAK-", (HEX, 24), "-", (HEX, 34)],
    "pulumi-api-token": ["pul-", (HEX, 40)],
    "shopify-access-token": ["shpat_", (HEX, 32)],
    "databricks-api-token": ["dapi", (HEX, 32)],
    "anthropic-api-key": ["sk-ant-api03-", (URLSAFE, 93), "AA"],
    "planetscale-api-token": ["pscale_tkn_", (URLSAFE, 48)],
    "airtable-personnal-access-token": ["pat", (ALNUM, 14), ".", (HEX, 64)],
    "flyio-access-token": ["fo1_", (URLSAFE, 43)],
}
# Every value occurs once. Template IDs are recorded as grouping keys; keep all
# examples of an ID together if creating any future train/evaluation split.
TEMPLATES = (
    ("json-nested", '{"deployment":{"credential":"', '"},"replicas":3}\n', "json"),
    ("toml-table", '[deployment.runtime]\ncredential = "', '" # injected literal\n', "toml"),
    ("yaml-list", 'environments:\n  - credential: "', '"\n    region: west\n', "yaml"),
    ("python-call", 'client.configure(\n    credential="', '",\n    timeout=8,\n)\n', "py"),
    ("javascript-member", '// 初始化 🧭\nsettings.runtime.credential = "', '";\n', "js"),
    ("shell-export", 'export RUNTIME_CREDENTIAL="', '"\r\nprintf "%s\\n" ready\r\n', "sh"),
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def grammar(parts: list) -> str:
    return "".join(re.escape(p) if isinstance(p, str) else
                   "[" + re.escape(p[0]) + "]{" + str(p[1]) + "}" for p in parts)


class Builder:
    def __init__(self, root: Path):
        self.root = root
        self.rng = random.Random(SEED)
        self.entries = []
        self.files = []

    def token(self, size: int, alphabet: str = ALNUM) -> str:
        return "".join(self.rng.choice(alphabet) for _ in range(size))

    def add(self, *, category: str, index: int, value: str, prefix: str, suffix: str,
            template: str, extension: str, label: str, group: str, reason: str) -> None:
        path = f"quality/{group}/{category}/item-{index:03d}.{extension}"
        content = (prefix + value + suffix).encode()
        candidate = value.encode()
        start = len(prefix.encode())
        assert content[start:start + len(candidate)] == candidate
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        self.files.append({"path": path, "bytes": len(content), "sha256": sha(content)})
        self.entries.append({
            "id": f"holdout-{len(self.entries):04d}", "dataset": "quality",
            "path": path, "start": start, "end": start + len(candidate),
            "line": content[:start].count(b"\n") + 1,
            "end_line": content[:start + len(candidate)].count(b"\n") + 1,
            "sha256": sha(candidate), "value_group": sha(candidate),
            "template_group": template, "case": template, "provider": category,
            "label": label, "group": group, "label_reason": reason,
            "class": "benign" if label == "negative" else group,
            "purpose": "false-positive-control" if label == "negative" else
                       "syntactic-format-detection" if group == "format-valid" else
                       "context-dependent-secret-candidate",
        })

    def positives(self) -> None:
        for category, parts in FORMATS.items():
            for i in range(24):
                value = "".join(p if isinstance(p, str) else self.token(p[1], p[0]) for p in parts)
                assert re.fullmatch(grammar(parts), value)
                template, prefix, suffix, extension = TEMPLATES[i % len(TEMPLATES)]
                self.add(category=category, index=i, value=value, prefix=prefix, suffix=suffix,
                         template=template, extension=extension, label="positive", group="format-valid",
                         reason=f"Fabricated lexical candidate of pinned upstream {category}; no validity assertion")
        for category in ("opaque-api-key", "natural-language-password", "unicode-password", "uri-password"):
            for i in range(30):
                if category == "opaque-api-key":
                    value = self.token(28 + i % 19)
                    prefix, suffix = ('{"upstream":{"api_key":"', '"}}\n') if i % 2 else ('client_secret =\n  "', '"\n')
                    template = "generic-json-key" if i % 2 else "generic-multiline-secret"
                elif category == "natural-language-password":
                    value = f"three quiet otters guard {self.token(8, string.ascii_lowercase)}"
                    prefix, suffix, template = 'login_password = "', '"\n', "generic-passphrase"
                elif category == "unicode-password":
                    value = "通行凭证_" + self.token(20) + "_冬季"
                    prefix, suffix, template = '# 非公开登录配置\npassword: "', '"\n', "generic-unicode"
                else:
                    value = self.token(23, ALNUM + "-_")
                    prefix, suffix, template = 'dsn = "postgresql://worker:', '@db.example.invalid/app"\n', "generic-uri"
                self.add(category=category, index=i, value=value, prefix=prefix, suffix=suffix,
                         template=template, extension="conf", label="positive", group="broad-generic",
                         reason="Deliberately placed literal in authentication assignment or URI password field; format not provider-specific")

    def negatives(self) -> None:
        for category in ("artifact-digest", "request-uuid", "public-resource-url", "css-color",
                         "environment-reference", "runtime-secret-lookup", "template-expression",
                         "public-id", "catalog-description", "encoded-public-text", "redacted-log", "format-specification"):
            for i in range(25):
                name = self.token(12, string.ascii_uppercase)
                if category == "artifact-digest":
                    value, prefix, suffix = sha(f"public artifact {name}".encode()), 'artifact_sha256 = "', '"\n'
                    reason = "SHA-256 of public artifact label, not authentication material"
                elif category == "request-uuid":
                    h = self.token(32, HEX)
                    value, prefix, suffix = f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:]}", 'request_id = "', '"\n'
                    reason = "Public request correlation identifier"
                elif category == "public-resource-url":
                    value, prefix, suffix = f"https://docs.example.invalid/{name.lower()}/overview?lang=en", 'homepage = "', '"\n'
                    reason = "Public documentation URL with no credentials"
                elif category == "css-color":
                    value, prefix, suffix = "#" + self.token(6, HEX), f".{name.lower()} {{ color: ", "; }\n"
                    reason = "CSS color literal"
                elif category == "environment-reference":
                    value, prefix, suffix = "${RUNTIME_" + name + "}", 'api_key = "', '"\n'
                    reason = "Unexpanded environment variable reference, not its value"
                elif category == "runtime-secret-lookup":
                    value, prefix, suffix = f'process.env.RUNTIME_{name}', 'const api_key = ', ';\n'
                    reason = "Runtime environment lookup expression, no literal credential"
                elif category == "template-expression":
                    value, prefix, suffix = "{{ secrets." + name.lower() + " }}", 'client_secret: "', '"\n'
                    reason = "Template reference to secret storage, not secret content"
                elif category == "public-id":
                    value, prefix, suffix = self.token(32), 'public_asset_id = "', '"\n'
                    reason = "Opaque public asset identifier generated independently of authentication"
                elif category == "catalog-description":
                    value, prefix, suffix = f"Reports exposed service credentials in configuration category {name.lower()}", '{"service-api-key": "', '"}\n'
                    reason = "Human-readable rule catalogue description, no authentication assignment"
                elif category == "encoded-public-text":
                    value = base64.b64encode(f"Published changelog for module {name.lower()}: fixed rendering.".encode()).decode()
                    prefix, suffix, reason = 'public_changelog_base64 = "', '"\n', "Base64 encoding of explicitly public prose"
                elif category == "redacted-log":
                    value, prefix, suffix = "[REDACTED]", f'# request {name}\npassword = "', '"\n'
                    reason = "Fixed redaction marker; request context varies but marker repeats intentionally"
                else:
                    value, prefix, suffix = f"the credential contains {20 + i} characters and a service prefix {name.lower()}", 'description = "', '"\n'
                    reason = "Prose describing a credential format, not a credential value"
                self.add(category=category, index=i, value=value, prefix=prefix, suffix=suffix,
                         template="negative-" + category, extension="txt", label="negative", group="negative", reason=reason)


def validate(root: Path, manifest: dict) -> None:
    """Check actual stored bytes and frozen labels without running a detector."""
    seen_ids, seen_paths, positive_values, negative_values = set(), set(), set(), set()
    for entry in manifest["entries"]:
        assert entry["id"] not in seen_ids
        seen_ids.add(entry["id"])
        path = Path(entry["path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert path.as_posix() not in seen_paths
        seen_paths.add(path.as_posix())
        data = (root / path).read_bytes()
        start, end = entry["start"], entry["end"]
        assert 0 <= start < end <= len(data)
        candidate = data[start:end]
        assert sha(candidate) == entry["sha256"] == entry["value_group"]
        assert data[:start].count(b"\n") + 1 == entry["line"]
        assert data[:end].count(b"\n") + 1 == entry["end_line"]
        if entry["label"] == "positive":
            assert candidate not in positive_values, "Positive values must not be reused across contexts"
            positive_values.add(candidate)
            if entry["group"] == "format-valid":
                assert re.fullmatch(grammar(FORMATS[entry["provider"]]), candidate.decode())
        else:
            assert entry["label"] == "negative"
            negative_values.add(candidate)
    assert not positive_values.intersection(negative_values)
    for entry in manifest["entries"]:
        if entry["label"] == "negative":
            data = (root / entry["path"]).read_bytes()
            assert not any(value in data for value in positive_values), "Positive candidate embedded in negative file"
    assert len(positive_values) == 600
    assert Counter(e["label"] for e in manifest["entries"]) == {"positive": 600, "negative": 300}
    assert Counter(e["group"] for e in manifest["entries"]) == {"format-valid": 480, "broad-generic": 120, "negative": 300}
    assert {f["path"] for f in manifest["files"]} == seen_paths
    for item in manifest["files"]:
        data = (root / item["path"]).read_bytes()
        assert sha(data) == item["sha256"] and len(data) == item["bytes"]
    assert sha(json_bytes(manifest["files"])) == manifest["corpus_sha256"]


def generate(root: Path) -> dict:
    if root.exists() and any(root.iterdir()):
        raise ValueError("output directory must be empty")
    root.mkdir(parents=True, exist_ok=True)
    builder = Builder(root)
    builder.positives()
    builder.negatives()
    files = sorted(builder.files, key=lambda item: item["path"])
    manifest = {
        "schema_version": 1, "seed": SEED, "synthetic": True,
        "network_verification_allowed": False, "offset_unit": "byte", "span_convention": "half-open",
        "ground_truth": "Fabricated syntax candidates and explicit semantic negatives; no known or intended active credentials",
        "evaluation_status": "frozen before first scanner evaluation; subsequent tuning makes it regression data",
        "limitations": ["Format source shares ancestry with tested rule catalogue",
                        "Syntactic validity does not establish cryptographic/checksum/server validity",
                        "Synthetic mixture is not representative production prevalence",
                        "Value and template grouping keys must be respected in any future split"],
        "sources": [{"url": SOURCE_URL, "commit": SOURCE_COMMIT, "sha256": SOURCE_SHA256,
                     "license": "MIT", "rule_ids": list(FORMATS),
                     "verified": "pinned upstream raw bytes hash-checked before generator implementation"}],
        "generator_sha256": sha(Path(__file__).read_bytes()),
        "corpus_sha256": sha(json_bytes(files)), "files": files,
        "datasets": {"quality": {"path": "quality", "mode": "fs", "files": len(files),
                                  "bytes": sum(f["bytes"] for f in files),
                                  "content": "independent-synthetic-holdout-600-positive-300-negative"}},
        "entries": builder.entries,
    }
    validate(root, manifest)
    (root / "manifest.json").write_bytes(json_bytes(manifest))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp) / "a", Path(temp) / "b"
            generate(a)
            generate(b)
            assert (a / "manifest.json").read_bytes() == (b / "manifest.json").read_bytes()
            print("Holdout self-check passed: 600 unique positive values, 300 negative positions, deterministic bytes")
    elif args.output:
        manifest = generate(args.output)
        print(json.dumps({"generator_sha256": manifest["generator_sha256"],
                          "corpus_sha256": manifest["corpus_sha256"],
                          "manifest_sha256": sha((args.output / "manifest.json").read_bytes()),
                          "positive": 600, "negative": 300}, indent=2))
    else:
        parser.error("supply --output or --self-test")


if __name__ == "__main__":
    main()
