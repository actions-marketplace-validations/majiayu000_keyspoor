#!/usr/bin/env python3
"""Import pinned MIT Gitleaks rule data, never its scanning implementation."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib
import urllib.request

COMMIT = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
CONFIG_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
LICENSE_SHA256 = "e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6"
BASE = f"https://raw.githubusercontent.com/gitleaks/gitleaks/{COMMIT}/"
ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {
    "pkcs12-file": "path-only rule has no content regex; current findings require a byte span",
}


def source(name: str, expected: str, directory: Path | None) -> bytes:
    data = ((directory / name.replace("/", "_")).read_bytes() if directory else
            urllib.request.urlopen(BASE + name, timeout=30).read())
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError(f"pinned {name} SHA-256 mismatch: {actual}")
    return data


def rust_pattern(pattern: str) -> str:
    """Escape Go literal braces; leave quantifiers, classes, and flags intact."""
    out, index, in_class = [], 0, False
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            out.append(pattern[index:index + 2])
            index += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        if not in_class and char == "{":
            quantifier = re.match(r"\{\d+(?:,\d*)?\}", pattern[index:])
            if quantifier:
                out.append(quantifier.group())
                index += len(quantifier.group())
                continue
            out.append(r"\{")
        elif not in_class and char == "}":
            out.append(r"\}")
        else:
            out.append(char)
        index += 1
    return "".join(out)


def allowlist(config: dict) -> dict:
    supported = {"description", "condition", "regexTarget", "regexes", "stopwords", "paths"}
    if set(config) - supported:
        raise ValueError(f"unsupported allowlist fields: {set(config) - supported}")
    condition = config.get("condition", "OR").upper()
    if condition in {"", "OR", "||"}:
        condition = "or"
    elif condition in {"AND", "&&"}:
        condition = "and"
    else:
        raise ValueError(f"unsupported allowlist condition: {condition}")
    target = config.get("regexTarget") or "secret"
    if target not in {"secret", "match", "line"}:
        raise ValueError(f"unsupported allowlist target: {target}")
    # Keep groups and targets intact. Stopwords always inspect the captured
    # secret, even when the group's regex target is the match or source line.
    return {"condition": condition, "target": target,
            "regexes": [rust_pattern(pattern) for pattern in config.get("regexes", [])],
            "paths": [rust_pattern(pattern) for pattern in config.get("paths", [])],
            "stopwords": config.get("stopwords", [])}


def convert(config: dict) -> dict:
    global_allow = allowlist(config["allowlist"])
    rules = []
    observed_exclusions = set()
    supported = {"id", "description", "regex", "keywords", "entropy", "allowlists", "path", "secretGroup"}
    for upstream in config["rules"]:
        identity = upstream["id"]
        if identity in EXCLUDED:
            observed_exclusions.add(identity)
            continue
        if set(upstream) - supported:
            raise ValueError(f"{identity}: unsupported fields {set(upstream) - supported}")
        groups = [global_allow] + [allowlist(item) for item in upstream.get("allowlists", [])]
        # Gitleaks omitted/zero secretGroup selects the first nonempty capture;
        # our null represents that behavior (our explicit zero means whole match).
        group = upstream.get("secretGroup") or None
        rules.append({"id": identity, "name": upstream["description"],
                      "pattern": rust_pattern(upstream["regex"]), "secret_group": group,
                      "keywords": upstream.get("keywords", []),
                      "min_entropy": upstream.get("entropy", 0),
                      "confidence": "medium", "path": rust_pattern(upstream["path"]) if "path" in upstream else None,
                      "allowlist": groups, "exclude_paths": []})
    if observed_exclusions != set(EXCLUDED):
        raise ValueError("pinned exclusion inventory changed")
    return {"rules": rules}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, help="offline directory with config_gitleaks.toml and LICENSE")
    parser.add_argument("--check", action="store_true", help="verify generated assets instead of writing")
    args = parser.parse_args()
    raw = source("config/gitleaks.toml", CONFIG_SHA256, args.source_dir)
    license_text = source("LICENSE", LICENSE_SHA256, args.source_dir).decode()
    config = tomllib.loads(raw.decode())
    converted = convert(config)
    catalogue = json.dumps(converted, indent=2, ensure_ascii=False) + "\n"
    notices = ("Third-party rule data\n=====================\n\n"
               "src/builtin_rules.json contains transformed Gitleaks v8.30.1 rule data.\n"
               f"Source commit: {COMMIT}\n"
               f"Configuration SHA-256: {CONFIG_SHA256}\n"
               f"License SHA-256: {LICENSE_SHA256}\n"
               f"Source: {BASE}config/gitleaks.toml\n\n" + license_text)
    for path, contents in ((ROOT / "src/builtin_rules.json", catalogue), (ROOT / "THIRD_PARTY_NOTICES", notices)):
        if args.check:
            if path.read_text() != contents:
                raise ValueError(f"generated asset differs: {path}")
        else:
            path.write_text(contents)
    print(json.dumps({"upstream_rules": len(config["rules"]), "imported_rules": len(converted["rules"]),
                      "excluded": EXCLUDED, "check": args.check}, indent=2))


if __name__ == "__main__":
    main()
