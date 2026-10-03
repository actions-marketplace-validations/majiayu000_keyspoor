#!/usr/bin/env python3
"""Fresh synthetic values/contexts with repeated-value and same-line challenges.

This is a new synthetic draw, not an independent real-world distribution: format
families and broad category generators are shared with holdout.py. Never run a
scanner from this generator or tune its labels using detector output.
"""
from __future__ import annotations

import argparse
from collections import Counter
import importlib.util
from pathlib import Path
import random
import re
import tempfile

SPEC = importlib.util.spec_from_file_location("holdout_base", Path(__file__).with_name("holdout.py"))
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)
SEED = 982451653019
TEMPLATES = (
    ("v3-json-array", '{"deployments":[{"credential":"', '"},{"region":"east"}]}\n', "json"),
    ("v3-toml-array", '[[environments]]\nname = "preview"\ncredential = "', '"\n', "toml"),
    ("v3-yaml-block", 'runtime:\n  enabled: true\n  credential: "', '"\n', "yaml"),
    ("v3-python-dict", '# 运行配置 🛰️\noptions = {"credential": "', '", "retries": 2}\n', "py"),
    ("v3-js-call", 'configure({region: "east", credential: "', '"});\r\n', "js"),
    ("v3-shell-local", 'run_job() {\n  local RUNTIME_CREDENTIAL="', '"\n  export RUNTIME_CREDENTIAL\n}\n', "sh"),
)


class Builder(base.Builder):
    def __init__(self, root: Path):
        super().__init__(root)
        self.rng = random.Random(SEED)

    def add(self, **kwargs) -> None:
        if kwargs["group"] == "format-valid":
            template, prefix, suffix, extension = TEMPLATES[(kwargs["index"] * 5 + 3) % len(TEMPLATES)]
            kwargs.update(template=template, prefix=prefix, suffix=suffix, extension=extension)
        else:
            # Keep the public generator's semantic label while varying byte/line
            # context; values are from an entirely new deterministic RNG stream.
            kwargs["prefix"] = f'# 配置片段 🧭 {kwargs["index"]}\r\n\n' + kwargs["prefix"]
            kwargs["suffix"] += '\n# generated offline; network verification forbidden\n'
            kwargs["template"] = "v3-context-" + kwargs["template"]
        super().add(**kwargs)

    def pair_positions(self) -> None:
        for provider in base.FORMATS:
            entries = [e for e in self.entries if e["provider"] == provider and e["label"] == "positive"]
            for offset, repeated in ((0, True), (2, False)):
                first, second = entries[offset:offset + 2]
                first_data = (self.root / first["path"]).read_bytes()
                second_data = (self.root / second["path"]).read_bytes()
                value_a = first_data[first["start"]:first["end"]]
                value_b = value_a if repeated else second_data[second["start"]:second["end"]]
                prefix = '// 并列凭证 🧭\nconst left = "'.encode()
                separator = b'"; const right = "'
                content = prefix + value_a + separator + value_b + b'";\n'
                removed_path = second["path"]
                (self.root / first["path"]).write_bytes(content)
                (self.root / removed_path).unlink()
                self.files = [f for f in self.files if f["path"] != removed_path]
                for item in self.files:
                    if item["path"] == first["path"]:
                        item.update(bytes=len(content), sha256=base.sha(content))
                for entry, value, start in ((first, value_a, len(prefix)),
                                            (second, value_b, len(prefix) + len(value_a) + len(separator))):
                    entry.update(path=first["path"], start=start, end=start + len(value),
                                 line=2, end_line=2, sha256=base.sha(value), value_group=base.sha(value),
                                 template_group="v3-pair-repeat" if repeated else "v3-pair-distinct",
                                 case="v3-pair-repeat" if repeated else "v3-pair-distinct")


def validate(root: Path, manifest: dict) -> None:
    ids, positions, paths, positive_values, negative_values = set(), set(), set(), set(), set()
    counts = Counter()
    for entry in manifest["entries"]:
        assert entry["id"] not in ids
        ids.add(entry["id"])
        path = Path(entry["path"])
        assert not path.is_absolute() and ".." not in path.parts
        paths.add(path.as_posix())
        position = (entry["path"], entry["start"], entry["end"])
        assert position not in positions
        positions.add(position)
        data = (root / path).read_bytes()
        start, end = entry["start"], entry["end"]
        assert 0 <= start < end <= len(data)
        value = data[start:end]
        assert base.sha(value) == entry["sha256"] == entry["value_group"]
        assert data[:start].count(b"\n") + 1 == entry["line"]
        assert data[:end].count(b"\n") + 1 == entry["end_line"]
        counts[entry["label"]] += 1
        if entry["label"] == "positive":
            positive_values.add(value)
            if entry["group"] == "format-valid":
                assert re.fullmatch(base.grammar(base.FORMATS[entry["provider"]]), value.decode())
        else:
            assert entry["label"] == "negative"
            negative_values.add(value)
    assert counts == {"positive": 600, "negative": 300}
    assert len(positive_values) == 580
    assert not positive_values.intersection(negative_values)
    assert Counter(e["group"] for e in manifest["entries"]) == {"format-valid": 480, "broad-generic": 120, "negative": 300}
    for entry in manifest["entries"]:
        if entry["label"] == "negative":
            data = (root / entry["path"]).read_bytes()
            assert not any(value in data for value in positive_values)
    assert len(manifest["files"]) == len(paths) == 860
    assert {f["path"] for f in manifest["files"]} == paths
    for item in manifest["files"]:
        data = (root / item["path"]).read_bytes()
        assert base.sha(data) == item["sha256"] and len(data) == item["bytes"]
    assert base.sha(base.json_bytes(manifest["files"])) == manifest["corpus_sha256"]


def generate(root: Path) -> dict:
    if root.exists() and any(root.iterdir()):
        raise ValueError("output directory must be empty")
    root.mkdir(parents=True, exist_ok=True)
    builder = Builder(root)
    builder.positives()
    builder.negatives()
    builder.pair_positions()
    files = sorted(builder.files, key=lambda item: item["path"])
    manifest = {
        "schema_version": 1, "seed": SEED, "synthetic": True,
        "network_verification_allowed": False, "offset_unit": "byte", "span_convention": "half-open",
        "ground_truth": "Fabricated syntax candidates and semantic negatives; no intended active credentials",
        "evaluation_status": "frozen before first scanner evaluation; subsequent tuning makes it regression data",
        "limitations": ["Format families and broad category generators are shared with the previous synthetic holdout",
                        "Format source shares ancestry with tested rule catalogue",
                        "Fresh seeded values and rearranged contexts are not an independent real-world distribution",
                        "Syntactic validity does not establish checksum or server validity",
                        "Twenty positive values intentionally appear twice at different positions on one line",
                        "Value and template grouping keys must be respected in future splits"],
        "sources": [{"url": base.SOURCE_URL, "commit": base.SOURCE_COMMIT, "sha256": base.SOURCE_SHA256,
                     "license": "MIT", "rule_ids": list(base.FORMATS)}],
        "generator_sha256": base.sha(Path(__file__).read_bytes()),
        "base_generator_sha256": base.sha(Path(base.__file__).read_bytes()),
        "corpus_sha256": base.sha(base.json_bytes(files)), "files": files,
        "datasets": {"quality": {"path": "quality", "mode": "fs", "files": len(files),
                                  "bytes": sum(f["bytes"] for f in files),
                                  "content": "fresh-synthetic-holdout-600-positive-300-negative-with-position-challenges"}},
        "entries": builder.entries,
    }
    validate(root, manifest)
    (root / "manifest.json").write_bytes(base.json_bytes(manifest))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        with tempfile.TemporaryDirectory() as temp:
            first, second = Path(temp) / "first", Path(temp) / "second"
            generate(first)
            generate(second)
            assert (first / "manifest.json").read_bytes() == (second / "manifest.json").read_bytes()
        print("Holdout v3 self-check passed: 600 positive positions, 580 unique positive values, 300 negative positions")
    elif args.output:
        manifest = generate(args.output)
        print(base.json_bytes({"generator_sha256": manifest["generator_sha256"],
                               "base_generator_sha256": manifest["base_generator_sha256"],
                               "corpus_sha256": manifest["corpus_sha256"],
                               "manifest_sha256": base.sha((args.output / "manifest.json").read_bytes()),
                               "positive": 600, "negative": 300, "unique_positive_values": 580}).decode(), end="")
    else:
        parser.error("supply --output or --self-test")


if __name__ == "__main__":
    main()
