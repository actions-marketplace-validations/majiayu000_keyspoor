#!/usr/bin/env python3
"""Reproduce this iteration's paired JSON CLI measurements; validate after timing."""
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "bench"))
import run as benchmark


def main():
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_suffix(".json")
    if output.exists():
        raise SystemExit("Output exists; pass a new artifact path")
    binaries = {"before": ROOT / "bench/tools/secret-scan-v5-aca1a038",
                "after": ROOT / "target/release/secret-scan"}
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    hashes = {name: digest(path) for name, path in binaries.items()}
    corpus = ROOT / "bench/corpus-final"
    fixture = json.loads((corpus / "manifest.json").read_text())
    result = {"binary_sha256": hashes, "driver_sha256": digest(Path(__file__)),
              "runner_sha256": digest(ROOT / "bench/run.py"),
              "hardware": benchmark.hardware(), "repeats": 20,
              "method": "One warmup per binary/dataset, then 20 alternating before/after pairs. "
                        "Fresh processes; default rules and threads; uncontrolled warm filesystem cache. "
                        "CLI JSON output goes to a temporary file; parsing and parity validation are outside timing. "
                        "RSS is the scanner process wait4 peak, not aggregate process-tree memory.",
              "datasets": {}}
    for name in ("throughput-16mib", "throughput-128mib", "real-regex"):
        source = corpus / fixture["datasets"][name]["path"]
        tree = hashlib.sha256()
        for path in sorted(p for p in source.rglob("*") if p.is_file()):
            tree.update(path.relative_to(source).as_posix().encode() + b"\0")
            tree.update(bytes.fromhex(digest(path)))
        data = {"input_sha256": tree.hexdigest(), "before": [], "after": []}
        reference = None
        for repeat in range(-1, 20):
            order = ("before", "after") if repeat % 2 == 0 else ("after", "before")
            for label in order:
                command = [str(binaries[label]), "scan", str(source), "--format", "json"]
                measured = benchmark.measure(command, 120)
                parsed = benchmark.parse_output("secret_scan", measured.pop("_stdout"),
                                                measured.pop("_stderr"), corpus)
                if (measured["status"] != "finished" or measured["exit_code"] not in (0, 1)
                        or not parsed["complete"] or parsed["stats"].get("skipped") != 0
                        or parsed["stats"].get("files", 0) == 0):
                    raise RuntimeError("Incomplete or unsuccessful benchmark scan")
                identity = hashlib.sha256(json.dumps(sorted(parsed["findings"],
                    key=lambda x: json.dumps(x, sort_keys=True)), sort_keys=True).encode()).hexdigest()
                if reference is not None and identity != reference:
                    raise RuntimeError("Finding parity failed")
                reference = identity
                measured.update(command=command, findings=len(parsed["findings"]),
                                locations_sha256=identity, stats=parsed["stats"])
                if repeat >= 0:
                    data[label].append(measured)
        data["finding_parity"] = True
        result["datasets"][name] = data
        print(name, {label: round(statistics.median(r["wall_seconds"] for r in data[label]) * 1000, 3)
                     for label in binaries}, flush=True)
    if hashes != {name: digest(path) for name, path in binaries.items()}:
        raise RuntimeError("Measured binary changed")
    output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
