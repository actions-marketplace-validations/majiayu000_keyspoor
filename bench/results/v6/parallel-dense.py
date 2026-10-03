#!/usr/bin/env python3
"""Paired four-worker dense JSON CLI benchmark; validate only after timing."""
import hashlib
import json
from pathlib import Path
import statistics
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "bench"))
import run as benchmark
sys.path.insert(0, str(ROOT / "scripts"))
from stress_benchmark import TOKEN


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(measured, source, names, per_file):
    stdout, stderr = measured.pop("_stdout"), measured.pop("_stderr")
    if measured["status"] != "finished" or measured["exit_code"] != 1 or stderr:
        raise RuntimeError("Scanner failed; raw output withheld")
    report = json.loads(stdout)
    findings = report["findings"]
    if (report.get("complete") is not True or report.get("errors") != []
            or len(findings) != len(names) * per_file
            or report["stats"]["files"] != len(names)
            or report["stats"]["skipped"] != 0):
        raise RuntimeError("Incomplete or unexpected result; raw output withheld")
    expected_bytes = len(names) * per_file * (len(TOKEN) + 1)
    if report["stats"]["bytes"] != expected_bytes:
        raise RuntimeError("Unexpected scanned byte count")
    seen = {name: set() for name in names}
    hashes = []
    width = len(TOKEN) + 1
    for finding in findings:
        path = Path(finding["path"])
        if path.is_absolute():
            path = path.relative_to(source)
        name = path.as_posix()
        start = finding["start"]
        if (name not in seen or type(start) is not int or start % width != 0
                or not 0 <= start < width * per_file or start in seen[name]
                or finding["end"] != start + len(TOKEN)
                or finding["line"] != start // width + 1 or finding["column"] != 0
                or finding["rule_id"] != "github-pat"
                or finding["coordinate_space"] != "source_bytes"
                or finding["is_base64_encoded"] is not False
                or finding["redacted"] != "[REDACTED]"):
            raise RuntimeError("Finding coordinates or identity failed; raw output withheld")
        seen[name].add(start)
        finding["path"] = name
        # All Finding fields, including fingerprint, evidence, explanation and
        # confidence, participate. Sort digests to ignore worker output order.
        hashes.append(hashlib.sha256(json.dumps(finding, sort_keys=True,
            separators=(",", ":")).encode()).digest())
    if any(len(offsets) != per_file for offsets in seen.values()):
        raise RuntimeError("Missing expected source occurrences")
    identity = hashlib.sha256(b"".join(sorted(hashes))).hexdigest()
    measured.update(findings=len(findings), complete=True, error_count=0,
                    full_findings_sha256=identity, stats=report["stats"])
    return identity


def main():
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_suffix(".json")
    if output.exists():
        raise SystemExit("Output exists; pass a new artifact path")
    binaries = {"before": ROOT / "bench/tools/secret-scan-v5-aca1a038",
                "after": ROOT / "target/release/secret-scan"}
    binary_hashes = {name: digest(path) for name, path in binaries.items()}
    result = {"binary_sha256": binary_hashes,
              "driver_sha256": digest(Path(__file__)),
              "runner_sha256": digest(ROOT / "bench/run.py"),
              "fixture_generator_sha256": digest(ROOT / "scripts/stress_benchmark.py"),
              "hardware": benchmark.hardware(), "repeats": 20,
              "method": "16 files with 6250 identical synthetic GitHub tokens each; four scanner workers; "
                        "decode disabled; one warmup per binary then 20 alternating pairs. "
                        "Fresh processes and uncontrolled warm filesystem cache. CLI JSON is written "
                        "to temporary files; parsing and full finding validation happen after timing. "
                        "CPU and RSS cover only the scanner process; this is CLI throughput, not pure kernel throughput.",
              "command_template": ["{binary}", "scan", "{source}", "--threads", "4",
                                   "--no-decode", "--format", "json"],
              "before": [], "after": []}
    with tempfile.TemporaryDirectory(prefix="secret-scan-parallel-dense-") as directory:
        source = Path(directory).resolve()
        names = [f"file-{index:02}.txt" for index in range(16)]
        body = ((TOKEN + "\n") * 6250).encode()
        tree = hashlib.sha256()
        for name in names:
            (source / name).write_bytes(body)
            tree.update(name.encode() + b"\0" + hashlib.sha256(body).digest())
        result.update(input_sha256=tree.hexdigest(), file_count=len(names),
                      findings_per_file=6250, input_bytes=len(body) * len(names))
        reference = None
        for repeat in range(-1, 20):
            order = ("before", "after") if repeat % 2 == 0 else ("after", "before")
            for label in order:
                measured = benchmark.measure([str(binaries[label]), "scan", str(source),
                    "--threads", "4", "--no-decode", "--format", "json"], 120)
                identity = validate(measured, source, names, 6250)
                if reference is not None and identity != reference:
                    raise RuntimeError("Full finding parity failed")
                reference = identity
                measured.update(pair=repeat, order_in_pair=order.index(label))
                if repeat >= 0:
                    result[label].append(measured)
        result["full_finding_parity"] = True
    if binary_hashes != {name: digest(path) for name, path in binaries.items()}:
        raise RuntimeError("Measured binary changed")
    result["median"] = {label: {
        "wall_ms": statistics.median(r["wall_seconds"] * 1000 for r in result[label]),
        "cpu_ms": statistics.median((r["user_seconds"] + r["system_seconds"]) * 1000
                                     for r in result[label]),
        "rss_mib": statistics.median(r["peak_rss_bytes"] / 1048576 for r in result[label])}
        for label in binaries}
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["median"]))


if __name__ == "__main__":
    main()
