#!/usr/bin/env python3
"""Compare fresh-process UTF-16 peak RSS and exact source coordinates on macOS.

Uses only synthetic, temporary 16 MiB UTF-16LE inputs and offline scanning.
Each case/binary runs three times, with alternating before/after order. Reports
contain measurements and input/binary hashes, never input or scanner output.
This compares whole versions, including their different rule catalogs and fixes;
it does not isolate the causal contribution of the coordinate mapping change.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time


SIZE = 16 * 1024 * 1024
REPEATS = 3


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def fixture(path, token, positive):
    # Two lines, with the token at the start of the final line. Write in chunks
    # so fixture generation does not leave a large parent allocation at spawn.
    tail = "\n" + (token if positive else " " * len(token)) + "\n"
    padding = SIZE - 2 - len(tail.encode("utf-16le"))
    block = b" \x00" * 32768
    with path.open("wb") as output:
        output.write(b"\xff\xfe")
        while padding:
            count = min(padding, len(block))
            output.write(block[:count])
            padding -= count
        output.write(tail.encode("utf-16le"))
    return {"start": SIZE - 2 * (len(token) + 1), "end": SIZE - 2,
            "line": 2, "column": 0, "coordinate_space": "source_bytes"}


def measure(binary, path, token, positive, expected):
    env = {key: os.environ[key] for key in ("PATH", "TMPDIR", "LANG", "LC_ALL")
           if key in os.environ}
    command = [str(binary), "--no-decode", "scan", "--threads", "1",
               "--format", "json", str(path)]
    # Files avoid pipe backpressure without requiring communicate(), which
    # would reap the child before wait4 could collect this process's own RSS.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        started = time.perf_counter()
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr, env=env)
        try:
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
        except BaseException:
            child.kill()
            child.wait()
            raise
        elapsed = time.perf_counter() - started
        stdout.seek(0)
        stderr.seek(0)
        raw_output = stdout.read()
        raw_errors = stderr.read()
    if token.encode() in raw_output or token.encode() in raw_errors:
        raise RuntimeError("scanner exposed the synthetic credential; output withheld")
    if child.returncode != (1 if positive else 0):
        raise RuntimeError("scanner returned an unexpected exit code; output withheld")
    try:
        report = json.loads(raw_output)
    except (ValueError, UnicodeError):
        raise RuntimeError("scanner did not emit a valid JSON report; output withheld") from None
    if report.get("complete") is not True or report.get("errors"):
        raise RuntimeError("scanner reported an incomplete scan; output withheld")
    stats = report.get("stats", {})
    if stats.get("bytes") != SIZE or stats.get("files") != 1 or stats.get("skipped") != 0:
        raise RuntimeError("scanner did not cover the complete fixture")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise RuntimeError("scanner report omitted findings")
    if positive:
        github = [item for item in findings if item.get("rule_id") == "github-pat"]
        if len(github) != 1:
            raise RuntimeError("expected exactly one GitHub PAT finding")
        if any(github[0].get(key) != value for key, value in expected.items()):
            raise RuntimeError("GitHub finding failed exact original source-span validation")
        for finding in findings:
            if (finding.get("path") != str(path)
                    or finding.get("redacted") != "[REDACTED]"
                    or finding.get("is_base64_encoded") is not False):
                raise RuntimeError("finding failed path/redaction validation")
    elif findings:
        raise RuntimeError("benign fixture unexpectedly produced findings")
    # Keep only identities needed for parity, never full findings or messages.
    identity = sorted((item["rule_id"], item["start"], item["end"],
                       item["line"], item["column"], item["fingerprint"])
                      for item in findings)
    return {"wall_ms": elapsed * 1000, "user_ms": usage.ru_utime * 1000,
            "system_ms": usage.ru_stime * 1000,
            "peak_rss_bytes": int(usage.ru_maxrss),
            "finding_count": len(findings), "exit_code": child.returncode,
            "exact_span_verified": positive, "raw_value_absent": True}, identity


def summarize(runs):
    result = {"runs": runs}
    for field in ("wall_ms", "user_ms", "system_ms", "peak_rss_bytes"):
        values = [run[field] for run in runs]
        result[field] = {"median": statistics.median(values),
                         "min": min(values), "max": max(values)}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, type=Path)
    parser.add_argument("--after", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=Path("bench/results/utf16-memory.json"))
    args = parser.parse_args()
    if platform.system() != "Darwin" or not hasattr(os, "wait4"):
        parser.error("this measurement requires macOS wait4; ru_maxrss is recorded in bytes")
    binaries = {"before": args.before.resolve(), "after": args.after.resolve()}
    for binary in binaries.values():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error("both binary paths must be executable files")
    result = {"schema_version": 1, "host": {"system": platform.system(),
              "release": platform.release(), "machine": platform.machine()},
              "binary_sha256": {label: digest(path) for label, path in binaries.items()},
              "rss_method": "per-child wait4 ru_maxrss; Darwin bytes; fresh process",
              "scope": "Whole-version UTF-16 comparison, not an isolated mapping experiment; "
                       "default rules; no Base64 decode; one scan thread; no cache flushing; "
                       "wall time includes process and rule initialization",
              "repeats": REPEATS, "cases": {}}
    token = "ghp_" + hashlib.sha256(b"utf16-memory-offline-synthetic-only").hexdigest()[:36]
    with tempfile.TemporaryDirectory(prefix="secret-scan-utf16-") as directory:
        for case, positive in (("with_finding", True), ("without_finding", False)):
            path = Path(directory) / (case + ".txt")
            expected = fixture(path, token, positive)
            runs = {label: [] for label in binaries}
            reference = None
            for repeat in range(REPEATS):
                order = ("before", "after") if repeat % 2 == 0 else ("after", "before")
                for label in order:
                    run, identity = measure(binaries[label], path, token, positive, expected)
                    if reference is not None and identity != reference:
                        raise RuntimeError("before/after or repeated finding identities differ")
                    reference = identity
                    runs[label].append(run)
            result["cases"][case] = {
                "input_bytes": path.stat().st_size, "input_sha256": digest(path),
                "expected_source_span": expected if positive else None,
                "finding_parity": True,
                **{label: summarize(values) for label, values in runs.items()},
            }
    # Reject a binary replaced during the measurement rather than misattribute it.
    if any(digest(path) != result["binary_sha256"][label] for label, path in binaries.items()):
        raise RuntimeError("a measured binary changed during the run")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        raise SystemExit(str(error)) from None
