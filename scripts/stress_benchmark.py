#!/usr/bin/env python3
"""Whole-version secret-scan stress comparison, not isolated optimization proof.

macOS wait4 reports each scanner process's peak RSS in bytes. Temporary synthetic
inputs are shared by both binaries. Scanner stdout/stderr are consumed in memory,
never saved or echoed. JSONL findings are validated and reduced to counts plus an
order-independent cryptographic multiset digest. No credentials or network used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import statistics
import subprocess
import tempfile
import time


TOKEN = "ghp_" + hashlib.sha256(b"secret-scan-stress-synthetic-only").hexdigest()[:36]
SIZE = 16 * 1024 * 1024
MODULUS = 1 << 256
IDENTITY_FIELDS = ("rule_id", "path", "start", "end", "line", "column",
                   "coordinate_space", "is_base64_encoded")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def clean_env():
    return {key: os.environ[key] for key in ("PATH", "TMPDIR", "LANG", "LC_ALL")
            if key in os.environ}


def git(repo, *arguments, data=None):
    result = subprocess.run(["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null",
                             *arguments], input=data, capture_output=True, env=clean_env())
    if result.returncode:
        raise RuntimeError("synthetic Git fixture command failed; output withheld")
    return result.stdout


def git_fixture(repo, commits):
    repo.mkdir()
    git(repo, "init", "--bare", "--quiet")
    records = bytearray()
    # Sixteen fixed blobs and paths; all subsequent commits retain the same tree.
    for index in range(16):
        body = ((TOKEN + "\n") if index == 0 else f"benign fixture number {index}\n").encode()
        records.extend(f"blob\nmark :{index + 1}\ndata {len(body)}\n".encode())
        records.extend(body + b"\n")
    for index in range(commits):
        records.extend(f"commit refs/heads/main\nmark :{100 + index}\n"
                       f"committer Benchmark <benchmark@example.invalid> {1700000000 + index} +0000\n"
                       "data 6\nbench\n".encode())
        if index:
            records.extend(f"from :{99 + index}\n".encode())
        else:
            for blob in range(16):
                name = "secret.txt" if blob == 0 else f"benign-{blob}.txt"
                records.extend(f"M 100644 :{blob + 1} {name}\n".encode())
        records.extend(b"\n")
    records.extend(b"done\n")
    git(repo, "fast-import", "--quiet", data=bytes(records))
    reachable = set(git(repo, "rev-list", "--all").decode("ascii").splitlines())
    if len(reachable) != commits:
        raise RuntimeError("synthetic Git fixture has an unexpected commit count")
    return reachable


def make_cases(root, args):
    cases = []
    if "newline" in args.cases:
        path = root / "newline.txt"
        start = SIZE - len(TOKEN) - 1
        with path.open("wb") as output:
            block = b"\n" * 65536
            remaining = start
            while remaining:
                count = min(remaining, len(block))
                output.write(block[:count])
                remaining -= count
            output.write((TOKEN + "\n").encode())
        cases.append({"name": "newline_dense_16mib", "kind": "newline", "path": path,
                      "mode": "scan", "expected": 1, "start": start,
                      "input_bytes": SIZE, "input_sha256": digest(path)})
    if "manyfiles" in args.cases:
        directory = root / "manyfiles"
        directory.mkdir()
        total = 0
        for index in range(args.many_files):
            body = ("record\n" + TOKEN + "\n") if index % 100 == 0 else "ordinary benign text\n"
            data = body.encode()
            (directory / f"file-{index:06}.txt").write_bytes(data)
            total += len(data)
        cases.append({"name": f"manyfiles_{args.many_files}", "kind": "manyfiles",
                      "path": directory, "mode": "scan", "expected": (args.many_files + 99) // 100,
                      "file_count": args.many_files, "input_bytes": total})
    if "dense" in args.cases:
        for count in args.dense_counts:
            path = root / f"dense-{count}.txt"
            with path.open("wb") as output:
                block = (TOKEN + "\n").encode()
                for _ in range(count):
                    output.write(block)
            cases.append({"name": f"densefindings_{count}", "kind": "dense", "path": path,
                          "mode": "scan", "expected": count, "input_bytes": path.stat().st_size,
                          "input_sha256": digest(path)})
    if "git" in args.cases:
        for commits in sorted({1, args.git_commits}):
            repo = root / f"history-{commits}.git"
            reachable = git_fixture(repo, commits)
            cases.append({"name": f"git_fixedblobs_{commits}commits", "kind": "git",
                          "mode": "history", "path": repo, "expected": commits,
                          "commits": reachable, "unique_blobs": 16,
                          "commit_set_sha256": hashlib.sha256("\n".join(sorted(reachable)).encode()).hexdigest()})
    return cases


def normalized_path(case, path):
    """Align old absolute FS paths with source-relative paths in newer builds."""
    if not isinstance(path, str) or not path:
        raise RuntimeError("finding path is missing or invalid")
    if case["kind"] == "git":
        return path
    candidate = Path(path)
    root = case["path"] if case["kind"] == "manyfiles" else case["path"].parent
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(root)
        except ValueError:
            raise RuntimeError("finding path is outside the synthetic source root") from None
    if not candidate.parts or ".." in candidate.parts:
        raise RuntimeError("finding path escapes the synthetic source root")
    return candidate.as_posix()


class Collector:
    def __init__(self, case):
        self.case = case
        self.count = 0
        self.github_count = 0
        self.github_locations = set()
        self.multiset = 0
        self.error_count = 0
        self.progress_count = 0
        self.summary = None

    def accept(self, record):
        if self.summary is not None:
            raise RuntimeError("scanner emitted records after the final summary")
        if record.get("type") == "summary":
            self.summary = record
            return False
        if record.get("type") == "progress":
            if not isinstance(record.get("stats"), dict):
                raise RuntimeError("scanner emitted a malformed progress record")
            self.progress_count += 1
            return False
        if record.get("type") == "error":
            if not isinstance(record.get("error"), dict):
                raise RuntimeError("scanner emitted a malformed error record")
            self.error_count += 1
            return False
        if record.get("type") != "finding" or not isinstance(record.get("finding"), dict):
            raise RuntimeError("scanner emitted an unsupported JSONL record")
        finding = dict(record["finding"])
        finding["path"] = normalized_path(self.case, finding.get("path"))
        if finding.get("redacted") != "[REDACTED]" or finding.get("is_base64_encoded") is not False:
            raise RuntimeError("scanner finding failed redaction/encoding validation")
        if finding.get("coordinate_space") != "source_bytes":
            raise RuntimeError("scanner finding uses unexpected coordinates")
        identity = {key: finding.get(key) for key in IDENTITY_FIELDS}
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        self.multiset = (self.multiset + int.from_bytes(hashlib.sha256(encoded).digest(), "big")) % MODULUS
        self.count += 1
        if finding.get("rule_id") == "github-pat":
            location = self.check_coordinates(finding)
            if location in self.github_locations:
                raise RuntimeError("scanner duplicated a synthetic GitHub occurrence")
            self.github_locations.add(location)
            self.github_count += 1
        return True

    def check_coordinates(self, finding):
        case = self.case
        start, line, column = 0, 1, 0
        path = finding.get("path")
        if case["kind"] == "newline":
            start = case["start"]
            line = start + 1
            valid_path = path == case["path"].name
        elif case["kind"] == "dense":
            start = finding.get("start", -1)
            width = len(TOKEN) + 1
            valid_offset = isinstance(start, int) and 0 <= start < width * case["expected"] and start % width == 0
            if not valid_offset:
                raise RuntimeError("dense finding source offset is incorrect")
            line = start // width + 1
            valid_path = path == case["path"].name
        elif case["kind"] == "manyfiles":
            start, line = len("record\n"), 2
            candidate = Path(path or "")
            try:
                index = int(candidate.stem.removeprefix("file-"))
            except ValueError:
                raise RuntimeError("many-file finding has an unexpected path") from None
            valid_path = (len(candidate.parts) == 1 and 0 <= index < case["file_count"]
                          and index % 100 == 0 and candidate.name == f"file-{index:06}.txt")
        else:
            parts = (path or "").split(":", 2)
            valid_path = len(parts) == 3 and parts[0] == "git" and parts[1] in case["commits"] and parts[2] == "secret.txt"
        expected = {"start": start, "end": start + len(TOKEN), "line": line, "column": column}
        if not valid_path or any(finding.get(key) != value for key, value in expected.items()):
            raise RuntimeError("GitHub finding failed exact path/source-coordinate validation")
        return path, start

    def finish(self, exit_code):
        summary = self.summary
        if (not summary or summary.get("complete") is not True or summary.get("errors")
                or self.error_count or summary.get("error_count", 0)):
            raise RuntimeError("scanner did not finish with a complete JSONL summary")
        if exit_code != 1 or summary.get("finding_count") != self.count:
            raise RuntimeError("scanner exit code or summary finding count is incorrect")
        if self.github_count != self.case["expected"]:
            raise RuntimeError("scanner did not detect the expected number of synthetic GitHub occurrences")
        stats = summary.get("stats", {})
        if stats.get("skipped") != 0:
            raise RuntimeError("scanner skipped part of the synthetic input")
        if "input_bytes" in self.case and stats.get("bytes") != self.case["input_bytes"]:
            raise RuntimeError("scanner byte coverage differs from the fixture")
        return {"findings": self.count, "github_occurrences": self.github_count,
                "identity_multiset_sha256_sum": f"{self.multiset:064x}",
                "progress_records": self.progress_count,
                "coordinates_verified": True, "complete": True,
                "stats": {key: stats.get(key) for key in ("files", "bytes", "skipped", "detection_passes")}}


def measure(binary, case, threads, timeout):
    command = [str(binary), "--no-decode", case["mode"], "--threads", str(threads),
               "--format", "jsonl", str(case["path"])]
    collector = Collector(case)
    started = time.perf_counter()
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=clean_env())
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
    pending = bytearray()
    tails = {"stdout": b"", "stderr": b""}
    sizes = {"stdout": 0, "stderr": 0}
    first_result = None
    usage = None
    try:
        while selector.get_map() or usage is None:
            if time.perf_counter() - started > timeout:
                raise RuntimeError("scanner exceeded the per-run time limit")
            for key, _ in selector.select(0.1):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                name = key.data
                sizes[name] += len(data)
                combined = tails[name] + data
                if TOKEN.encode() in combined:
                    raise RuntimeError("scanner exposed the synthetic credential; output withheld")
                tails[name] = combined[-len(TOKEN):]
                if name == "stdout":
                    pending.extend(data)
                    while True:
                        newline = pending.find(b"\n")
                        if newline < 0:
                            break
                        line = bytes(pending[:newline])
                        del pending[:newline + 1]
                        try:
                            record = json.loads(line)
                        except (ValueError, UnicodeError):
                            raise RuntimeError("scanner emitted invalid JSONL; output withheld") from None
                        if not isinstance(record, dict):
                            raise RuntimeError("scanner emitted a non-object JSONL record")
                        if collector.accept(record) and first_result is None:
                            first_result = (time.perf_counter() - started) * 1000
                    if len(pending) > 1024 * 1024:
                        raise RuntimeError("scanner emitted an unexpectedly large JSONL record")
            if usage is None:
                pid, status, measured = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    child.returncode = os.waitstatus_to_exitcode(status)
                    usage = measured
        if pending.strip():
            raise RuntimeError("scanner output ended before a JSONL record terminator")
        verified = collector.finish(child.returncode)
        return {"wall_ms": (time.perf_counter() - started) * 1000,
                "first_finding_ms": first_result, "peak_rss_bytes": int(usage.ru_maxrss),
                "user_ms": usage.ru_utime * 1000, "system_ms": usage.ru_stime * 1000,
                "stdout_bytes": sizes["stdout"], "stderr_bytes": sizes["stderr"],
                "exit_code": child.returncode, "raw_value_absent": True, **verified}
    finally:
        selector.close()
        child.stdout.close()
        child.stderr.close()
        if usage is None:
            child.kill()
            child.wait()


def summarize(runs):
    summary = {"runs": runs}
    for field in ("wall_ms", "first_finding_ms", "peak_rss_bytes", "user_ms", "system_ms"):
        values = [run[field] for run in runs]
        summary[field] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, default=Path("bench/tools/secret-scan-2113800"))
    parser.add_argument("--after", type=Path, default=Path("target/release/secret-scan"))
    parser.add_argument("--output", type=Path, default=Path("bench/results/stress-comparison.json"))
    parser.add_argument("--many-files", type=int, default=10000)
    parser.add_argument("--dense-counts", type=int, nargs="+", default=[10000, 100000])
    parser.add_argument("--git-commits", type=int, default=200)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--cases", nargs="+", choices=["newline", "manyfiles", "dense", "git"],
                        default=["newline", "manyfiles", "dense", "git"])
    args = parser.parse_args()
    if platform.system() != "Darwin" or not hasattr(os, "wait4"):
        parser.error("requires macOS wait4; RSS is recorded in bytes")
    if min(args.many_files, args.git_commits, args.repeats, args.threads, args.timeout, *args.dense_counts) <= 0:
        parser.error("workload sizes, repeats, threads and timeout must be positive")
    binaries = {"before": args.before.resolve(), "after": args.after.resolve()}
    if any(not path.is_file() or not os.access(path, os.X_OK) for path in binaries.values()):
        parser.error("both binary paths must identify executable files")
    hashes = {label: digest(path) for label, path in binaries.items()}
    result = {"schema_version": 1, "binary_sha256": hashes,
              "benchmark_script_sha256": digest(Path(__file__)),
              "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
              "scope": "Whole-version comparison, not isolated causal attribution; default rules, "
                       "Base64 disabled, warm/uncleared filesystem cache, fresh processes. "
                       "RSS is per-child wait4 peak, not sampled simultaneous process-tree RSS. "
                       "Wall and first-result include pipe transfer and benchmark validation/backpressure.",
              "parity_scope": "Rule, path and exact source coordinates; fingerprints intentionally "
                              "excluded because fingerprint identity policy changed between versions. "
                              "Filesystem paths normalized relative to each fixture source root; "
                              "Git commit/path provenance remains unchanged.",
              "repeats": args.repeats, "threads_argument": args.threads, "cases": {}}
    with tempfile.TemporaryDirectory(prefix="secret-scan-stress-") as directory:
        for case in make_cases(Path(directory), args):
            runs = {label: [] for label in binaries}
            reference = None
            for repeat in range(args.repeats):
                order = ("before", "after") if repeat % 2 == 0 else ("after", "before")
                for label in order:
                    measured = measure(binaries[label], case, args.threads, args.timeout)
                    identity = (measured["findings"], measured["identity_multiset_sha256_sum"])
                    if reference is not None and identity != reference:
                        raise RuntimeError("before/after or repeated findings differ; comparison withheld")
                    reference = identity
                    runs[label].append(measured)
            metadata = {key: value for key, value in case.items()
                        if key not in ("path", "commits")}
            result["cases"][case["name"]] = {"fixture": metadata, "finding_parity": True,
                                                  **{label: summarize(values) for label, values in runs.items()}}
    if any(digest(path) != hashes[label] for label, path in binaries.items()):
        raise RuntimeError("a measured binary changed during the run")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        raise SystemExit(str(error)) from None
