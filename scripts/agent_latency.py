#!/usr/bin/env python3
"""Measure fresh CLI and persistent JSONL calls on one fixed synthetic payload.

This is an integration latency measurement, not a cross-tool ranking or token
estimate. No credentials, network validation or external datasets are used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import statistics
import subprocess
import time


def read_line(process, timeout=10):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(timeout):
            raise TimeoutError("persistent scanner response timed out")
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("persistent scanner exited without a response")
        return line
    finally:
        selector.close()


def summary(values):
    ordered = sorted(values)
    return {"count": len(values), "median_ms": statistics.median(values),
            "p95_ms": ordered[min(len(ordered) - 1, int(len(ordered) * .95))],
            "min_ms": min(values), "max_ms": max(values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/keyspoor"))
    parser.add_argument("--output", type=Path, default=Path("bench/results/agent-latency.json"))
    parser.add_argument("--requests", type=int, default=100)
    args = parser.parse_args()
    if args.requests < 1:
        parser.error("--requests must be positive")
    binary = args.binary.resolve()
    payload = ('const enabled = true; // local synthetic fixture\n' * 20).encode()
    env = {key: os.environ[key] for key in ("PATH", "TMPDIR", "LANG", "LC_ALL") if key in os.environ}
    fresh = []
    output_bytes = []
    for _ in range(10):
        start = time.perf_counter()
        result = subprocess.run([str(binary), "scan", "-"], input=payload,
                                capture_output=True, env=env, timeout=10)
        fresh.append((time.perf_counter() - start) * 1000)
        if result.returncode != 0:
            raise RuntimeError("fresh scanner failed")
        report = json.loads(result.stdout)
        if not report["complete"] or report["findings"]:
            raise RuntimeError("unexpected result on benign synthetic payload")
        output_bytes.append(len(result.stdout))
    start = time.perf_counter()
    child = subprocess.Popen([str(binary), "serve"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    steady = []
    try:
        request = {"id": 0, "path": "stdin", "text": payload.decode()}
        child.stdin.write(json.dumps(request).encode() + b"\n")
        child.stdin.flush()
        first = json.loads(read_line(child))
        startup = (time.perf_counter() - start) * 1000
        if first.get("id") != 0 or not first["result"]["complete"]:
            raise RuntimeError("persistent scanner initialization failed")
        for identity in range(1, args.requests + 1):
            request["id"] = identity
            encoded = json.dumps(request).encode() + b"\n"
            start = time.perf_counter()
            child.stdin.write(encoded)
            child.stdin.flush()
            response = json.loads(read_line(child))
            steady.append((time.perf_counter() - start) * 1000)
            if response.get("id") != identity or not response["result"]["complete"] or response["result"]["findings"]:
                raise RuntimeError("persistent scanner returned an invalid result")
        child.stdin.close()
        if child.wait(timeout=10) != 0:
            raise RuntimeError("persistent scanner failed on shutdown")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
    result = {"schema_version": 1, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "payload_sha256": hashlib.sha256(payload).hexdigest(), "payload_bytes": len(payload),
              "fresh_cli": summary(fresh), "persistent_startup_ms": startup,
              "persistent_requests": summary(steady), "fresh_output_bytes": output_bytes,
              "scope": "same binary, benign synthetic input; includes IPC and JSON; no token or cross-tool claim"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
