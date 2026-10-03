#!/usr/bin/env python3
"""Install an npm tarball or exact registry version and check the real CLI."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", help="Local .tgz path or exact keyspoor@version")
    parser.add_argument("version", help="Expected CLI and npm package version")
    args = parser.parse_args()
    package = str(Path(args.package).resolve()) if Path(args.package).is_file() else args.package
    npm = "npm.cmd" if os.name == "nt" else "npm"
    with tempfile.TemporaryDirectory(prefix="keyspoor-npm-check-") as temp:
        root = Path(temp)
        subprocess.run(
            [npm, "install", "--prefix", str(root), "--ignore-scripts", "--no-audit", "--no-fund", package],
            check=True,
        )
        installed = root / "node_modules/keyspoor"
        metadata = json.loads((installed / "package.json").read_text())
        if metadata["version"] != args.version:
            raise RuntimeError("Installed npm version does not match the release")
        for platform in ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64", "win32-x64"]:
            binary = installed / "bin" / platform / ("keyspoor.exe" if platform == "win32-x64" else "keyspoor")
            if not binary.is_file() or binary.stat().st_size == 0:
                raise RuntimeError(f"Missing native binary for {platform}")
        cli = ["node", str(installed / "cli.cjs")]
        version = subprocess.check_output([*cli, "--version"], text=True).strip()
        if version != f"keyspoor {args.version}":
            raise RuntimeError("Installed native CLI version does not match the release")
        fixture = root / "input.conf"
        # Synthetic format-only fixture; no provider APIs are called.
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        for content, expected in [("clean\n", 0), (f'github_token = "{token}"\n', 1)]:
            fixture.write_text(content, encoding="utf-8")
            result = subprocess.run([*cli, "scan", str(fixture), "--format", "json"], capture_output=True, text=True)
            if result.returncode != expected:
                raise RuntimeError(f"Installed CLI exit {result.returncode}; expected {expected}")
            if token in result.stdout or token in result.stderr:
                raise RuntimeError("Installed CLI exposed the synthetic secret")
        missing = subprocess.run([*cli, "scan", str(root / "missing")], capture_output=True, text=True)
        if missing.returncode != 2:
            raise RuntimeError(f"Installed CLI missing-input exit {missing.returncode}; expected 2")
    print(f"Verified npm keyspoor@{args.version}: five bundled binaries, native version, exits 0/1/2 and redaction")


if __name__ == "__main__":
    main()
