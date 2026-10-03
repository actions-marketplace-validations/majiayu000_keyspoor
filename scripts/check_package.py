#!/usr/bin/env python3
"""Package the crate and run its example as an independent library consumer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-dirty", action="store_true", help="Validate uncommitted local changes")
    args = parser.parse_args()
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT, text=True,
    ))
    command = ["cargo", "package", "--locked"]
    if args.allow_dirty:
        command.append("--allow-dirty")
    subprocess.run(command, cwd=ROOT, check=True)
    name = f'{package["name"]}-{package["version"]}'
    archive = Path(metadata["target_directory"]) / "package" / f"{name}.crate"
    with tempfile.TemporaryDirectory(prefix="keyspoor-package-") as temp:
        directory = Path(temp)
        with tarfile.open(archive) as bundle:
            if any(member.name.startswith((f"{name}/bench/", f"{name}/target/")) for member in bundle.getmembers()):
                raise RuntimeError("Package unexpectedly contains benchmark or build artifacts")
            bundle.extractall(directory, filter="data")
        unpacked = directory / name
        consumer = directory / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text(
            '[package]\nname = "keyspoor-package-consumer"\nversion = "0.0.0"\nedition = "2024"\n'
            '\n[dependencies]\nkeyspoor = { path = '
            + json.dumps(unpacked.as_posix()) + ' }\n', encoding="utf-8",
        )
        shutil.copyfile(unpacked / "examples/scan.rs", consumer / "src/main.rs")
        # A real consumer has its own lockfile. Resolve from the dependencies
        # cached by cargo package, then use that lock for the build and runs.
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(directory / "target")
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=consumer, env=env, check=True)
        subprocess.run(["cargo", "build", "--locked", "--offline"], cwd=consumer, env=env, check=True)
        binary = directory / "target/debug" / ("keyspoor-package-consumer.exe" if os.name == "nt" else "keyspoor-package-consumer")
        fixture = directory / "input.conf"
        # Synthetic format-only value. This checker never uses provider APIs.
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        cases = [("clean\n", 0), (f'github_token = "{token}"\n', 1)]
        for content, expected in cases:
            fixture.write_text(content, encoding="utf-8")
            result = subprocess.run([str(binary), str(fixture)], capture_output=True, text=True, check=False)
            if result.returncode != expected:
                raise RuntimeError(f"Packaged consumer exit {result.returncode}; expected {expected}")
            if token in result.stdout or token in result.stderr:
                raise RuntimeError("Packaged consumer exposed the synthetic secret")
        missing = subprocess.run([str(binary), str(directory / "missing")], capture_output=True, text=True, check=False)
        if missing.returncode != 2:
            raise RuntimeError(f"Packaged consumer missing-input exit {missing.returncode}; expected 2")
    print(f"Verified {archive.name}: independent consumer clean/finding/error exits and redaction")
    print(f"SHA256 {hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}")


if __name__ == "__main__":
    main()
