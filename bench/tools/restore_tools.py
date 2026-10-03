#!/usr/bin/env python3
"""Restore named benchmark tools from the pinned manifest and dependency locks.

Usage: python3 bench/tools/restore_tools.py gitleaks detect-secrets keyhog
All installations stay under bench/tools; Rust builds use two jobs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent

def run(argv, cwd=None, env=None):
    subprocess.run([str(x) for x in argv], cwd=cwd, env=env, check=True)

def checkout(url, directory, revision, submodules=False):
    if not (directory / '.git').exists():
        run(['git', 'clone', '--no-checkout', '--filter=blob:none', url, directory])
    run(['git', 'fetch', '--depth', '1', 'origin', revision], cwd=directory)
    run(['git', 'checkout', '--detach', revision], cwd=directory)
    if submodules:
        run(['git', 'submodule', 'update', '--init', '--depth', '1'], cwd=directory)

def download(url, path, digest):
    if not path.exists():
        urllib.request.urlretrieve(url, path)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest.removeprefix('sha256:'):
        raise ValueError(f'SHA-256 mismatch for {path.name}')

def python_env(name, lock):
    directory = ROOT / 'venvs' / name
    if not (directory / 'bin/python').exists():
        run(['uv', 'venv', '--python', '3.12', directory])
    text = lock.read_text()
    # uv freeze records a source checkout as an absolute file URL.
    text = '\n'.join(('credentialdigger @ ' + (ROOT / 'source/credential-digger').as_uri())
                     if line.startswith('credentialdigger @ ') else line
                     for line in text.splitlines()) + '\n'
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', dir=ROOT) as tmp:
        tmp.write(text)
        tmp.flush()
        run(['uv', 'pip', 'sync', '--python', directory / 'bin/python', tmp.name])

def restore(tool):
    tool_id = tool['id']
    if tool['status'] != 'available':
        raise ValueError(f'{tool_id}: {tool["status"]}: {tool.get("reason", "not executable")}')
    if tool_id in ('detect-secrets', 'deepsecrets', 'whispers'):
        python_env('python', ROOT / 'python-requirements.lock')
    elif tool_id == 'credential-digger':
        checkout(tool['source_url'], ROOT / 'source/credential-digger', tool['commit_or_digest'])
        python_env('credentialdigger', ROOT / 'credentialdigger-requirements.lock')
    elif tool_id == 'secretlint':
        directory = ROOT / 'npm'
        directory.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / 'npm-package.json', directory / 'package.json')
        shutil.copyfile(ROOT / 'npm-package-lock.json', directory / 'package-lock.json')
        run(['npm', 'ci', '--prefix', directory])
    elif tool_id in ('keyhog', 'rusty-hog', 'scratch-scanner-rs', 'git-secrets'):
        folder = {'rusty-hog': 'rusty-hog-build'}.get(tool_id, tool_id)
        directory = ROOT / 'source' / folder
        checkout(tool['source_url'], directory, tool['commit_or_digest'])
        if tool_id == 'git-secrets':
            return
        env = os.environ.copy()
        if tool_id == 'scratch-scanner-rs':
            dep = tool['source_dependencies'][0]
            checkout(dep['repository'], ROOT / 'source/Gossip-rs', dep['commit'])
            boost = tool['native_dependencies'][0]
            archive = ROOT / 'source/boost_1_88_0.tar.gz'
            download(boost['url'], archive, boost['sha256'])
            with tarfile.open(archive) as bundle:
                members = [m for m in bundle.getmembers()
                           if m.name.startswith('boost_1_88_0/boost/')]
                bundle.extractall(ROOT / 'source', members=members, filter='data')
            env['BOOST_ROOT'] = str(ROOT / 'source/boost_1_88_0')
        if tool_id == 'rusty-hog':
            shutil.copyfile(ROOT / 'rusty-hog-Cargo.lock', directory / 'Cargo.lock')
        cmd = ['cargo', 'build', '--release', '--locked', '-j', '2']
        if tool_id == 'rusty-hog':
            cmd += ['--bin', 'duroc_hog']
        run(cmd, cwd=directory, env=env)
    else:
        directory = ROOT / 'source' / tool_id
        directory.mkdir(exist_ok=True)
        archive = directory / tool['asset_url'].rsplit('/', 1)[1]
        download(tool['asset_url'], archive, tool['commit_or_digest'])
        executable_name = Path(tool['executable']).name
        if tarfile.is_tarfile(archive):
            with tarfile.open(archive) as bundle:
                bundle.extractall(directory, filter='data')
            binary = next(p for p in directory.rglob(executable_name) if p.is_file())
        elif zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(directory)
            binary = next(p for p in directory.rglob(executable_name) if p.is_file())
        else:
            binary = archive
        binary.chmod(0o755)
        link = ROOT / 'binaries' / executable_name
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(binary)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tools', nargs='+', help='Tool IDs from manifest.json')
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    tools = {tool['id']: tool for tool in manifest['tools']}
    (ROOT / 'source').mkdir(exist_ok=True)
    (ROOT / 'binaries').mkdir(exist_ok=True)
    for tool_id in args.tools:
        restore(tools[tool_id])

if __name__ == '__main__':
    main()
