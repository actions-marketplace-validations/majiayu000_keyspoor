#!/usr/bin/env python3
"""Append a pinned, unlabelled real-source dataset to an existing corpus."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request


def fetch(url):
    request = urllib.request.Request(url,headers={'User-Agent':'secret-scan-benchmark'})
    with urllib.request.urlopen(request,timeout=60) as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus',type=Path,required=True)
    parser.add_argument('--repository',default='rust-lang/regex')
    parser.add_argument('--ref',required=True,help='commit, tag or branch to resolve and pin')
    parser.add_argument('--name',default='real-regex')
    args = parser.parse_args()
    manifest_path = args.corpus/'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if args.name in manifest['datasets']:
        parser.error('dataset already exists')
    commit = json.loads(fetch(f'https://api.github.com/repos/{args.repository}/commits/{args.ref}'))['sha']
    url = f'https://codeload.github.com/{args.repository}/tar.gz/{commit}'
    archive = fetch(url)
    target = args.corpus/args.name
    target.mkdir(parents=True,exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as source:
        for item in source:
            parts = Path(item.name).parts[1:]
            if not parts:
                continue
            path = target.joinpath(*parts)
            if not path.resolve().is_relative_to(target.resolve()):
                raise ValueError('archive traversal')
            if item.isdir():
                path.mkdir(parents=True,exist_ok=True)
            elif item.isfile():
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(source.extractfile(item).read())
            else:
                raise ValueError('unsupported non-regular source archive entry')
    metadata = {'path':args.name,'mode':'fs','labelled':False,'source_url':f'https://github.com/{args.repository}',
                'requested_ref':args.ref,'commit':commit,'archive_url':url,'archive_sha256':hashlib.sha256(archive).hexdigest(),
                'bytes':sum(p.stat().st_size for p in target.rglob('*') if p.is_file()),
                'quality_note':'Unlabelled public source: report detection counts only, never precision or false-positive rates.'}
    manifest['datasets'][args.name] = metadata
    manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(metadata))

if __name__=='__main__':
    main()
