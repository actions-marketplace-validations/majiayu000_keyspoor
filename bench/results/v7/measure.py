#!/usr/bin/env python3
"""Paired native process measurements for the credential-context fix."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import statistics

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('benchmark', ROOT / 'bench/run.py')
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def scan(binary, path):
    run = benchmark.measure([str(binary), 'scan', str(path), '--format', 'json'], 120)
    report = json.loads(run.pop('_stdout'))
    run.pop('_stderr')
    if run['status'] != 'finished' or run['exit_code'] not in (0, 1) or not report['complete'] or report['errors']:
        raise RuntimeError('Measurement did not complete; raw output withheld')
    run['findings'] = len(report['findings'])
    run['files'] = report['stats']['files']
    run['bytes'] = report['stats']['bytes']
    if not run['files']:
        raise RuntimeError('Measurement scanned no files')
    locations = sorted((f['path'], f['start'], f['end']) for f in report['findings'])
    run['locations_sha256'] = hashlib.sha256(json.dumps(locations).encode()).hexdigest()
    return run


def summary(runs):
    return {'median_wall_ms': statistics.median(r['wall_seconds'] * 1000 for r in runs),
            'median_cpu_ms': statistics.median((r['user_seconds'] + r['system_seconds']) * 1000 for r in runs),
            'median_peak_rss_bytes': statistics.median(r['peak_rss_bytes'] for r in runs)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--sources', type=Path, required=True, help='Pinned repository snapshot metadata from the adoption trial')
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--pairs', type=int, default=20)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.pairs < 1:
        parser.error('Use a fresh output path and a positive pair count')
    sources = json.loads(args.sources.read_text())
    cases = [(s['repository'].rsplit('/', 1)[-1], Path(s['directory'])) for s in sources]
    fixture = json.loads((args.corpus / 'manifest.json').read_text())
    for name in ('throughput-16mib', 'throughput-128mib'):
        cases.append((name, args.corpus / fixture['datasets'][name]['path']))
    result = {'pairs': args.pairs, 'platform': platform.platform(), 'machine': platform.machine(),
              'method': 'New native processes, one warmup each, alternating order by pair; OS cache uncontrolled. RSS is scanner-process wait4 peak.',
              'sources': sources, 'binaries': {}, 'cases': []}
    for label in ('before', 'after'):
        binary = getattr(args, label).resolve()
        result['binaries'][label] = {'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    for name, path in cases:
        runs = {label: [] for label in ('before', 'after')}
        warmups = {label: scan(getattr(args, label).resolve(), path) for label in runs}
        for pair in range(args.pairs):
            order = ('before', 'after') if pair % 2 == 0 else ('after', 'before')
            for label in order:
                run = scan(getattr(args, label).resolve(), path)
                if run['locations_sha256'] != warmups[label]['locations_sha256']:
                    raise RuntimeError('Nondeterministic finding locations')
                run['pair'] = pair
                runs[label].append(run)
        if (warmups['before']['files'], warmups['before']['bytes']) != (warmups['after']['files'], warmups['after']['bytes']):
            raise RuntimeError('Before and after processed different input sizes')
        if name.startswith('throughput-') and warmups['before']['locations_sha256'] != warmups['after']['locations_sha256']:
            raise RuntimeError('Synthetic throughput detection locations changed')
        row = {'name': name, 'path': str(path), 'warmups': warmups, 'runs': runs,
               'summary': {label: summary(items) for label, items in runs.items()}}
        result['cases'].append(row)
        print(name, row['summary'], flush=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
