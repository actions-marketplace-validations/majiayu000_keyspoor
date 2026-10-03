#!/usr/bin/env python3
"""Merge measured artifacts in order, refusing mixed binary hashes per tool."""
import argparse
import json
from pathlib import Path


def merge(paths):
    rows, metadata, artifacts = {}, {}, []
    launched_tools = set()
    corpus_hashes, corpus_roles = set(), set()
    for path in paths:
        artifact = json.loads(path.read_text())
        if artifact.get('schema_version')!=2 or artifact.get('method',{}).get('scoring_version')!=2:
            raise ValueError('only schema/scoring v2 artifacts can be merged; preserve v1 results separately')
        corpus_hashes.add(artifact['corpus_manifest_sha256'])
        corpus_roles.add(artifact['method']['corpus_role'])
        if len(corpus_hashes)>1 or len(corpus_roles)>1:
            raise ValueError('different corpora or evaluation roles cannot be merged into one score table')
        tools = {t['id']:t for t in artifact['tools']}
        artifacts.append({'path':str(path),'timestamp_utc':artifact['timestamp_utc'],'runner_sha256':artifact.get('runner_sha256'),'method':artifact['method']})
        for row in artifact['results']:
            if any(run.get('exit_code') is not None for run in row.get('runs',[])):
                launched_tools.add(row['tool'])
            tool = tools[row['tool']]
            copy = dict(row, source_artifact=str(path), tool_digest=tool.get('commit_or_digest'),tool_version=tool.get('version'))
            rows[(row['tool'],row.get('dataset'))] = copy
            metadata[row['tool']] = tool
    for tool_id in metadata:
        hashes = {r['tool_digest'] for r in rows.values() if r['tool']==tool_id and r.get('runs')}
        if len(hashes)>1:
            raise ValueError(f'{tool_id} has mixed binary versions across selected datasets; rerun every retained dataset or merge separately')
    # A later successful dataset supersedes an earlier whole-tool unavailable row.
    for key in list(rows):
        if key[1] is None and any(k[0]==key[0] and k[1] is not None for k in rows):
            del rows[key]
    corpus_role = next(iter(corpus_roles))
    interpretation = ('Declared frozen synthetic holdout.' if corpus_role=='holdout' else 'Development-informed synthetic regression/diagnostic results, not an independent holdout.')
    return {'schema_version':2,'scoring_version':2,'corpus_manifest_sha256':next(iter(corpus_hashes)),
            'corpus_role':corpus_role,'executed_tool_count':len(launched_tools),'executed_tools':sorted(launched_tools),
            'interpretation':interpretation+' Precision is conditional on localized unique findings; recall is a confirmed-location lower bound. Unlocalized outputs are separate from false positives and duplicates. Real-source results have no accuracy labels. Default rule sets differ; input throughput alone is not an efficiency or accuracy ranking.',
            'artifacts':artifacts,'tools':list(metadata.values()),'results':list(rows.values())}



def markdown(data):
    rows = {(r['tool'],r.get('dataset')):r for r in data['results']}
    lines = ['# Final measured comparison','',data['interpretation'],'',*data.get('corpus_limitations',[]),'',
             '| Tool | Quality TP / FP / FN | Unlocalized | 16 MiB, ms (TP/labels) | 128 MiB, ms (TP/labels) | Real source, ms | Real peak RSS, MiB | Quality status |',
             '|---|---|---:|---:|---:|---:|---:|---|']
    def duration(tool,dataset):
        row = rows.get((tool,dataset),{})
        if row.get('status')!='ok': return row.get('status','—')
        value = row.get('summary',{}).get('median_seconds')
        if value is None: return '—'
        text = f'{value*1000:.1f}'
        quality = row.get('quality')
        if dataset.startswith('throughput-') and quality:
            text += f" ({quality['tp']}/{quality['positive_labels']})"
        return text
    for tool in data['tools']:
        name=tool['id'];qrow=rows.get((name,'quality'),{})
        q=qrow.get('quality');quality=f"{q['tp']} / {q['fp']} / {q['fn']}" if q else '—'
        fallback=rows.get((name,None),{})
        status=qrow.get('status',fallback.get('status','not measured'))
        real = rows.get((name,'real-regex'),{})
        rss = real.get('summary',{}).get('max_peak_rss_bytes')
        lines.append('| '+' | '.join([name,quality,str(q.get('unlocalized','—')) if q else '—',duration(name,'throughput-16mib'),duration(name,'throughput-128mib'),duration(name,'real-regex'),f'{rss/1048576:.1f}' if rss is not None else '—',status])+' |')
    lines += ['', 'Measured capability probes use default commands; a miss does not prove that no optional mode supports the feature. “Unsupported” means this harness has no confirmed command adapter for that input mode.', '',
              '| Tool | Boundary/encoding probes | ZIP / TAR member location | History target found | Index target found |', '|---|---|---|---|---|']
    for tool in data['tools']:
        name=tool['id'];cap=rows.get((name,'capabilities'),{});q=cap.get('quality',{})
        score=f"{q['tp']}/{q['positive_labels']}" if q else cap.get('status','—')
        archives=cap.get('archive_probes',[])
        archive=' / '.join('yes' if a['reported_member'] else ('archive only' if a['reported_archive'] else 'no') for a in archives) or '—'
        modes=[]
        for ds in ('git_history','staged'):
            row=rows.get((name,ds),{});quality=row.get('quality')
            if quality: modes.append(f"{quality['tp']}/{quality['positive_labels']}"+(' + scope violation' if row.get('scope_violation') else ''))
            elif row.get('file_level_quality'): modes.append('file-level only')
            else: modes.append(row.get('status','—'))
        lines.append('| '+' | '.join([name,score,archive,*modes])+' |')
    lines += ['', f"Actually launched scanners: {data['executed_tool_count']}. Failed/incomplete launched scans count as attempts; unsupported commands and unavailable tools do not.", '', 'Timing entries include startup and output processing. Rows with zero injected-secret recall must not be presented as equivalent detection throughput. Unavailable, incomplete and unmeasured tools have no numeric zero score. Version/digest, individual repeats, CPU/RSS, locations, scope notes and source artifacts are retained in the merged JSON.']
    return '\n'.join(lines)+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts',nargs='+',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists() or args.output.with_suffix('.md').exists():
        parser.error('output already exists; choose a new artifact path to preserve previous results')
    data=merge(args.artifacts)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(data,indent=2)+'\n')
    args.output.with_suffix('.md').write_text(markdown(data))
    print('merged',len(data['tools']),'tools;',len(data['results']),'rows')

if __name__=='__main__': main()
