#!/usr/bin/env python3
"""Offline process benchmark. Raw scanner output is never saved in reports."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import tempfile
import threading
import time


def measure(command, timeout, cwd=None, env_extra=None):
    # Do not pass provider credentials inherited by the caller to scanners.
    env = {k: v for k, v in os.environ.items() if k in ('PATH','HOME','TMPDIR','SYSTEMROOT','LANG','LC_ALL','DYLD_LIBRARY_PATH','LD_LIBRARY_PATH')}
    env.update({'NO_COLOR':'1', 'CI':'true'})
    env.update(env_extra or {})
    start = time.perf_counter()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            child = subprocess.Popen(command, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
        except OSError as exc:
            return {'status':'execution_error','error_type':type(exc).__name__,'wall_seconds':time.perf_counter()-start,'exit_code':None,'_stdout':'','_stderr':''}
        expired = threading.Event()
        def terminate():
            expired.set()
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        timer = threading.Timer(timeout, terminate)
        timer.start()
        try:
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
        finally:
            timer.cancel()
        elapsed = time.perf_counter()-start
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(), err.read()
    return {'status':'timeout' if expired.is_set() else 'finished', 'exit_code':child.returncode,
            'wall_seconds':elapsed,'user_seconds':usage.ru_utime,'system_seconds':usage.ru_stime,
            'peak_rss_bytes':usage.ru_maxrss * (1 if platform.system() == 'Darwin' else 1024),
            'stdout_bytes':len(stdout),'stderr_bytes':len(stderr),
            'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest(),
            '_stdout':stdout.decode('utf-8',errors='replace'),'_stderr':stderr.decode('utf-8',errors='replace')}


def relative_path(raw, root):
    from urllib.parse import unquote
    value = unquote(str(raw or '').replace('file://',''))
    p = Path(value)
    if p.is_absolute():
        try:
            return p.relative_to(root.resolve()).as_posix()
        except ValueError:
            return p.as_posix()
    value = p.as_posix().removeprefix('./')
    # Some tools emit paths relative to process cwd rather than corpus.
    try:
        return (Path.cwd()/p).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return value


def parse_output(parser, stdout, stderr, root):
    data = None
    if parser not in ('trufflehog','ripsecrets','git_secrets'):
        data = json.loads(stdout)
    findings = []
    complete = True
    stats = {}
    def add(path, start=None, end=None, line=None, rule=None, column=None, revision=None):
        if str(path or '').startswith('git:'):
            parts = str(path).split(':',2)
            if len(parts)==3:
                _, origin_revision, path = parts
                revision = revision or (':index' if origin_revision in ('index','staged') else origin_revision)
        item = {'path':relative_path(path,root)} if isinstance(path,str) and path else {}
        for key, value in [('start',start),('end',end),('line',line),('rule_id',rule),('column',column),('revision',revision)]:
            if value is not None:
                item[key] = value
        findings.append(item)
    if parser in ('secret_scan','normalized'):
        if not isinstance(data,dict) or 'findings' not in data or 'complete' not in data:
            raise ValueError('missing normalized result contract')
        complete = data['complete']
        if not isinstance(complete,bool) or not isinstance(data['findings'],list):
            raise ValueError('invalid normalized result contract')
        stats = {k:v for k,v in data.get('stats',{}).items() if k in ('files','bytes','skipped','detection_passes','elapsed_ms') and isinstance(v,(int,float))}
        for f in data.get('findings',[]):
            add(f.get('path'),f.get('start'),f.get('end'),f.get('line'),f.get('rule_id'),f.get('column'),f.get('revision'))
            if isinstance(f.get('coordinate_space'),str): findings[-1]['coordinate_space'] = f['coordinate_space']
    elif parser in ('gitleaks','betterleaks'):
        if not isinstance(data,list): raise ValueError('expected findings array')
        for f in data:
            add(f.get('File',f.get('file')),line=f.get('StartLine',f.get('start_line')),rule=f.get('RuleID',f.get('rule_id')),column=f.get('StartColumn'),revision=f.get('Commit') or None)
    elif parser == 'whispers':
        if not isinstance(data,list): raise ValueError('expected findings array')
        for f in data:
            add(f.get('file'),line=f.get('line'),rule=f.get('rule_id'))
    elif parser == 'detect_secrets':
        if not isinstance(data,dict) or not isinstance(data.get('results'),dict):
            raise ValueError('missing detect-secrets results')
        for path, items in data['results'].items():
            for f in items:
                add(path,line=f.get('line_number'),rule=f.get('type'))
    elif parser == 'trufflehog':
        for row in stdout.splitlines():
            if not row.strip():
                continue
            f = json.loads(row)
            metadata = f.get('SourceMetadata',{}).get('Data',{})
            source = next(iter(metadata.values()),{})
            add(source.get('file'),line=source.get('line'),rule=f.get('DetectorName'),revision=source.get('commit'))
    elif parser == 'secretlint':
        if not isinstance(data,list): raise ValueError('expected file results array')
        stats = {'files':len(data)}
        for file in data:
            for f in file.get('messages',[]):
                loc = f.get('loc',{}).get('start',{})
                span = f.get('range') or [None,None]
                # Secretlint offsets are JS UTF-16 units, not bytes; use line for correctness.
                add(file.get('filePath'),line=f.get('line',loc.get('line')),rule=f.get('ruleId'),column=f.get('column',loc.get('column')))
    elif parser == 'sarif':
        if not isinstance(data,dict) or 'runs' not in data:
            raise ValueError('missing SARIF runs')
        for run in data.get('runs',[]):
            if any(i.get('executionSuccessful') is False for i in run.get('invocations',[])):
                complete = False
            for f in run.get('results',[]):
                for loc in f.get('locations') or [{}]:
                    loc = loc.get('physicalLocation',{})
                    region = loc.get('region',{})
                    offset = region.get('byteOffset')
                    length = region.get('byteLength')
                    end = offset+length if isinstance(offset,int) and isinstance(length,int) else None
                    add(loc.get('artifactLocation',{}).get('uri'),start=offset if end is not None else None,end=end,line=region.get('startLine'),rule=f.get('ruleId'))
    elif parser in ('ripsecrets','git_secrets'):
        import re
        for line in stdout.splitlines():
            match = re.match(r'^(.*?):(\d+):',line)
            if match:
                add(match[1],line=int(match[2]))
    else:
        raise ValueError('unsupported parser: '+parser)
    if parser=='sarif' and 'persist_incomplete=' in stderr:
        for row in stderr.splitlines():
            key, separator, value = row.partition('=')
            if separator and key in ('files','bytes','errors','dropped_findings','persist_emit_failures') and value.split(' ')[0].isdigit():
                stats[key] = int(value.split(' ')[0])
            if key=='persist_incomplete' and value.strip()=='true': complete = False
        if any(stats.get(k,0)>0 for k in ('errors','dropped_findings','persist_emit_failures')):
            complete = False
    return {'complete':bool(complete),'findings':[safe_finding(f) for f in findings],'stats':stats}


def safe_finding(finding):
    """Persist only source metadata; never snippets, matches, values or messages."""
    strings = ('path','rule_id','revision','coordinate_space')
    integers = ('start','end','line','column')
    result = {key:value for key,value in finding.items()
              if (key in strings and isinstance(value,str)) or (key in integers and type(value) is int)}
    invalid = [key for key in integers if finding.get(key) is not None and type(finding[key]) is not int]
    invalid.extend(key for key in finding.get('invalid_location_fields',[]) if key in integers)
    if invalid: result['invalid_location_fields'] = sorted(set(invalid))
    return result


def score_findings(findings, labels, file_limits=None):
    positive_indices = {i for i,l in enumerate(labels) if l['label']=='positive'}
    negative_indices = {i for i,l in enumerate(labels) if l['label']=='negative'}
    matched, negative_hits, unresolved_negatives = set(), set(), set()
    first_label_evidence, seen_locations = {}, {}
    evidence = []
    location_quality = {'exact_span':0,'overlap_span':0,'line_only':0}
    by_group = collections.defaultdict(lambda:{'tp':0,'total':0})
    by_provider = collections.defaultdict(lambda:{'tp':0,'total':0})
    for i in positive_indices:
        label = labels[i]
        by_group[label.get('group','unspecified')]['total'] += 1
        by_provider[label.get('provider','unspecified')]['total'] += 1

    def same_source(f,label):
        return f.get('path')==label['path'] and not (f.get('revision') and label.get('revision') and f['revision']!=label['revision'])

    for index, original in enumerate(findings):
        finding = safe_finding(original)
        item = dict(finding, finding_index=index)
        related = [i for i,l in enumerate(labels) if same_source(finding,l)]
        issue = None
        path = finding.get('path')
        has_span = original.get('start') is not None or original.get('end') is not None
        if finding.get('invalid_location_fields'):
            issue = 'invalid_coordinate_type'
        elif not path or path=='.':
            issue = 'missing_path'
        elif file_limits is not None and path not in file_limits:
            issue = 'unknown_source_path'
        elif has_span:
            if type(original.get('start')) is not int or type(original.get('end')) is not int or not (0 <= original['start'] < original['end']):
                issue = 'invalid_byte_span'
            elif finding.get('coordinate_space','source_bytes') != 'source_bytes':
                issue = 'non_source_coordinate_space'
            elif file_limits is not None and finding['end'] > file_limits[path]['bytes']:
                issue = 'byte_span_out_of_bounds'
        elif type(original.get('line')) is not int or original['line'] < 1:
            issue = 'missing_or_invalid_line'
        elif file_limits is not None and finding['line'] > file_limits[path]['lines']:
            issue = 'line_out_of_bounds'

        candidates = []
        if issue is None:
            if has_span:
                exact = [i for i in related if finding['start']==labels[i]['start'] and finding['end']==labels[i]['end']]
                overlap = [i for i in related if min(finding['end'],labels[i]['end'])-max(finding['start'],labels[i]['start']) >= (labels[i]['end']-labels[i]['start'])*0.5
                           and finding['end']-finding['start'] <= max(1,labels[i]['end']-labels[i]['start'])*4]
                candidates = exact or overlap
                quality = 'exact_span' if exact else 'overlap_span'
                if not candidates and any(min(finding['end'],labels[i]['end']) > max(finding['start'],labels[i]['start']) for i in related):
                    issue = 'insufficient_span_precision'
            else:
                candidates = [i for i in related if labels[i].get('line',0) <= finding['line'] <= labels[i].get('end_line',labels[i].get('line',0))]
                quality = 'line_only'
            if len(candidates)>1:
                issue = 'ambiguous_span' if has_span else 'ambiguous_line'
        if issue:
            item.update(classification='unlocalized',reason=issue)
            possible = candidates or related
            if not path or path=='.': possible = list(negative_indices)
            unresolved_negatives.update(set(possible) & negative_indices)
        else:
            location = (path,finding.get('revision'),finding.get('start'),finding.get('end')) if has_span else (path,finding.get('revision'),'line',finding['line'])
            label_index = candidates[0] if candidates else None
            previous = first_label_evidence.get(label_index) if label_index is not None else seen_locations.get(location)
            item['location_quality'] = quality if candidates else ('byte_span' if has_span else 'line_only')
            if label_index is not None: item['matched_label_id'] = labels[label_index]['id']
            if previous is not None:
                item.update(classification='duplicate',duplicate_of=previous)
            elif label_index in positive_indices:
                matched.add(label_index)
                location_quality[quality] += 1
                label = labels[label_index]
                by_group[label.get('group','unspecified')]['tp'] += 1
                by_provider[label.get('provider','unspecified')]['tp'] += 1
                item['classification'] = 'tp'
            else:
                item.update(classification='fp',reason='negative_label' if label_index is not None else 'unmatched_location')
                if label_index is not None: negative_hits.add(label_index)
            if previous is None:
                seen_locations[location] = index
                if label_index is not None: first_label_evidence[label_index] = index
        evidence.append(item)

    counts = collections.Counter(item['classification'] for item in evidence)
    tp,fp,fn = counts['tp'],counts['fp'],len(positive_indices)-len(matched)
    precision = tp/(tp+fp) if tp+fp else None
    recall = tp/len(positive_indices) if positive_indices else None
    f1 = 2*precision*recall/(precision+recall) if precision is not None and recall is not None and precision+recall else (0.0 if positive_indices else None)
    for groups in (by_group,by_provider):
        for group in groups.values():
            group['recall'] = group['tp']/group['total'] if group['total'] else None
    unresolved_negatives -= negative_hits
    return {'scoring_version':2,'tp':tp,'fp':fp,'fn':fn,'unlocalized':counts['unlocalized'],
            'negative_labels_flagged':len(negative_hits),'negative_labels_unresolved':len(unresolved_negatives),
            'tn':len(negative_indices)-len(negative_hits)-len(unresolved_negatives),
            'positive_labels':len(positive_indices),'negative_labels':len(negative_indices),
            'precision':precision,'precision_scope':'localized_unique_findings_only',
            'recall':recall,'recall_scope':'confirmed_location_lower_bound','f1':f1,
            'localization_rate':(len(findings)-counts['unlocalized'])/len(findings) if findings else None,
            'duplicate_findings':counts['duplicate'],'location_quality':location_quality,
            'by_group':dict(by_group),'by_provider':dict(by_provider),
            'missed_label_ids':[labels[i]['id'] for i in sorted(positive_indices-matched)],'evidence':evidence}


def hardware():
    value = {'system':platform.platform(),'machine':platform.machine(),'python':platform.python_version(),'logical_cpus':os.cpu_count()}
    if platform.system() == 'Darwin':
        for key,name in [('hw.memsize','memory_bytes'),('machdep.cpu.brand_string','cpu')]:
            r = subprocess.run(['sysctl','-n',key],capture_output=True,text=True)
            if r.returncode==0:
                value[name] = r.stdout.strip()
    return value


def report_markdown(result):
    lines = ['# Secret scanner benchmark','',f"Generated: {result['timestamp_utc']}",'',
             'Offline, default-rule end-to-end comparison. First-run is a new process, not a cold disk-cache claim. Warm runs start new processes after an unmeasured warmup. No provider validation is enabled. Raw scanner output is discarded.',
             '', '| Tool | Dataset | Status | Median ms | Input MiB/s | Peak RSS MiB | TP/FP/FN | Unlocalized | Localized P / recall lower bound / F1 |', '|---|---|---|---:|---:|---:|---|---:|---|']
    def pct(x): return '—' if x is None else f'{x:.3f}'
    for row in result['results']:
        s = row.get('summary',{})
        q = row.get('quality',{})
        quality = '/'.join(str(q[k]) for k in ('tp','fp','fn')) if q else '—'
        prf = '/'.join(pct(q[k]) for k in ('precision','recall','f1')) if q else '—'
        lines.append('| '+ ' | '.join([row['tool'],row.get('dataset','—'),row['status'],f"{s['median_seconds']*1000:.3f}" if s else '—',f"{s['mib_per_second']:.2f}" if s and s.get('mib_per_second') is not None else '—',f"{s['max_peak_rss_bytes']/1048576:.2f}" if s else '—',quality,str(q.get('unlocalized','—')),prf])+' |')
    lines += ['', 'Schema/scoring v2: precision excludes unlocalized results and is conditional on localized unique findings, not a real-world false-positive estimate. Recall is a confirmed-location lower bound; unlocalized findings do not prove a miss or a hit. Duplicate detections do not increase recall. Exact byte-span, overlapping-span and line-only matches are counted separately in JSON; line-only tools have weaker localization evidence. Tools have different default rules and coverage, so throughput alone does not rank engine efficiency. Unavailable and unsupported entries are not zero scores.', '', 'Hardware: `'+json.dumps(result['hardware'],sort_keys=True)+'`', '', 'See the JSON artifact for versions, commands, exits, per-run timings, CPU, RSS, corpus hashes, labels and completeness. RSS is per-child getrusage peak; it is not a simultaneous aggregate for a multiprocess tree.']
    return '\n'.join(lines)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,default=Path(__file__).parent/'tools/manifest.json')
    parser.add_argument('--corpus',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=Path(__file__).parent/'results/v2/latest.json')
    parser.add_argument('--tools',help='comma separated tool IDs')
    parser.add_argument('--datasets',help='comma separated dataset names; defaults to all declared datasets')
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--timeout',type=float,default=120)
    parser.add_argument('--corpus-role',default='synthetic-diagnostic',choices=['synthetic-diagnostic','regression','holdout'])
    args = parser.parse_args()
    if args.repeats < 1: parser.error('--repeats must be positive')
    if args.output.exists() or args.output.with_suffix('.md').exists():
        parser.error('output already exists; choose a new artifact path to preserve previous results')
    corpus = args.corpus.resolve()
    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    corpus_bytes = (corpus/'manifest.json').read_bytes()
    fixture = json.loads(corpus_bytes)
    labels = fixture['entries']
    for label in labels:
        if 'line' not in label:
            path = corpus/label['path']
            if path.is_file():
                label['line'] = path.read_bytes()[:label['start']].count(b'\n')+1
    datasets = fixture.get('datasets', {'quality':{'path':'quality','mode':'fs'},'throughput':{'path':'throughput','mode':'fs'}})
    result = {'schema_version':2,'timestamp_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'hardware':hardware(),
              'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'manifest_sha256':hashlib.sha256(manifest_bytes).hexdigest(),'corpus_manifest_sha256':hashlib.sha256(corpus_bytes).hexdigest(),
              'method':{'scoring_version':2,'corpus_role':args.corpus_role,'quality_interpretation':('Declared frozen synthetic holdout; real-source datasets remain unlabelled.' if args.corpus_role=='holdout' else 'Synthetic regression/diagnostic corpus, not an independent holdout; real-source datasets remain unlabelled.'),'offline':True,'repeats':args.repeats,'timeout_seconds':args.timeout,'cache':'OS cache uncontrolled; warmup before repeats','scoring':'v2 unique location matches; missing/invalid/ambiguous coordinates unlocalized; precision conditional on localized unique findings'},'tools':manifest['tools'],'datasets':datasets,'results':[]}
    selected = set(args.tools.split(',')) if args.tools else None
    for tool in manifest['tools']:
        if selected and tool['id'] not in selected: continue
        if tool.get('status') not in ('available','ready','installed'):
            result['results'].append({'tool':tool['id'],'status':tool.get('status','unavailable'),'reason':tool.get('notes','')})
            continue
        if not tool.get('offline',False):
            result['results'].append({'tool':tool['id'],'status':'unavailable','reason':'offline command not confirmed'})
            continue
        for name in (args.datasets.split(',') if args.datasets else datasets):
            if name not in datasets: continue
            dataset = datasets[name]
            mode = dataset.get('mode','fs')
            command_template = tool.get('commands',{}).get(mode)
            if not command_template:
                result['results'].append({'tool':tool['id'],'dataset':name,'status':'unsupported','reason':'no tested '+mode+' command'})
                continue
            input_path = (corpus/dataset['path']).resolve()
            corpus_files = sorted(p for p in input_path.rglob('*') if p.is_file() and '.git' not in p.parts)
            total_bytes = (dataset.get('bytes') or sum(p.stat().st_size for p in corpus_files)) if mode=='fs' else None
            content_digest = hashlib.sha256()
            file_limits = {} if mode=='fs' else None
            for corpus_file in corpus_files:
                content_digest.update(corpus_file.relative_to(input_path).as_posix().encode()+b'\0')
                content = corpus_file.read_bytes()
                content_digest.update(hashlib.sha256(content).digest())
                if file_limits is not None:
                    file_limits[corpus_file.relative_to(corpus).as_posix()] = {'bytes':len(content),'lines':content.count(b'\n')+int(bool(content) and not content.endswith(b'\n'))}
            row = {'tool':tool['id'],'dataset':name,'mode':mode,'input_bytes':total_bytes,'input_files':len(corpus_files),'worktree_content_sha256':content_digest.hexdigest(),'runs':[],'status':'ok'}
            dataset_labels = [l for l in labels if l.get('dataset','quality')==name] if dataset.get('labelled',True) else []
            with tempfile.TemporaryDirectory(prefix='secret-benchmark-') as tmp:
                report = Path(tmp)/'report.json'
                substitutions = {'input':str(input_path),'output':str(report),'root':str(corpus),'repo':str(input_path)}
                command = [x.format(**substitutions) for x in command_template]
                row['command'] = command
                parsed_first = None
                # first new process, explicit warmup, then repeat new processes with warm filesystem.
                for index in range(args.repeats+2):
                    if report.exists(): report.unlink()
                    measurement = measure(command,args.timeout,cwd=tool.get('cwd'),env_extra=tool.get('env'))
                    raw = report.read_text(errors='replace') if report.exists() else measurement['_stdout']
                    measurement['parsed_output_bytes'] = len(raw.encode('utf-8'))
                    measurement['parsed_output_sha256'] = hashlib.sha256(raw.encode('utf-8')).hexdigest()
                    measurement['output_source'] = 'report_file' if report.exists() else 'stdout'
                    try:
                        parsed = parse_output(tool.get('parser','normalized'),raw,measurement['_stderr'],corpus)
                        # Tools often return input-root relative paths.
                        for f in parsed['findings']:
                            relative_input = input_path.relative_to(corpus).as_posix()
                            if f.get('path') and not Path(f['path']).is_absolute() and not (f['path']==relative_input or f['path'].startswith(relative_input+'/')):
                                f['path'] = (input_path/f['path']).relative_to(corpus).as_posix()
                        measurement['scanner_stats'] = parsed.get('stats',{})
                        if row['input_files'] and parsed.get('stats',{}).get('files')==0:
                            parsed['complete'] = False
                            measurement['coverage_error'] = 'nonempty dataset but scanner reported zero files'
                        measurement['complete'] = parsed['complete']
                        measurement['findings_count'] = len(parsed['findings'])
                        measurement['normalized_findings'] = parsed['findings']
                        measurement['locations_sha256'] = hashlib.sha256(json.dumps(sorted(parsed['findings'],key=lambda x:json.dumps(x,sort_keys=True)),sort_keys=True).encode()).hexdigest()
                        if parsed_first is None: parsed_first = parsed
                    except (ValueError,TypeError,KeyError,AttributeError) as exc:
                        measurement['parse_error'] = type(exc).__name__
                        measurement['complete'] = False
                    measurement.pop('_stdout',None)
                    measurement.pop('_stderr',None)
                    measurement['phase'] = 'cold_process' if index==0 else ('warmup' if index==1 else 'warm_fs')
                    row['runs'].append(measurement)
                    if measurement['status']!='finished' or measurement['exit_code'] not in tool.get('accepted_exit_codes',[0,1]) or not measurement.get('complete'):
                        row['status'] = 'timeout' if measurement['status']=='timeout' else 'failed'
                        break
                row['scan_complete'] = all(r.get('complete') and r['status']=='finished' and r['exit_code'] in tool.get('accepted_exit_codes',[0,1]) for r in row['runs'])
                if row['status']=='ok' and len({r['locations_sha256'] for r in row['runs']}) != 1:
                    row['status'] = 'nondeterministic'
                if row['status']=='ok':
                    warm = [r for r in row['runs'] if r['phase']=='warm_fs']
                    median = statistics.median(r['wall_seconds'] for r in warm)
                    row['summary'] = {'cold_process_seconds':row['runs'][0]['wall_seconds'],'median_seconds':median,'min_seconds':min(r['wall_seconds'] for r in warm),'max_seconds':max(r['wall_seconds'] for r in warm),'mib_per_second':total_bytes/1048576/median if total_bytes is not None else None,'max_peak_rss_bytes':max(r['peak_rss_bytes'] for r in warm)}
                    quality_findings = parsed_first['findings']
                    if dataset.get('archives'):
                        probes = []
                        excluded = []
                        for probe in dataset['archives']:
                            hits = [f for f in quality_findings if Path(probe['path']).name in f.get('path','')]
                            excluded.extend(hits)
                            probes.append({'path':probe['path'],'member':probe['member'],'reported_archive':bool(hits),'reported_member':any(probe['member'] in f['path'] for f in hits),'evidence':'location only; no decoded span or credential validity claim'})
                        row['archive_probes'] = probes
                        row['excluded_unscored_archive_findings'] = len(excluded)
                        quality_findings = [f for f in quality_findings if f not in excluded]
                    if dataset_labels and tool.get('localization')=='file':
                        expected_files = {l['path'] for l in dataset_labels if l['label']=='positive'}
                        observed_files = {f['path'] for f in quality_findings if f.get('path') and f['path']!='.'}
                        row['file_level_quality'] = {'expected_positive_files':len(expected_files),'detected_positive_files':len(expected_files & observed_files),'missed_positive_files':sorted(expected_files-observed_files),'other_reported_files':sorted(observed_files-expected_files),'note':'File-level evidence only; cannot establish byte/line accuracy or distinguish index from worktree content at the same path.'}
                    elif dataset_labels:
                        if mode in ('git','staged'):
                            def at_location(f,label):
                                if f.get('path') != label['path']: return False
                                if type(f.get('start')) is int and type(f.get('end')) is int:
                                    return min(f['end'],label['end']) > max(f['start'],label['start'])
                                return f.get('line') is not None and f['line']==label.get('line')
                            others = [l for l in labels if l.get('dataset','quality')!=name and l['label']=='positive']
                            extra = [f for f in quality_findings if not any(at_location(f,l) for l in dataset_labels) and any(at_location(f,l) for l in others)]
                            row['extra_scope_findings'] = extra
                            row['scope_note'] = 'Known positive fixture locations from other input modes are separately reported, not false positives; extra results in staged mode violate its expected index-only scope.'
                            if mode=='staged' and extra:
                                row['scope_violation'] = True
                                row['status'] = 'scope_violation'
                            else:
                                quality_findings = [f for f in quality_findings if f not in extra]
                        row['quality'] = score_findings(quality_findings,dataset_labels,file_limits=file_limits)
                result['results'].append(row)
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(json.dumps(result,indent=2)+'\n')
            args.output.with_suffix('.md').write_text(report_markdown(result))
            print(tool['id']+' '+name+': '+row['status'],flush=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    args.output.with_suffix('.md').write_text(report_markdown(result))

if __name__ == '__main__':
    main()
