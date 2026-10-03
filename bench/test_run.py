import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('bench_run', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class ScoringTests(unittest.TestCase):
    def test_locations_not_just_counts(self):
        labels = [{'id':'a','path':'a.txt','start':4,'end':12,'label':'positive','provider':'aws','group':'common'}, {'id':'b','path':'b.txt','start':4,'end':12,'label':'negative'}]
        score = runner.score_findings([{'path':'b.txt','start':4,'end':12}], labels)
        self.assertEqual((score['tp'], score['fp'], score['fn']), (0,1,1))

    def test_duplicates_do_not_inflate_recall(self):
        labels = [{'id':'a','path':'a','start':4,'end':12,'label':'positive','group':'common'}]
        score = runner.score_findings([{'path':'a','start':4,'end':12}]*2, labels)
        self.assertEqual((score['tp'],score['duplicate_findings'],score['fn']), (1,1,0))

    def test_line_only_scoring_is_explicit(self):
        labels = [{'id':'a','path':'a','start':4,'end':12,'line':2,'label':'positive'}]
        score = runner.score_findings([{'path':'a','line':2}], labels)
        self.assertEqual(score['tp'], 1)
        self.assertEqual(score['location_quality'], {'exact_span':0,'overlap_span':0,'line_only':1})

    def test_incomplete_is_not_clean(self):
        result = runner.parse_output('secret_scan', '{"complete":false,"findings":[],"errors":[]}', '', Path('.'))
        self.assertFalse(result['complete'])

    def test_git_origin_preserves_revision(self):
        result = runner.parse_output('secret_scan', '{"complete":true,"findings":[{"path":"git:abcdef:deleted.conf","start":1,"end":2}]}', '', Path('.'))
        self.assertEqual(result['findings'][0]['path'], 'deleted.conf')
        self.assertEqual(result['findings'][0]['revision'], 'abcdef')

    def test_invalid_sarif_not_clean(self):
        with self.assertRaises(ValueError):
            runner.parse_output('sarif', '{}', '', Path('.'))

    def test_json_parsers_reject_missing_output(self):
        for parser in ('gitleaks','betterleaks','secretlint','whispers','detect_secrets','sarif','secret_scan'):
            with self.subTest(parser=parser), self.assertRaises(ValueError):
                runner.parse_output(parser, '', '', Path('.'))

    def test_detect_secrets_requires_results(self):
        with self.assertRaises(ValueError):
            runner.parse_output('detect_secrets', '{}', '', Path('.'))

    def test_secretlint_distinguishes_clean_files_from_no_input(self):
        clean = runner.parse_output('secretlint', '[{"filePath":"a.conf","messages":[]}]', '', Path('.'))
        empty = runner.parse_output('secretlint', '[]', '', Path('.'))
        self.assertEqual(clean['stats']['files'], 1)
        self.assertEqual(empty['stats']['files'], 0)

    def test_sarif_failed_invocation_is_incomplete(self):
        parsed = runner.parse_output('sarif', '{"runs":[{"invocations":[{"executionSuccessful":false}],"results":[]}]}', '', Path('.'))
        self.assertFalse(parsed['complete'])

    def test_merge_rejects_mixed_binary_versions(self):
        import json
        spec = importlib.util.spec_from_file_location('bench_merge', Path(__file__).with_name('merge_results.py'))
        merger = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(merger)
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for i, dataset in enumerate(('quality','throughput')):
                artifact = {'schema_version':2,'corpus_manifest_sha256':'corpus','tools':[{'id':'scanner','version':'1','commit_or_digest':str(i)}], 'timestamp_utc':'test', 'method':{'scoring_version':2,'corpus_role':'regression'}, 'results':[{'tool':'scanner','dataset':dataset,'runs':[{}]}]}
                path = Path(tmp)/f'{i}.json'
                path.write_text(json.dumps(artifact))
                paths.append(path)
            with self.assertRaisesRegex(ValueError,'mixed binary'):
                merger.merge(paths)

    def test_sarif_byte_location_without_line(self):
        text = '{"runs":[{"results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.conf"},"region":{"byteOffset":14,"byteLength":40}}}]}]}]}'
        parsed = runner.parse_output('sarif', text, '', Path('.'))
        self.assertEqual(parsed['findings'][0]['start'], 14)
        self.assertEqual(parsed['findings'][0]['end'], 54)

    def test_scratch_dropped_results_are_incomplete(self):
        parsed = runner.parse_output('sarif', '{"runs":[]}', 'files=2\nbytes=1024 (1KiB)\ndropped_findings=1\npersist_incomplete=false\n', Path('.'))
        self.assertFalse(parsed['complete'])
        self.assertEqual(parsed['stats']['bytes'], 1024)

    def test_missing_or_invalid_locations_are_unlocalized(self):
        label = {'id':'p','path':'a','start':4,'end':12,'line':1,'label':'positive'}
        findings = [{'path':'a'}, {'path':'a','line':0}, {'path':'a','line':-1},
                    {'path':'a','start':12,'end':4}, {'line':1},
                    {'path':'a','start':'4','end':'12'}, {'path':'a','line':True}]
        score = runner.score_findings(findings, [label])
        self.assertEqual((score['tp'],score['fp'],score['unlocalized'],score['fn']), (0,0,7,1))
        self.assertIsNone(score['precision'])

    def test_out_of_bounds_location_is_not_false_positive(self):
        score = runner.score_findings([{'path':'a','start':8,'end':40}, {'path':'a','line':9}],
                                      [], file_limits={'a':{'bytes':12,'lines':2}})
        self.assertEqual((score['fp'],score['unlocalized']), (0,2))

    def test_two_candidates_on_same_line_require_span_evidence(self):
        labels = [{'id':'p1','path':'a','start':4,'end':12,'line':1,'label':'positive'},
                  {'id':'p2','path':'a','start':20,'end':28,'line':1,'label':'positive'}]
        line_score = runner.score_findings([{'path':'a','line':1}]*2, labels)
        self.assertEqual((line_score['tp'],line_score['fp'],line_score['unlocalized'],line_score['fn']), (0,0,2,2))
        span_score = runner.score_findings([{'path':'a','start':4,'end':12}, {'path':'a','start':20,'end':28}],labels)
        self.assertEqual((span_score['tp'],span_score['unlocalized'],span_score['fn']), (2,0,0))

    def test_line_with_positive_and_negative_is_ambiguous(self):
        labels = [{'id':'p','path':'a','start':4,'end':12,'line':1,'label':'positive'},
                  {'id':'n','path':'a','start':20,'end':28,'line':1,'label':'negative'}]
        score = runner.score_findings([{'path':'a','line':1}],labels)
        self.assertEqual((score['tp'],score['fp'],score['unlocalized'],score['negative_labels_unresolved']), (0,0,1,1))
        self.assertEqual(score['tn'],0)

    def test_unicode_offsets_are_bytes_and_evidence_omits_raw_fields(self):
        text = '部署😀 prefix VALUE suffix'
        start = text.encode().index(b'VALUE')
        label = {'id':'p','path':'a','start':start,'end':start+5,'line':1,'label':'positive'}
        score = runner.score_findings([{'path':'a','start':start,'end':start+5,'raw':'TEST_PRIVATE_PAYLOAD','message':'TEST_PRIVATE_PAYLOAD'}], [label])
        self.assertEqual(score['tp'],1)
        self.assertEqual(score['evidence'][0]['start'],start)
        self.assertNotIn('TEST_PRIVATE_PAYLOAD',str(score))

    def test_broad_span_covering_two_candidates_is_unlocalized(self):
        labels = [{'id':'p1','path':'a','start':4,'end':12,'line':1,'label':'positive'},
                  {'id':'p2','path':'a','start':20,'end':28,'line':1,'label':'positive'}]
        score = runner.score_findings([{'path':'a','start':4,'end':28}],labels)
        self.assertEqual((score['tp'],score['fp'],score['unlocalized']), (0,0,1))

    def test_duplicate_false_positive_locations_are_separate(self):
        label = {'id':'n','path':'a','start':4,'end':12,'line':1,'label':'negative'}
        score = runner.score_findings([{'path':'a','start':4,'end':12}]*2,[label])
        self.assertEqual((score['fp'],score['duplicate_findings'],score['unlocalized']), (1,1,0))

    def test_sarif_result_without_location_is_retained(self):
        parsed = runner.parse_output('sarif', '{"runs":[{"results":[{"ruleId":"r"}]}]}', '', Path('.'))
        self.assertEqual(len(parsed['findings']),1)
        self.assertEqual(runner.score_findings(parsed['findings'],[])['unlocalized'],1)

    def test_partial_scan_keeps_safe_evidence_without_quality(self):
        import json, subprocess, sys
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'quality').mkdir()
            (root/'quality/a.conf').write_text('credential = TEST_VALUE\n')
            (root/'manifest.json').write_text(json.dumps({'datasets':{'quality':{'path':'quality','mode':'fs'}},'entries':[]}))
            scanner = root/'scanner.py'
            result = {'complete':False,'findings':[{'path':'a.conf','start':13,'end':23,'raw':'TEST_PRIVATE_PAYLOAD'}],'errors':['TEST_PRIVATE_PAYLOAD']}
            scanner.write_text('print('+repr(json.dumps(result))+')')
            tools = root/'tools.json'
            tools.write_text(json.dumps({'tools':[{'id':'fake','status':'available','offline':True,'parser':'normalized','commands':{'fs':[sys.executable,str(scanner)]}}]}))
            output = root/'new-result.json'
            command = [sys.executable,str(Path(__file__).with_name('run.py')),'--manifest',str(tools),'--corpus',str(root),'--output',str(output),'--repeats','1']
            first = subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(first.returncode,0,first.stderr)
            artifact = json.loads(output.read_text())
            self.assertEqual(artifact['schema_version'],2)
            row = artifact['results'][0]
            self.assertEqual(row['status'],'failed')
            self.assertNotIn('quality',row)
            self.assertFalse(row['runs'][0]['complete'])
            self.assertEqual(len(row['runs'][0]['normalized_findings']),1)
            self.assertNotIn('TEST_PRIVATE_PAYLOAD',output.read_text())
            before = output.read_bytes()
            second = subprocess.run(command,capture_output=True,text=True)
            self.assertNotEqual(second.returncode,0)
            self.assertEqual(output.read_bytes(),before)

    def test_parser_invalid_coordinates_do_not_leak_values(self):
        parsed = runner.parse_output('normalized','{"complete":true,"findings":[{"path":"a","line":"TEST_PRIVATE_PAYLOAD"}]}','',Path('.'))
        self.assertNotIn('TEST_PRIVATE_PAYLOAD',str(parsed))
        self.assertEqual(runner.score_findings(parsed['findings'],[])['unlocalized'],1)

    def test_merge_rejects_old_scoring_and_different_corpora(self):
        import json
        spec = importlib.util.spec_from_file_location('bench_merge', Path(__file__).with_name('merge_results.py'))
        merger = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(merger)
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp)/'a.json', Path(tmp)/'b.json'
            artifact = {'schema_version':1,'tools':[],'results':[]}
            first.write_text(json.dumps(artifact))
            with self.assertRaisesRegex(ValueError,'schema/scoring v2'):
                merger.merge([first])
            artifact.update(schema_version=2,corpus_manifest_sha256='corpus-a',timestamp_utc='test',method={'scoring_version':2,'corpus_role':'regression'})
            first.write_text(json.dumps(artifact))
            artifact['corpus_manifest_sha256']='corpus-b'
            second.write_text(json.dumps(artifact))
            with self.assertRaisesRegex(ValueError,'different corpora'):
                merger.merge([first,second])

    def test_staged_extra_scope_is_visible_and_not_clean(self):
        import json, subprocess, sys
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'repo').mkdir()
            (root/'repo/partial.conf').write_text('public worktree\n')
            labels = [{'id':'index','path':'repo/partial.conf','start':4,'end':12,'line':1,'label':'positive','dataset':'staged','revision':':index'},
                      {'id':'worktree','path':'repo/partial.conf','start':20,'end':28,'line':3,'label':'positive','dataset':'worktree'}]
            (root/'manifest.json').write_text(json.dumps({'datasets':{'staged':{'path':'repo','mode':'staged'}},'entries':labels}))
            scanner = root/'scanner.py'
            scanner.write_text('print('+repr(json.dumps({'complete':True,'findings':[{'path':'partial.conf','start':4,'end':12},{'path':'partial.conf','start':20,'end':28}]}))+')')
            tools = root/'tools.json'
            tools.write_text(json.dumps({'tools':[{'id':'fake','status':'available','offline':True,'parser':'normalized','commands':{'staged':[sys.executable,str(scanner)]}}]}))
            output=root/'result.json'
            completed=subprocess.run([sys.executable,str(Path(__file__).with_name('run.py')),'--manifest',str(tools),'--corpus',str(root),'--output',str(output),'--repeats','1'],capture_output=True,text=True)
            self.assertEqual(completed.returncode,0,completed.stderr)
            row=json.loads(output.read_text())['results'][0]
            self.assertTrue(row['scan_complete'])
            self.assertEqual(row['status'],'scope_violation')
            self.assertEqual(len(row['extra_scope_findings']),1)
            self.assertEqual((row['quality']['tp'],row['quality']['fp']), (1,1))

    def test_resource_measurement(self):
        import sys
        result = runner.measure([sys.executable, '-c', 'print("ok")'], 5)
        self.assertEqual(result['exit_code'], 0)
        self.assertGreater(result['wall_seconds'], 0)
        self.assertGreater(result['peak_rss_bytes'], 0)
        self.assertEqual(result['_stdout'].strip(), 'ok')

    def test_timeout_is_recorded(self):
        import sys
        result = runner.measure([sys.executable, '-c', 'import time; time.sleep(10)'], 0.05)
        self.assertEqual(result['status'], 'timeout')

if __name__ == '__main__':
    unittest.main()
