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
                artifact = {'tools':[{'id':'scanner','version':'1','commit_or_digest':str(i)}], 'timestamp_utc':'test', 'method':{}, 'results':[{'tool':'scanner','dataset':dataset,'runs':[{}]}]}
                path = Path(tmp)/f'{i}.json'
                path.write_text(json.dumps(artifact))
                paths.append(path)
            with self.assertRaises(ValueError):
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
