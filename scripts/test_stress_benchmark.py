"""Collector and process-wait contract tests; no scanner workload required."""
from contextlib import ExitStack
import copy
import importlib.util
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


SPEC = importlib.util.spec_from_file_location("stress_benchmark", Path(__file__).with_name("stress_benchmark.py"))
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class MeasureWaitTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.now = 0.0
        self.child = Mock(pid=42, returncode=None)
        self.selector = Mock()
        self.registered = {}

        def register(stream, events, name):
            self.registered[stream] = SimpleNamespace(fileobj=stream, fd=name, data=name)

        def select(timeout):
            self.assertTrue(self.registered, "must not wait on an empty selector")
            return [(key, BENCH.selectors.EVENT_READ) for key in self.registered.values()]

        def sleep(delay):
            self.now += delay

        self.selector.register.side_effect = register
        self.selector.unregister.side_effect = self.registered.pop
        self.selector.get_map.side_effect = lambda: self.registered
        self.selector.select.side_effect = select
        self.stack.enter_context(patch.object(BENCH.subprocess, "Popen", return_value=self.child))
        self.stack.enter_context(patch.object(BENCH.selectors, "DefaultSelector", return_value=self.selector))
        self.stack.enter_context(patch.object(BENCH.time, "perf_counter", side_effect=lambda: self.now))
        self.sleep = self.stack.enter_context(patch.object(BENCH.time, "sleep", side_effect=sleep))
        self.stack.enter_context(patch.object(BENCH.os, "read", return_value=b""))
        self.wait4 = self.stack.enter_context(patch.object(BENCH.os, "wait4"))
        self.collector = self.stack.enter_context(patch.object(BENCH, "Collector")).return_value
        self.collector.finish.return_value = {}
        self.usage = SimpleNamespace(ru_maxrss=12345, ru_utime=0.02, ru_stime=0.003)
        self.case = {"mode": "scan", "path": Path("/fixture/dense.txt")}

    def measure(self, timeout=1):
        return BENCH.measure(Path("/synthetic/scanner"), self.case, 1, timeout)

    def assert_closed(self):
        self.selector.close.assert_called_once_with()
        self.child.stdout.close.assert_called_once_with()
        self.child.stderr.close.assert_called_once_with()

    def test_pipe_eof_before_exit_avoids_empty_selector_wait_and_keeps_usage(self):
        self.wait4.side_effect = [(0, 0, None), (0, 0, None), (42, 1 << 8, self.usage)]
        result = self.measure()
        self.selector.select.assert_called_once_with(0.1)
        self.sleep.assert_called_once_with(0.001)
        self.assertEqual(self.wait4.call_count, 3)
        for call in self.wait4.call_args_list:
            self.assertEqual(call.args, (42, BENCH.os.WNOHANG))
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["wall_ms"], 1)
        self.assertEqual(result["peak_rss_bytes"], 12345)
        self.assertEqual(result["user_ms"], 20)
        self.assertEqual(result["system_ms"], 3)
        self.collector.finish.assert_called_once_with(1)
        self.child.kill.assert_not_called()
        self.child.wait.assert_not_called()
        self.assert_closed()

    def test_exit_ready_after_pipe_eof_does_not_sleep(self):
        self.wait4.side_effect = [(0, 0, None), (42, 1 << 8, self.usage)]
        result = self.measure()
        self.selector.select.assert_called_once_with(0.1)
        self.sleep.assert_not_called()
        self.assertEqual(result["wall_ms"], 0)
        self.child.kill.assert_not_called()
        self.child.wait.assert_not_called()
        self.assert_closed()

    def test_exited_child_is_reaped_once_and_buffered_pipes_are_drained_before_finish(self):
        self.wait4.return_value = (42, 1 << 8, self.usage)
        records = [{"type": "progress", "stats": {"files": 1}},
                   {"type": "summary", "complete": True}]
        stdout = b"".join(BENCH.json.dumps(record).encode() + b"\n" for record in records)
        stderr = b"synthetic diagnostic\n"
        chunks = {"stdout": [stdout[:12], stdout[12:], b""],
                  "stderr": [stderr, b""]}

        def read(fd, size):
            self.assertEqual(self.child.returncode, 1, "child must already be reaped")
            return chunks[fd].pop(0)

        def finish(exit_code):
            self.assertEqual(exit_code, 1)
            self.assertFalse(self.registered, "both pipes must reach EOF before validation")
            self.assertTrue(all(not remaining for remaining in chunks.values()))
            return {}

        self.collector.accept.return_value = False
        self.collector.finish.side_effect = finish
        with patch.object(BENCH.os, "read", side_effect=read):
            result = self.measure()
        self.wait4.assert_called_once_with(42, BENCH.os.WNOHANG)
        self.assertEqual(self.collector.method_calls,
                         [call.accept(record) for record in records] + [call.finish(1)])
        self.assertEqual(result["stdout_bytes"], len(stdout))
        self.assertEqual(result["stderr_bytes"], len(stderr))
        self.assertEqual(result["peak_rss_bytes"], self.usage.ru_maxrss)
        self.sleep.assert_not_called()
        self.child.kill.assert_not_called()
        self.child.wait.assert_not_called()
        self.assert_closed()

    def test_closed_pipes_do_not_disable_timeout_or_child_cleanup(self):
        self.wait4.return_value = (0, 0, None)
        with self.assertRaisesRegex(RuntimeError, "per-run time limit"):
            self.measure(timeout=0.0025)
        self.assertAlmostEqual(self.now, 0.0025)
        self.assertEqual(self.sleep.call_count, 3)
        self.assertAlmostEqual(self.sleep.call_args.args[0], 0.0005)
        self.selector.select.assert_called_once_with(0.0025)
        self.collector.finish.assert_not_called()
        self.child.kill.assert_called_once_with()
        self.child.wait.assert_called_once_with()
        self.assert_closed()

    def test_pipe_wait_is_bounded_by_remaining_timeout(self):
        def no_output(timeout):
            self.now += timeout
            return []

        self.selector.select.side_effect = no_output
        self.wait4.return_value = (0, 0, None)
        with self.assertRaisesRegex(RuntimeError, "per-run time limit"):
            self.measure(timeout=0.025)
        self.selector.select.assert_called_once_with(0.025)
        self.sleep.assert_not_called()
        self.child.kill.assert_called_once_with()
        self.child.wait.assert_called_once_with()
        self.assert_closed()

    def test_wait4_error_is_propagated_and_child_is_cleaned_up(self):
        self.wait4.side_effect = OSError("synthetic wait4 failure")
        with self.assertRaisesRegex(OSError, "synthetic wait4 failure"):
            self.measure()
        self.child.kill.assert_called_once_with()
        self.child.wait.assert_called_once_with()
        self.assert_closed()


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.case = {"kind": "dense", "path": Path("/fixture/dense.txt"), "expected": 2,
                     "input_bytes": 2 * (len(BENCH.TOKEN) + 1)}

    def finding(self, row):
        start = row * (len(BENCH.TOKEN) + 1)
        return {"type": "finding", "finding": {
            "rule_id": "github-pat", "path": str(self.case["path"]),
            "start": start, "end": start + len(BENCH.TOKEN), "line": row + 1, "column": 0,
            "fingerprint": "synthetic-digest", "redacted": "[REDACTED]",
            "coordinate_space": "source_bytes", "is_base64_encoded": False}}

    def summary(self):
        return {"type": "summary", "complete": True, "errors": [], "finding_count": 2,
                "stats": {"bytes": self.case["input_bytes"], "files": 1, "skipped": 0,
                          "detection_passes": 1}}

    def test_permutation_has_same_identity_and_counts(self):
        results = []
        for order in ((0, 1), (1, 0)):
            collector = BENCH.Collector(self.case)
            for row in order:
                collector.accept(self.finding(row))
            collector.accept(self.summary())
            results.append(collector.finish(1))
        self.assertEqual(results[0], results[1])

    def test_shifted_source_span_is_rejected(self):
        finding = self.finding(0)
        finding["finding"]["end"] += 1
        with self.assertRaisesRegex(RuntimeError, "coordinate"):
            BENCH.Collector(self.case).accept(finding)

    def test_duplicate_does_not_substitute_for_missing_occurrence(self):
        collector = BENCH.Collector(self.case)
        collector.accept(self.finding(0))
        with self.assertRaisesRegex(RuntimeError, "duplicated"):
            collector.accept(self.finding(0))

    def test_incomplete_empty_result_is_not_clean(self):
        collector = BENCH.Collector(self.case)
        summary = self.summary()
        summary.update(complete=False, finding_count=0)
        collector.accept(summary)
        with self.assertRaisesRegex(RuntimeError, "complete"):
            collector.finish(2)

    def test_missing_summary_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "summary"):
            BENCH.Collector(self.case).finish(1)

    def test_records_after_summary_are_rejected(self):
        collector = BENCH.Collector(self.case)
        collector.accept(self.summary())
        with self.assertRaisesRegex(RuntimeError, "after"):
            collector.accept(self.finding(0))

    def test_changed_fingerprint_does_not_change_detection_identity(self):
        first = BENCH.Collector(self.case)
        second = BENCH.Collector(self.case)
        finding = self.finding(0)
        changed = copy.deepcopy(finding)
        changed["finding"]["fingerprint"] = "different-synthetic-digest"
        first.accept(finding)
        second.accept(changed)
        self.assertEqual(first.multiset, second.multiset)

    def test_absolute_and_relative_single_file_paths_are_equivalent(self):
        before = BENCH.Collector(self.case)
        after = BENCH.Collector(self.case)
        absolute = self.finding(0)
        relative = copy.deepcopy(absolute)
        relative["finding"]["path"] = "dense.txt"
        before.accept(absolute)
        after.accept(relative)
        self.assertEqual(before.multiset, after.multiset)

    def test_directory_paths_are_relative_to_the_directory(self):
        case = {"kind": "manyfiles", "path": Path("/fixture/manyfiles")}
        self.assertEqual(BENCH.normalized_path(case, "/fixture/manyfiles/file-000100.txt"),
                         BENCH.normalized_path(case, "file-000100.txt"))

    def test_git_provenance_is_not_rewritten(self):
        path = "git:0123456789:subdir/secret.txt"
        self.assertEqual(BENCH.normalized_path({"kind": "git"}, path), path)

    def test_path_outside_fixture_root_is_rejected(self):
        for path in ("/outside/dense.txt", "../dense.txt", "/fixture/../dense.txt"):
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, "root"):
                BENCH.normalized_path(self.case, path)

    def test_progress_does_not_count_as_a_finding(self):
        collector = BENCH.Collector(self.case)
        self.assertFalse(collector.accept({"type": "progress", "stats": {"files": 1}}))
        for row in range(2):
            collector.accept(self.finding(row))
        summary = self.summary()
        del summary["errors"]
        summary["error_count"] = 0
        collector.accept(summary)
        result = collector.finish(1)
        self.assertEqual(result["findings"], 2)
        self.assertEqual(result["progress_records"], 1)

    def test_error_event_cannot_be_hidden_by_clean_summary(self):
        collector = BENCH.Collector(self.case)
        collector.accept({"type": "error", "error": {"path": "fixture", "message": "unreadable"}})
        collector.accept(self.summary())
        with self.assertRaisesRegex(RuntimeError, "complete"):
            collector.finish(1)

    def test_new_summary_error_count_is_respected(self):
        collector = BENCH.Collector(self.case)
        summary = self.summary()
        del summary["errors"]
        summary["error_count"] = 1
        collector.accept(summary)
        with self.assertRaisesRegex(RuntimeError, "complete"):
            collector.finish(1)

    @unittest.skipUnless(shutil.which("git"), "Git is required for the tiny fixture check")
    def test_git_generator_reuses_the_exact_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "fixture.git"
            commits = BENCH.git_fixture(repo, 2)
            self.assertEqual(len(commits), 2)
            trees = [BENCH.git(repo, "ls-tree", "-r", commit) for commit in commits]
            self.assertEqual(trees[0], trees[1])
            self.assertEqual(len(trees[0].splitlines()), 16)

    def test_summary_keeps_output_and_progress_measurements(self):
        fields = ("wall_ms", "first_finding_ms", "peak_rss_bytes", "user_ms", "system_ms",
                  "stdout_bytes", "stderr_bytes", "progress_records")
        runs = [{field: value for field in fields} for value in (10, 2, 3)]
        summary = BENCH.summarize(runs)
        self.assertEqual(summary["runs"], runs)
        for field in fields:
            self.assertEqual(summary[field], {"median": 3, "min": 2, "max": 10})


if __name__ == "__main__":
    unittest.main()
