"""Small collector-contract tests; no scanners or generated workload required."""
import copy
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("stress_benchmark", Path(__file__).with_name("stress_benchmark.py"))
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


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
