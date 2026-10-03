"""Test label integrity without importing or running any scanner."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("holdout", Path(__file__).parent / "fixtures" / "holdout.py")
holdout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(holdout)


V3_SPEC = importlib.util.spec_from_file_location("holdout_v3", Path(__file__).parent / "fixtures" / "holdout_v3.py")
holdout_v3 = importlib.util.module_from_spec(V3_SPEC)
V3_SPEC.loader.exec_module(holdout_v3)


class HoldoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "corpus"
        self.manifest = holdout.generate(self.root)

    def test_deterministic_and_distinct_positive_values(self):
        other = Path(self.temp.name) / "other"
        holdout.generate(other)
        self.assertEqual((self.root / "manifest.json").read_bytes(), (other / "manifest.json").read_bytes())
        positives = [e for e in self.manifest["entries"] if e["label"] == "positive"]
        self.assertEqual(600, len({e["value_group"] for e in positives}))
        self.assertEqual(20, len(holdout.FORMATS))
        self.assertGreaterEqual(len({e["template_group"] for e in positives}), 10)

    def test_original_default_bytes_remain_frozen(self):
        self.assertEqual("b06c84b0bdfb564022cf417e5e39671d9bae78c20ed83cf32dc3491d6a6b8054",
                         self.manifest["generator_sha256"])
        self.assertEqual("e83583b0292458c05066034c48e3c75d8f6ea135fa4315829c3a6785ce81ae6f",
                         self.manifest["corpus_sha256"])

    def test_tampered_content_is_rejected(self):
        path = self.root / self.manifest["entries"][0]["path"]
        path.write_bytes(b"not original input")
        with self.assertRaises(AssertionError):
            holdout.validate(self.root, self.manifest)

    def test_wrong_byte_offset_is_rejected(self):
        self.manifest["entries"][0]["start"] += 1
        with self.assertRaises(AssertionError):
            holdout.validate(self.root, self.manifest)

    def test_label_flip_is_rejected(self):
        self.manifest["entries"][0]["label"] = "negative"
        with self.assertRaises(AssertionError):
            holdout.validate(self.root, self.manifest)

    def test_nonempty_output_is_preserved(self):
        before = (self.root / "manifest.json").read_bytes()
        with self.assertRaises(ValueError):
            holdout.generate(self.root)
        self.assertEqual(before, (self.root / "manifest.json").read_bytes())


class HoldoutV3Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "corpus"
        self.manifest = holdout_v3.generate(self.root)

    def test_deterministic_with_new_values(self):
        other = Path(self.temp.name) / "other"
        holdout_v3.generate(other)
        self.assertEqual((self.root / "manifest.json").read_bytes(), (other / "manifest.json").read_bytes())
        original = holdout.generate(Path(self.temp.name) / "original")
        values = {e["value_group"] for e in self.manifest["entries"] if e["label"] == "positive"}
        old_values = {e["value_group"] for e in original["entries"] if e["label"] == "positive"}
        self.assertEqual(580, len(values))
        self.assertFalse(values.intersection(old_values))

    def test_pair_challenges_preserve_distinct_positions(self):
        for template, expected_unique in (("v3-pair-repeat", 1), ("v3-pair-distinct", 2)):
            entries = [e for e in self.manifest["entries"] if e["case"] == template]
            self.assertEqual(40, len(entries))
            for path in {e["path"] for e in entries}:
                pair = [e for e in entries if e["path"] == path]
                self.assertEqual(2, len(pair))
                self.assertEqual(expected_unique, len({e["value_group"] for e in pair}))
                self.assertEqual(1, len({e["line"] for e in pair}))
                self.assertLess(pair[0]["end"], pair[1]["start"])

    def test_duplicate_position_is_rejected(self):
        first, second = self.manifest["entries"][:2]
        second.update(path=first["path"], start=first["start"], end=first["end"])
        with self.assertRaises(AssertionError):
            holdout_v3.validate(self.root, self.manifest)

    def test_nonempty_output_is_preserved(self):
        before = (self.root / "manifest.json").read_bytes()
        with self.assertRaises(ValueError):
            holdout_v3.generate(self.root)
        self.assertEqual(before, (self.root / "manifest.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
