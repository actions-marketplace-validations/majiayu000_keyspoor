"""Test label integrity without importing or running any scanner."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("holdout", Path(__file__).parent / "fixtures" / "holdout.py")
holdout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(holdout)


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


if __name__ == "__main__":
    unittest.main()
