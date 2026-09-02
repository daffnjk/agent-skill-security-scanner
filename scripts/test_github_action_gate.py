import json
import tempfile
import unittest
from pathlib import Path

from github_action_gate import load_results, render_summary, should_fail


class GitHubActionGateTests(unittest.TestCase):
    def write_rows(self, rows):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "results.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        self.addCleanup(directory.cleanup)
        return path

    def test_counts_and_policy(self):
        rows = [
            {"skill_id": "a", "verdict": "malicious", "engine_category": "ast01", "evidence_text": "x"},
            {"skill_id": "b", "verdict": "suspicious", "engine_category": "ast03", "evidence_text": "y"},
            {"skill_id": "c", "verdict": "benign", "engine_category": "benign", "evidence_text": "z"},
        ]
        loaded, counts = load_results(self.write_rows(rows))
        self.assertEqual(counts["malicious"], 1)
        self.assertTrue(should_fail("malicious", counts))
        self.assertTrue(should_fail("suspicious", counts))
        self.assertFalse(should_fail("never", counts))
        self.assertIn("`a`", render_summary(loaded, counts))

    def test_rejects_schema_drift(self):
        row = {"skill_id": "a", "verdict": "benign", "engine_category": "benign", "evidence_text": "x", "score": 1}
        with self.assertRaisesRegex(ValueError, "four-field"):
            load_results(self.write_rows([row]))

    def test_rejects_empty_results(self):
        with self.assertRaisesRegex(ValueError, "no rows"):
            load_results(self.write_rows([]))


if __name__ == "__main__":
    unittest.main()
