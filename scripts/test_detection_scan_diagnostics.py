import json
from pathlib import Path
import tempfile
import unittest

import detection_loop as loop


class ScanDiagnosticsTests(unittest.TestCase):
    def output(self, tmp, predictions, metadata):
        path = Path(tmp)
        for name, rows in (("results.jsonl", predictions), ("scan-metadata.jsonl", metadata)):
            (path / name).write_text("".join(json.dumps(r) + "\n" for r in rows))
        return path

    def test_incomplete_diagnostics_are_aggregated_and_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.output(tmp, [], [{"skill_id": "sensitive-sample-id", "complete": False,
                "unreviewed_external_instructions": 2, "read_errors": 1, "truncated": True,
                "error_samples": ["DO_NOT_PUBLISH"], "internal_error": "DO_NOT_PUBLISH"}])
            error = loop.ScanFailure("image", 3, out, {"sensitive-sample-id"})
            self.assertEqual(error.diagnostics["incomplete_samples"], 1)
            self.assertEqual(error.diagnostics["counters"]["unreviewed_external_instructions"], 2)
            self.assertEqual(error.diagnostics["internal_error_samples"], 1)
            self.assertNotIn("DO_NOT_PUBLISH", json.dumps(error.diagnostics))
            self.assertNotIn("sensitive-sample-id", json.dumps(error.diagnostics))

    def test_malformed_diagnostics_still_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            error = loop.ScanFailure("image", 2, Path(tmp), {"a"})
            self.assertTrue(error.diagnostics["metadata_invalid"])
            self.assertEqual(error.diagnostics["exit_code"], 2)

    def test_diagnostic_counter_types_cannot_inject_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.output(tmp, [], [{"skill_id": "a", "complete": False,
                "read_errors": "DO_NOT_PUBLISH", "sampled_files": -10}])
            error = loop.ScanFailure("image", 3, out, {"a"})
            self.assertEqual(error.diagnostics["counters"]["read_errors"], 0)
            self.assertEqual(error.diagnostics["counters"]["sampled_files"], 0)
            self.assertNotIn("DO_NOT_PUBLISH", json.dumps(error.diagnostics))


if __name__ == "__main__":
    unittest.main()
