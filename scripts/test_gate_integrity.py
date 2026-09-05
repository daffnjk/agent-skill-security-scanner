import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from github_action_gate import load_results, load_sealed_reports, render_summary


class GateIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_id = 'a' * 32
        self.coverage = dict(collection_complete=True, content_complete=True, analysis_complete=True)
        self.results = [dict(skill_id='demo', verdict='benign', engine_category='benign', evidence_text='local notes')]
        self.scans = [dict(schema_version=2, run_id=self.run_id, skill_id='demo', complete=True, truncated=False, coverage=self.coverage, sampled_files=0, read_errors=0, skipped_symlinks=0, skipped_opaque=0, unreviewed_external_instructions=0)]
        self.audits = [dict(schema_version=2, run_id=self.run_id, skill_id='demo', coverage=self.coverage)]
        self.write()

    def write(self):
        hashes = {}
        for name, rows in [('results.jsonl', self.results), ('scan-metadata.jsonl', self.scans), ('analysis-metadata.jsonl', self.audits)]:
            data = ''.join(json.dumps(row) + '\n' for row in rows).encode()
            (self.root/name).write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        (self.root/'scan-complete.json').write_text(json.dumps(dict(schema_version=2, run_id=self.run_id, skill_count=len(self.results), reports=hashes)))

    def test_valid(self):
        rows, counts = load_sealed_reports(self.root/'results.jsonl')
        self.assertEqual(counts['benign'], 1)
        self.assertEqual(rows, self.results)

    def test_incomplete_never_bypasses_any_policy(self):
        self.scans[0]['complete'] = False
        self.write()
        for policy in ('malicious', 'suspicious', 'never'):
            with self.subTest(policy=policy):
                env = dict(os.environ, SKILLSCAN_ALLOW_PARTIAL='1')
                result = subprocess.run([sys.executable, str(Path(__file__).with_name('github_action_gate.py')), '--results', str(self.root/'results.jsonl'), '--fail-on', policy], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_missing_seal(self):
        (self.root/'scan-complete.json').unlink()
        with self.assertRaises(OSError): load_sealed_reports(self.root/'results.jsonl')

    def test_stale_or_modified_result(self):
        with (self.root/'results.jsonl').open('a') as f: f.write('\n')
        with self.assertRaisesRegex(ValueError, 'stale'): load_sealed_reports(self.root/'results.jsonl')

    def test_missing_extra_or_duplicate_ids(self):
        for mutation in ('extra', 'duplicate', 'missing'):
            with self.subTest(mutation=mutation):
                original = copy.deepcopy(self.scans)
                if mutation == 'extra': self.scans.append(dict(self.scans[0], skill_id='extra'))
                elif mutation == 'duplicate': self.scans.append(dict(self.scans[0]))
                else: self.scans = []
                self.write()
                with self.assertRaises(ValueError): load_sealed_reports(self.root/'results.jsonl')
                self.scans = original

    def test_mixed_run_identity(self):
        self.audits[0]['run_id'] = 'b'*32
        self.write()
        with self.assertRaisesRegex(ValueError, 'mixed run'): load_sealed_reports(self.root/'results.jsonl')

    def test_sampled_read_error_and_symlink_counter_even_when_complete_claimed(self):
        for key in ('sampled_files', 'read_errors', 'skipped_symlinks', 'skipped_opaque', 'unreviewed_external_instructions'):
            with self.subTest(key=key):
                self.scans[0][key] = 1
                self.write()
                with self.assertRaises(ValueError): load_sealed_reports(self.root/'results.jsonl')
                self.scans[0][key] = 0

    def test_coverage_bool_is_not_string_or_integer(self):
        for value in (False, 'true', 1, None):
            with self.subTest(value=value):
                self.scans[0]['coverage'] = dict(self.coverage, analysis_complete=value)
                self.write()
                with self.assertRaises(ValueError): load_sealed_reports(self.root/'results.jsonl')

    def test_duplicate_json_keys_and_nonobject(self):
        for text in ('[]\n', '{"skill_id":"x","skill_id":"y"}\n'):
            (self.root/'results.jsonl').write_text(text)
            with self.assertRaises(ValueError): load_results(self.root/'results.jsonl')

    def test_report_link_rejected(self):
        target = self.root/'other'
        target.write_bytes((self.root/'results.jsonl').read_bytes())
        (self.root/'results.jsonl').unlink()
        (self.root/'results.jsonl').symlink_to(target)
        with self.assertRaises(ValueError): load_sealed_reports(self.root/'results.jsonl')

    def test_external_instructions_require_review(self):
        self.audits[0]['external_dependencies'] = [dict(kind='instruction-delegation', content_reviewed=False)]
        self.write()
        with self.assertRaisesRegex(ValueError,'external instructions'): load_sealed_reports(self.root/'results.jsonl')

    def test_summary_escapes_untrusted_cells(self):
        from collections import Counter
        rows = [dict(skill_id='x`|\n<script>', verdict='suspicious', engine_category='ast08', evidence_text='<img src=x> | evidence')]
        summary = render_summary(rows, Counter(suspicious=1))
        self.assertNotIn('<script>', summary)
        self.assertNotIn('<img', summary)
        self.assertIn('not been verified', summary)


if __name__ == '__main__': unittest.main()
