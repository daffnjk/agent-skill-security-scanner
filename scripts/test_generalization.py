import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from evaluate_generalization import assert_nonregression, confusion, load_manifest, metrics, paired_group_intervals, verified_reports
from prepare_generalization import safe_relative, script_pieces
from prepare_external_generalization import safe_member

class GeneralizationTests(unittest.TestCase):
    def test_metrics_independent_hand_calculation(self):
        result = metrics(2, 1, 3, 1)
        for key in ('precision', 'recall', 'f1', 'f2'):
            self.assertAlmostEqual(result[key], 2 / 3)
        self.assertAlmostEqual(result['mcc'], 5 / 12)
        self.assertAlmostEqual(result['accuracy'], 5 / 7)
        self.assertAlmostEqual(result['fpr'], 1 / 4)

    def test_undefined_is_not_perfect(self):
        result = metrics(0, 0, 10, 0)
        self.assertIsNone(result['precision'])
        self.assertIsNone(result['recall'])
        self.assertIsNone(result['f1'])
        self.assertIsNone(result['mcc'])
        self.assertEqual(metrics(0, 0, 10, 2)['recall'], 0)

    def test_invalid_counts_rejected(self):
        for counts in ((-1, 0, 1, 2), (True, 0, 1, 2), (1.0, 0, 1, 2)):
            with self.assertRaises(ValueError):
                metrics(*counts)

    def test_screening_does_not_change_truth_labels(self):
        rows = [dict(skill_id='a', label='malicious'), dict(skill_id='b', label='benign')]
        predictions = {s: dict(verdict='suspicious') for s in ('a', 'b')}
        self.assertEqual(confusion(rows, predictions), (0, 0, 1, 1))
        self.assertEqual(confusion(rows, predictions, True), (1, 1, 0, 0))

    def test_path_traversal_and_entrypoint_collision(self):
        for name in ('../x', '/x', 'C:\\x', 'a/../../x', 'SKILL.md', 'skill.MD', ''):
            with self.assertRaises(ValueError, msg=name):
                safe_relative(name)
        self.assertEqual(str(safe_relative('scripts\\helper.py')), 'scripts/helper.py')

    def test_duplicate_scripts_are_not_collapsed(self):
        pieces, warning = script_pieces('--- a.py ---\none\n--- a.py ---\ntwo\n', ['a.py', 'a.py'])
        self.assertEqual(len(pieces), 2)
        self.assertNotEqual(pieces[0][1], pieces[1][1])
        with self.assertRaises(ValueError):
            script_pieces('unassigned\n--- a.py ---\ntext\n', ['a.py'])

    def test_manifest_duplicate_and_group_leakage(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'manifest.json'
            a = dict(skill_id='a', dataset='x', label='benign', split='development', group_id='a' * 64)
            b = a | dict(skill_id='b', split='holdout')
            for rows in ([a, a], [a, b], [a | dict(label='suspicious')]):
                path.write_text(json.dumps(rows))
                with self.assertRaises(ValueError):
                    load_manifest(path)

    def test_external_paths_preserve_safe_posix_components(self):
        self.assertEqual(str(safe_member('benchmark_full_v1.0/case_00001/compact:before/a.js')), 'benchmark_full_v1.0/case_00001/compact:before/a.js')
        for name in ('../a', '/tmp/a', 'C:/a', 'a/../../b', 'a\\b', ''):
            with self.assertRaises(ValueError):
                safe_member(name)

    def test_regression_gate_never_trades_recall_for_precision(self):
        b = dict(dataset='source', split='all', materialization='all_materializations', mode='strict', version='baseline', n=12, tp=5, fn=1, fp=3, tn=3, incomplete=0)
        good = b | dict(version='candidate', fp=2, tn=4)
        assert_nonregression(dict(metrics=[b, good]))
        for bad in (good | dict(tp=4, fn=2), good | dict(fp=4, tn=2), good | dict(incomplete=1), good | dict(n=11)):
            with self.assertRaises(ValueError):
                assert_nonregression(dict(metrics=[b, bad]))

    def reports(self, path, *, complete=True, verdict='malicious'):
        run_id = 'a' * 32
        coverage = dict(collection_complete=complete, content_complete=True, analysis_complete=True)
        scan = dict(skill_id='a', schema_version=2, run_id=run_id, coverage=coverage, complete=complete, truncated=False, input_digest='sha256:test', **{key: 0 for key in ('sampled_files', 'read_errors', 'skipped_symlinks', 'skipped_opaque', 'unreviewed_external_instructions')})
        analysis = dict(skill_id='a', schema_version=2, run_id=run_id, coverage=coverage, input_digest='sha256:test', scanner=dict(ruleset_hash='sha256:fixture'))
        prediction = dict(skill_id='a', verdict=verdict, engine_category='benign' if verdict == 'benign' else 'ast01', evidence_text='inert fixture')
        hashes = {}
        for name, row in (('results.jsonl', prediction), ('scan-metadata.jsonl', scan), ('analysis-metadata.jsonl', analysis)):
            data = (json.dumps(row) + '\n').encode()
            (path / name).write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        (path / 'scan-complete.json').write_text(json.dumps(dict(schema_version=2, run_id=run_id, skill_count=1, reports=hashes)))

    def test_integrity_and_missing_rows_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            self.reports(path)
            verified_reports(path, {'a'})
            with self.assertRaises(ValueError):
                verified_reports(path, {'a', 'b'})
            with (path / 'results.jsonl').open('a') as handle:
                handle.write(' ')
            with self.assertRaises(ValueError):
                verified_reports(path, {'a'})

    def test_incomplete_retained_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            self.reports(path, complete=False, verdict='suspicious')
            predictions, scans, _ = verified_reports(path, {'a'})
            self.assertIn('a', predictions)
            self.assertFalse(scans['a']['complete'])
            self.reports(path, complete=False, verdict='benign')
            with self.assertRaises(ValueError):
                verified_reports(path, {'a'})

    def test_group_bootstrap_is_paired_and_reproducible(self):
        rows = [dict(skill_id='a', label='malicious', group_id='x'), dict(skill_id='b', label='benign', group_id='y')]
        predictions = dict(a=dict(verdict='malicious'), b=dict(verdict='benign'))
        a = paired_group_intervals(rows, predictions, predictions, 100)
        self.assertEqual(a, paired_group_intervals(rows, predictions, predictions, 100))
        for interval in a.values():
            self.assertEqual(interval['low'], 0)
            self.assertEqual(interval['high'], 0)

if __name__ == '__main__':
    unittest.main()
