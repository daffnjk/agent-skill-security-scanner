import unittest
from compare_benchmarks import compare


class BenchmarkComparisonTests(unittest.TestCase):
    def test_policy_and_population(self):
        labels = {'m': {'label':'malicious','split':'holdout'}, 'b':{'label':'benign'}, 'x':{'label':'unknown'}}
        old = [dict(skill_id='m',verdict='benign'),dict(skill_id='b',verdict='malicious'),dict(skill_id='x',verdict='benign')]
        new = [dict(skill_id='m',verdict='suspicious'),dict(skill_id='b',verdict='benign'),dict(skill_id='x',verdict='benign')]
        report = compare(labels,old,new)
        self.assertEqual(report['policies']['strict']['candidate']['fn'],1)
        self.assertEqual(report['policies']['screening']['candidate']['tp'],1)
        self.assertEqual(report['policies']['screening']['candidate']['excluded'],1)
        self.assertEqual(report['policies']['screening']['changes']['fixed_false_negatives'],['m'])
        self.assertEqual(report['policies']['strict']['changes']['fixed_false_positives'],['b'])
        self.assertIn('holdout',report['policies']['strict']['groups']['split'])
        with self.assertRaises(ValueError): compare(labels,old,new[:-1])

    def test_zero_denominator_is_null(self):
        rows=[dict(skill_id='x',verdict='benign')]
        report=compare({'x':{'label':'benign'}},rows,rows)
        self.assertIsNone(report['policies']['strict']['candidate']['recall'])
        self.assertIsNone(report['policies']['strict']['candidate']['precision'])


if __name__ == '__main__': unittest.main()
