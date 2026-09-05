#!/usr/bin/env python3
"""Compare identical labeled populations; no tuning or label inference is performed.

Labels: JSONL objects with skill_id, label (benign/malicious), and optional
source, attack_type, split. Only split=holdout is an explicitly held-out group.
"""
from __future__ import annotations
import argparse
import json
from collections import defaultdict
from pathlib import Path
from github_action_gate import load_results


def load_labels(path: Path) -> dict[str, dict]:
    rows = {}
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip(): continue
        row = json.loads(line)
        if not isinstance(row, dict) or not isinstance(row.get('skill_id'), str) or not row['skill_id']:
            raise ValueError(f'invalid label row {number}')
        if row['skill_id'] in rows: raise ValueError('duplicate label ID')
        rows[row['skill_id']] = row
    if not rows: raise ValueError('no labels')
    return rows


def metrics(labels: dict, predictions: dict, positive: set[str]) -> dict:
    counts = dict(tp=0, fp=0, tn=0, fn=0, excluded=0)
    for skill_id, row in labels.items():
        label = row.get('label')
        if label not in ('benign', 'malicious'):
            counts['excluded'] += 1
            continue
        risk = predictions[skill_id]['verdict'] in positive
        key = ('tp' if risk else 'fn') if label == 'malicious' else ('fp' if risk else 'tn')
        counts[key] += 1
    tp, fp, tn, fn = (counts[k] for k in ('tp', 'fp', 'tn', 'fn'))
    ratio = lambda x, y: x / y if y else None
    return dict(counts, precision=ratio(tp,tp+fp), recall=ratio(tp,tp+fn), false_positive_rate=ratio(fp,fp+tn), f2=ratio(5*tp,5*tp+4*fn+fp))


def compare(labels: dict, baseline_rows: list[dict], candidate_rows: list[dict]) -> dict:
    baseline = {row['skill_id']: row for row in baseline_rows}
    candidate = {row['skill_id']: row for row in candidate_rows}
    if len(baseline) != len(baseline_rows) or len(candidate) != len(candidate_rows): raise ValueError('duplicate prediction ID')
    if set(labels) != set(baseline) or set(labels) != set(candidate): raise ValueError('label/baseline/candidate populations differ')
    output = {'population': len(labels), 'caveat': 'Verdict metrics do not prove scan completeness. Published v41 benchmarks are historical, not rerun results.', 'policies': {}}
    for name, positive in [('strict', {'malicious'}), ('screening', {'malicious','suspicious'})]:
        changes = dict(fixed_false_negatives=[], new_false_negatives=[], fixed_false_positives=[], new_false_positives=[])
        for skill_id, row in labels.items():
            old, new = baseline[skill_id]['verdict'] in positive, candidate[skill_id]['verdict'] in positive
            if old == new: continue
            if row.get('label') == 'malicious': key = 'fixed_false_negatives' if new else 'new_false_negatives'
            elif row.get('label') == 'benign': key = 'new_false_positives' if new else 'fixed_false_positives'
            else: continue
            changes[key].append(skill_id)
        groups = {}
        for dimension in ('source', 'attack_type', 'split'):
            buckets = defaultdict(dict)
            for skill_id, row in labels.items(): buckets[str(row.get(dimension, 'unspecified'))][skill_id] = row
            groups[dimension] = {key: {'baseline': metrics(group,baseline,positive), 'candidate': metrics(group,candidate,positive)} for key, group in sorted(buckets.items())}
        output['policies'][name] = dict(baseline=metrics(labels,baseline,positive), candidate=metrics(labels,candidate,positive), changes={k:sorted(v) for k,v in changes.items()}, groups=groups)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--labels',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    report = compare(load_labels(args.labels),load_results(args.baseline)[0],load_results(args.candidate)[0])
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return 0


if __name__ == '__main__': raise SystemExit(main())
