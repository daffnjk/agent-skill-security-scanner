#!/usr/bin/env python3
"""Offline, fail-closed paired evaluation. Never imports or executes Skill input.

A report is structurally verified even when scan coverage is incomplete. Such
rows remain in metric denominators and are reported separately; this is NOT an
alternative deployment gate. No threshold selection is performed here.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import subprocess
import time

from github_action_gate import REPORTS, _json, _read, _results, _rows


def load_manifest(path: Path) -> list[dict]:
    rows = _json(path.read_text(encoding='utf-8'))
    if not isinstance(rows, list) or not rows:
        raise ValueError('manifest must be a nonempty array')
    seen, development, holdout = set(), set(), set()
    for row in rows:
        sid = row.get('skill_id')
        if not isinstance(sid, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', sid) or sid in seen:
            raise ValueError('unsafe or duplicate manifest ID')
        seen.add(sid)
        if row.get('label') not in ('malicious', 'benign'):
            raise ValueError('unsupported truth label; do not silently map suspicious to malicious')
        if row.get('split') not in ('development', 'holdout', 'overlap_regression'):
            raise ValueError('missing or unsupported split')
        if not isinstance(row.get('dataset'), str) or not row['dataset']:
            raise ValueError('missing dataset')
        if not re.fullmatch(r'[a-f0-9]{64}', row.get('group_id', '')):
            raise ValueError('missing content/repository group')
        if row['split'] == 'development':
            development.add(row['group_id'])
        elif row['split'] == 'holdout':
            holdout.add(row['group_id'])
    if development & holdout:
        raise ValueError('development/holdout group leakage')
    return rows


def verified_reports(folder: Path, expected_ids: set[str]) -> tuple[dict, dict, dict]:
    seal = _json(_read(folder / 'scan-complete.json').decode('utf-8'))
    if seal.get('schema_version') != 2 or not re.fullmatch(r'[a-f0-9]{32}', seal.get('run_id', '')):
        raise ValueError('invalid report seal')
    if set(seal.get('reports', {})) != set(REPORTS):
        raise ValueError('missing sealed report')
    content = {name: _read(folder / name) for name in REPORTS}
    for name, payload in content.items():
        if hashlib.sha256(payload).hexdigest() != seal['reports'][name]:
            raise ValueError('report digest mismatch: ' + name)
    result_rows, _ = _results(content['results.jsonl'])
    predictions = {r['skill_id']: r for r in result_rows}
    if set(predictions) != expected_ids or type(seal.get('skill_count')) is not int or seal['skill_count'] != len(expected_ids):
        raise ValueError('prediction IDs/count differ from complete manifest')
    companions = {}
    for name in REPORTS[1:]:
        rows = _rows(content[name])
        if {r['skill_id'] for r in rows} != expected_ids:
            raise ValueError('metadata IDs are not one-to-one: ' + name)
        for row in rows:
            if row.get('schema_version') != 2 or row.get('run_id') != seal['run_id']:
                raise ValueError('mixed run/schema in metadata')
            coverage = row.get('coverage', {})
            if any(type(coverage.get(k)) is not bool for k in ('collection_complete', 'content_complete', 'analysis_complete')):
                raise ValueError('missing coverage fields')
        companions[name] = {r['skill_id']: r for r in rows}
    scans, analyses = companions['scan-metadata.jsonl'], companions['analysis-metadata.jsonl']
    identities = set()
    for sid in expected_ids:
        scan, analysis = scans[sid], analyses[sid]
        if type(scan.get('complete')) is not bool:
            raise ValueError('complete must be boolean')
        digest = scan.get('input_digest')
        if not isinstance(digest, str) or not digest or digest != analysis.get('input_digest'):
            raise ValueError('input digests disagree')
        if scan.get('coverage') != analysis.get('coverage'):
            raise ValueError('coverage companions disagree')
        if scan['complete']:
            if not all(scan['coverage'].values()) or scan.get('truncated') is not False or scan.get('internal_error'):
                raise ValueError('inconsistent complete status')
            for key in ('sampled_files', 'read_errors', 'skipped_symlinks', 'skipped_opaque', 'unreviewed_external_instructions'):
                if type(scan.get(key)) is not int or scan[key] != 0:
                    raise ValueError('complete scan has coverage warning')
        elif predictions[sid]['verdict'] == 'benign':
            raise ValueError('incomplete input incorrectly classified benign')
        scanner = analysis.get('scanner')
        if not isinstance(scanner, dict) or not scanner.get('ruleset_hash'):
            raise ValueError('missing scanner identity')
        identities.add(json.dumps(scanner, sort_keys=True))
    if len(identities) != 1:
        raise ValueError('mixed scanner identities')
    return predictions, scans, json.loads(identities.pop())


def ratio(a: float, b: float) -> float | None:
    return a / b if b else None


def metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    if any(type(v) is not int or v < 0 for v in (tp, fp, tn, fn)):
        raise ValueError('confusion counts must be nonnegative integers')
    p, r, specificity = ratio(tp, tp + fp), ratio(tp, tp + fn), ratio(tn, tn + fp)
    denominator = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return dict(n=tp + fp + tn + fn, tp=tp, fp=fp, tn=tn, fn=fn,
                precision=p, recall=r, f1=ratio(2 * tp, 2 * tp + fp + fn),
                f2=ratio(5 * tp, 5 * tp + fp + 4 * fn), fpr=ratio(fp, fp + tn),
                specificity=specificity, accuracy=ratio(tp + tn, tp + fp + tn + fn),
                balanced_accuracy=(r + specificity) / 2 if r is not None and specificity is not None else None,
                mcc=(tp * tn - fp * fn) / math.sqrt(denominator) if denominator else None)


def confusion(rows: list[dict], predictions: dict, screening: bool = False) -> tuple[int, int, int, int]:
    counts = [0, 0, 0, 0]
    for row in rows:
        positive = predictions[row['skill_id']]['verdict'] in (('malicious', 'suspicious') if screening else ('malicious',))
        truth = row['label'] == 'malicious'
        counts[0 if truth and positive else 3 if truth else 1 if positive else 2] += 1
    return tuple(counts)


def paired_group_intervals(rows: list[dict], baseline: dict, candidate: dict, repetitions: int = 2000) -> dict:
    groups = defaultdict(list)
    for row in rows:
        groups[row['group_id']].append(row)
    keys = sorted(groups)
    base = [confusion(groups[k], baseline) for k in keys]
    cand = [confusion(groups[k], candidate) for k in keys]
    rng = random.Random(20260906)
    names = ('precision', 'recall', 'f1', 'f2', 'fpr', 'balanced_accuracy', 'mcc')
    deltas = {name: [] for name in names}
    for _ in range(repetitions):
        b, c = [0] * 4, [0] * 4
        for _ in keys:
            i = rng.randrange(len(keys))
            for j in range(4):
                b[j] += base[i][j]
                c[j] += cand[i][j]
        bm, cm = metrics(*b), metrics(*c)
        for name in names:
            if bm[name] is not None and cm[name] is not None:
                deltas[name].append(cm[name] - bm[name])
    def percentile(values, q):
        position = (len(values) - 1) * q
        lo, hi = int(position), math.ceil(position)
        return values[lo] + (values[hi] - values[lo]) * (position - lo)
    return {name: dict(low=percentile(sorted(values), 0.025), high=percentile(sorted(values), 0.975), valid_replicates=len(values), groups=len(keys))
            for name, values in deltas.items() if values}


def compare(manifest: Path, baseline: Path, candidate: Path, output: Path, bootstrap: int = 2000) -> dict:
    rows = load_manifest(manifest)
    ids = {r['skill_id'] for r in rows}
    bp, bs, bi = verified_reports(baseline, ids)
    cp, cs, ci = verified_reports(candidate, ids)
    for sid in ids:
        if bs[sid]['input_digest'] != cs[sid]['input_digest']:
            raise ValueError('baseline and candidate read different input bytes: ' + sid)
    for folder, scans in ((baseline, bs), (candidate, cs)):
        run_path = folder / 'run.json'
        if run_path.exists():
            run = _json(run_path.read_text())
            expected_code = 3 if any(not row['complete'] for row in scans.values()) else 0
            if run.get('returncode') != expected_code:
                raise ValueError('process status and scan completeness disagree')
    tables, intervals = [], {}
    for source in sorted({r['dataset'] for r in rows}):
        for split in ('all', 'development', 'holdout', 'overlap_regression'):
            cohort = [r for r in rows if r['dataset'] == source and (split == 'all' or r['split'] == split)]
            if not cohort:
                continue
            for sensitivity in ('all_materializations', 'unambiguous_only'):
                eligible = [r for r in cohort if sensitivity == 'all_materializations' or not r.get('materialization_warning')]
                for version, pred, scans in (('baseline', bp, bs), ('candidate', cp, cs)):
                    for mode in ('strict', 'screening'):
                        row = dict(dataset=source, split=split, materialization=sensitivity, version=version, mode=mode,
                                   **metrics(*confusion(eligible, pred, mode == 'screening')))
                        row['incomplete'] = sum(not scans[r['skill_id']]['complete'] for r in eligible)
                        row['complete_rate'] = ratio(row['n'] - row['incomplete'], row['n'])
                        row['materialization_warnings'] = sum(bool(r.get('materialization_warning')) for r in eligible)
                        tables.append(row)
            if split == 'holdout' and bootstrap:
                intervals[source] = paired_group_intervals(cohort, bp, cp, bootstrap)
    result = dict(schema_version=1, manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                  scanner_identities=dict(baseline=bi, candidate=ci), metrics=tables,
                  paired_group_bootstrap=dict(seed=20260906, repetitions=bootstrap, confidence=0.95, intervals=intervals),
                  run_metadata={version: _json((folder / 'run.json').read_text()) if (folder / 'run.json').exists() else None
                                for version, folder in (('baseline', baseline), ('candidate', candidate))})
    output.mkdir(parents=True, exist_ok=True)
    (output / 'comparison.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    with (output / 'metrics.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(tables[0]))
        writer.writeheader()
        writer.writerows(tables)
    # This contains no source content or model evidence strings.
    with (output / 'paired-predictions.jsonl').open('w') as handle:
        for row in rows:
            sid = row['skill_id']
            handle.write(json.dumps({k: row[k] for k in ('skill_id', 'dataset', 'label', 'split', 'group_id')} |
                                    dict(baseline=bp[sid]['verdict'], candidate=cp[sid]['verdict'],
                                         baseline_complete=bs[sid]['complete'], candidate_complete=cs[sid]['complete'])) + '\n')
    return result


def assert_nonregression(result: dict) -> None:
    """Per-source guardrail; all screening/strict denominators stay unchanged."""
    grouped = defaultdict(dict)
    for row in result['metrics']:
        if row['split'] == 'all' and row['materialization'] == 'all_materializations':
            grouped[(row['dataset'], row['mode'])][row['version']] = row
    if not grouped:
        raise ValueError('no comparable source metrics')
    failures = []
    for (source, mode), versions in sorted(grouped.items()):
        if set(versions) != {'baseline', 'candidate'}:
            raise ValueError('missing comparison version')
        b, c = versions['baseline'], versions['candidate']
        if c['n'] != b['n'] or c['tp'] + c['fn'] != b['tp'] + b['fn']:
            failures.append(f'{source}/{mode}: changed truth denominator')
        if c['tp'] < b['tp'] or c['fp'] > b['fp'] or c['incomplete'] > b['incomplete']:
            failures.append(f'{source}/{mode}: TP/FP/completeness regression')
    if failures:
        raise ValueError('; '.join(failures))


def run_scan(binary: Path, corpus: Path, output: Path, timeout: float) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    start = time.perf_counter()
    try:
        with (output / 'stdout.log').open('wb') as stdout, (output / 'stderr.log').open('wb') as stderr:
            result = subprocess.run([str(binary.resolve()), '--collection', str(corpus.resolve()), str(output.resolve())],
                                    stdout=stdout, stderr=stderr, timeout=timeout,
                                    env={'PATH': '/usr/bin:/bin', 'HOME': str(output.resolve()), 'LANG': 'C.UTF-8'})
        record = dict(returncode=result.returncode, wall_seconds=time.perf_counter() - start,
                      binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), platform=platform.platform())
        (output / 'run.json').write_text(json.dumps(record, indent=2) + '\n')
        if result.returncode not in (0, 3):
            raise RuntimeError('scanner execution failed; no metrics may be claimed')
        return record
    except subprocess.TimeoutExpired:
        (output / 'run.json').write_text(json.dumps(dict(status='timeout', wall_seconds=time.perf_counter() - start)) + '\n')
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='action', required=True)
    scan = subs.add_parser('scan')
    for arg in ('binary', 'corpus', 'output'):
        scan.add_argument('--' + arg, required=True, type=Path)
    scan.add_argument('--timeout', type=float, default=600)
    comp = subs.add_parser('compare')
    for arg in ('manifest', 'baseline', 'candidate', 'output'):
        comp.add_argument('--' + arg, required=True, type=Path)
    comp.add_argument('--bootstrap', type=int, default=2000)
    comp.add_argument('--require-nonregression', action='store_true')
    args = parser.parse_args()
    if args.action == 'scan':
        print(json.dumps(run_scan(args.binary, args.corpus, args.output, args.timeout)), flush=True)
    else:
        result = compare(args.manifest, args.baseline, args.candidate, args.output, args.bootstrap)
        if args.require_nonregression:
            assert_nonregression(result)
        for row in result['metrics']:
            if row['split'] in ('all', 'holdout') and row['mode'] == 'strict' and row['materialization'] == 'all_materializations':
                print(json.dumps(row), flush=True)

if __name__ == '__main__':
    main()
