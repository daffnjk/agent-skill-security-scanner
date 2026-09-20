#!/usr/bin/env python3
"""Create a deterministic, overlap-excluded SkillTrustBench package holdout.

Only checksum-verified static data is read. CC-BY-NC-SA-4.0 terms and upstream
attribution apply. The output is research evaluation data, not redistributed
scanner source. No target file is executed, imported, or followed as a URL.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile

ARCHIVE_SHA = 'a1970087675a6991788c2624eb6101b72445a7c56b3e1720bd2b97f0add6622f'
PREFIX = 'skilltrustbench-2026-08-30/data/'
MAX_ARCHIVE, MAX_FILE, MAX_TOTAL = 128 << 20, 32 << 20, 512 << 20


def normalized(text: str) -> str:
    return re.sub(r'\b[a-f0-9]{24,}\b', ' HEX ', re.sub(r'https?://[^\s<>"\)]+', ' URL ', text.lower()))


def safe_member(name: str) -> PurePosixPath:
    p = PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name or not p.parts or ':' in p.parts[0] or '\x00' in name:
        raise ValueError('unsafe archive path')
    return p


def prepare(archive: Path, selection_manifest: Path, selection_corpus: Path, output: Path, cap: int = 300) -> dict:
    from sklearn.feature_extraction.text import TfidfVectorizer
    if os.name != "posix":
        raise ValueError("package materialization requires POSIX paths")
    if cap < 1 or cap > 300:
        raise ValueError('cap must be in [1, 300]; the preregistered run uses 300')
    if archive.stat().st_size > MAX_ARCHIVE or hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA:
        raise ValueError('external archive checksum/size mismatch')
    with tarfile.open(archive) as t:
        def read(name):
            m = t.getmember(PREFIX + name)
            if not m.isfile() or m.size > MAX_ARCHIVE:
                raise ValueError('invalid release member')
            return t.extractfile(m).read(MAX_ARCHIVE + 1)
        cases = [json.loads(line) for line in read('data/test_cases.jsonl').decode().splitlines()]
        package = read('benchmark_full_v1.0.zip')
    if len(cases) != 5520 or len({c['id'] for c in cases}) != 5520:
        raise ValueError('unexpected external case identity/count')
    prior = json.loads(selection_manifest.read_text())
    texts = [(selection_corpus / r['skill_id'] / 'SKILL.md').read_text() for r in prior]
    raw_hashes = [r['sha256'] for r in prior]
    decoding_warnings = []
    with zipfile.ZipFile(io.BytesIO(package)) as z:
        members = z.infolist()
        if len(members) > 50000 or sum(m.file_size for m in members) > MAX_TOTAL:
            raise ValueError('package archive budget exceeded')
        by_case = defaultdict(list)
        names = set()
        for m in members:
            safe_member(m.filename)
            if m.filename in names:
                raise ValueError('duplicate zip member')
            names.add(m.filename)
            if m.is_dir():
                continue
            if stat.S_ISLNK(m.external_attr >> 16) or m.flag_bits & 1 or m.file_size > MAX_FILE:
                raise ValueError('symlink/encryption/member budget not supported')
            parts = PurePosixPath(m.filename).parts
            if len(parts) >= 3 and parts[0] == 'benchmark_full_v1.0' and re.fullmatch(r'case_\d{5}', parts[1]):
                by_case[parts[1]].append(m)
        for c in cases:
            expected = f"benchmark_full_v1.0/{c['id']}"
            if c['skill_path'] != expected:
                raise ValueError('unexpected case prefix')
            payload = z.read(expected + '/SKILL.md')
            raw_hashes.append(hashlib.sha256(payload).hexdigest())
            try:
                body = payload.decode('utf-8')
            except UnicodeDecodeError:
                decoding_warnings.append(c['id'])
                body = payload.decode('utf-8', errors='replace')
            texts.append(body)
        # Input-only grouping: exact document, repository when available, and
        # near-document similarity. Connected components enforce transitivity.
        n = len(texts); parent = list(range(n))
        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]; i = parent[i]
            return i
        def union(i, j):
            a, b = find(i), find(j)
            if a != b: parent[max(a, b)] = min(a, b)
        hashes = raw_hashes
        seen = {}
        rows = prior + cases
        for i, row in enumerate(rows):
            keys = [('exact', hashes[i])]
            if row.get('repo') and '/' in row['repo']:
                keys.append(('repository', row['repo'].lower().rstrip('/')))
            for key in keys:
                if key in seen: union(i, seen[key])
                else: seen[key] = i
        x = TfidfVectorizer(ngram_range=(3, 3), use_idf=False, norm='l2', min_df=1).fit_transform(map(normalized, texts))
        near_pairs = 0
        for start in range(0, n, 128):
            similarities = (x[start:start+128] * x.T).tocoo()
            for a, b, value in zip(similarities.row, similarities.col, similarities.data):
                a = int(a) + start; b = int(b)
                if a < b and value >= .90:
                    union(a, b); near_pairs += 1
        contaminated = {find(i) for i in range(len(prior))}
        groups = defaultdict(list)
        for i in range(len(prior), n): groups[find(i)].append(i)
        eligible, excluded = [], []
        for g, indices in groups.items():
            if g in contaminated:
                excluded.extend(cases[i-len(prior)]['id'] for i in indices)
                continue
            group_hash = hashlib.sha256(('external-groups-v1|' + '|'.join(sorted(hashes[i] for i in indices))).encode()).hexdigest()
            # Keep one deterministic representative per component, chosen
            # without the truth label. Mixed-label groups are not split.
            i = min(indices, key=lambda j: hashlib.sha256(('external-representative-v1|' + cases[j-len(prior)]['id']).encode()).hexdigest())
            c = cases[i-len(prior)]
            eligible.append((group_hash, i, c))
        selected = []
        for label in ('malicious', 'normal'):
            pool = sorted([e for e in eligible if e[2]['judgment'] == label])
            selected.extend(pool[:cap])
        output.mkdir(parents=True, exist_ok=False)
        corpus = output / 'corpus'; corpus.mkdir()
        records = []; total = 0
        for group_hash, i, c in sorted(selected):
            sid = 'skilltrustbench-' + c['id']
            files = by_case[c['id']]
            if len(files) > 4096: raise ValueError('case file budget exceeded')
            for m in files:
                rel = PurePosixPath(m.filename).relative_to(c['skill_path'])
                payload = z.read(m)
                total += len(payload)
                if total > MAX_TOTAL: raise ValueError('materialization budget exceeded')
                dest = corpus / sid / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open('xb') as f: f.write(payload)
            records.append(dict(skill_id=sid, dataset='skilltrustbench_external', original_id=c['id'], original_label=c['judgment'], label='malicious' if c['judgment']=='malicious' else 'benign', source_family=c['source'], group_id=group_hash, sha256=hashes[i], split='holdout', files=len(files)))
    serialized = json.dumps(records, indent=2)
    (output/'manifest.json').write_text(serialized)
    tree = hashlib.sha256()
    for p in sorted(corpus.rglob('*')):
        if p.is_file():
            name, payload = p.relative_to(corpus).as_posix().encode(), p.read_bytes()
            tree.update(len(name).to_bytes(8,'big')); tree.update(name)
            tree.update(len(payload).to_bytes(8,'big')); tree.update(payload)
    audit = dict(archive_sha256=ARCHIVE_SHA, selection_manifest_sha256=hashlib.sha256(selection_manifest.read_bytes()).hexdigest(), selection_records=len(prior), external_records=len(cases), external_label_counts=dict(Counter(c['judgment'] for c in cases)), overlap_excluded=len(excluded), overlap_excluded_ids=sorted(excluded), grouping_decode_warning_ids=decoding_warnings, near_pairs_in_joint_corpus=near_pairs, untainted_components=len(eligible), representative_labels=dict(Counter(e[2]['judgment'] for e in eligible)), selected=len(records), selected_labels=dict(Counter(r['original_label'] for r in records)), cap_per_label=cap, manifest_sha256=hashlib.sha256(serialized.encode()).hexdigest(), corpus_sha256=tree.hexdigest(), materialized_bytes=total, limitations=['Content/repository groups are not guaranteed campaign families.', 'Repository provenance is unavailable for external cases in the supplied case index.', 'Suspicious representatives are not treated as benign or malicious.', 'Public data may have been seen by earlier scanner authors.'])
    (output/'materialization.json').write_text(json.dumps(audit,indent=2)+'\n')
    return {k:v for k,v in audit.items() if k != 'overlap_excluded_ids'}

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--selection-manifest', type=Path, required=True)
    p.add_argument('--selection-corpus', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--cap', type=int, default=300)
    a = p.parse_args()
    print(json.dumps(prepare(a.archive,a.selection_manifest,a.selection_corpus,a.output,a.cap),indent=2))
