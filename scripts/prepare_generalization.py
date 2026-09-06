#!/usr/bin/env python3
"""Materialize three checksum-frozen sources as inert text and freeze group splits.

No archive is extracted to disk, no sample code is executed, and metadata never
enters a scanned Skill directory. Requires scikit-learn for label-free grouping;
pyarrow is needed only when --skillsbench-records is not supplied.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

ASSETS = {
    'agent_skill_malware': 'd66676ce9afce9d14f9c9c715c238f66b78458cf77bc23e4f1eb75a701c61fd3',
    'atr_skill_benchmark': '2971c42c9d0f9d30b788cf6f9de679f8c27b4e8ff322fc67cd42de47d16b7d81',
    'skillbench_1650': '1b027da5b2f21007b8ac620532c37d598fdf73bcced1f42262efbc78da886462',
}
EXPECTED_COUNTS = {'agent_skill_malware': 347, 'atr_skill_benchmark': 498, 'skillbench_1650': 1650}
EXPECTED_MANIFEST = '24ae1d054adc0bf1708aadf2b4d34037c08016eaaea57b18fc92451a274e5879'
EXPECTED_RECORDS = '17b5d171bbe259de30d513bc0e3dd5f1644b7b3b9425b031b3a5f5d46e02a3e3'
EXPECTED_CORPUS = 'a688ffff1dec611bd5b422d4f90d1f42cf14b974befed0fd40419b8e9f21cdab'
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_MEMBER = 128 * 1024 * 1024
MAX_CORPUS = 512 * 1024 * 1024


def safe_relative(name: str) -> PurePosixPath:
    p = PurePosixPath(name.replace('\\', '/'))
    if p.is_absolute() or '..' in p.parts or not p.parts or ':' in name or p.as_posix().casefold() == 'skill.md' or len(name) > 1024:
        raise ValueError('unsafe companion path')
    return p


def script_pieces(script: str, filenames: list[str]) -> tuple[list[tuple[str, str]], bool]:
    chunks = re.split(r'(?m)^--- (.+?) ---\s*\n', script)
    if len(chunks) > 1:
        if chunks[0].strip():
            # Not present in the frozen snapshot. A changed adapter must not
            # silently throw away this previously unknown representation.
            raise ValueError('unassigned script prefix; review materialization')
        return list(zip(chunks[1::2], chunks[2::2])), False
    if script.strip() and len(filenames) == 1:
        return [(filenames[0], script)], False
    if script.strip():
        return [('companion.txt', script)], True
    return [], False


def archive_rows(assets: Path, dataset: str, filename: str | None = None) -> list[dict]:
    path = assets / f'{dataset}-2026-08-30.tar.gz'
    if path.stat().st_size > MAX_ARCHIVE or hashlib.sha256(path.read_bytes()).hexdigest() != ASSETS[dataset]:
        raise ValueError('archive checksum or size mismatch: ' + dataset)
    rows = []
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        if len(members) > 10000:
            raise ValueError('archive member budget exceeded')
        for member in members:
            selected = member.name == f'{dataset}-2026-08-30/data/{filename}' if filename else member.name.endswith('.parquet')
            if not selected:
                continue
            if not member.isfile() or member.size > MAX_MEMBER:
                raise ValueError('unsafe archive member')
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError('unreadable archive member')
            payload = handle.read(MAX_MEMBER + 1)
            if len(payload) > MAX_MEMBER:
                raise ValueError('member read budget exceeded')
            if filename:
                rows.extend(json.loads(line) for line in payload.decode('utf-8').splitlines() if line.strip())
            else:
                import pyarrow.parquet as pq
                rows.extend(pq.read_table(io.BytesIO(payload)).to_pylist())
    if len(rows) != EXPECTED_COUNTS[dataset]:
        raise ValueError('unexpected dataset row count: ' + dataset)
    return rows


def assign_groups(records: list[dict], texts: list[str]) -> dict:
    from sklearn.feature_extraction.text import TfidfVectorizer
    normalized = [re.sub(r'\b[a-f0-9]{24,}\b', ' HEX ', re.sub(r'https?://[^\s<>"\)]+', ' URL ', text.lower())) for text in texts]
    x = TfidfVectorizer(ngram_range=(3, 3), use_idf=False, norm='l2', min_df=1).fit_transform(normalized)
    sim = (x * x.T).tocoo()
    parent = list(range(len(records)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    def union(i, j):
        a, b = find(i), find(j)
        if a != b:
            parent[max(a, b)] = min(a, b)
    near = 0
    for i, j, value in zip(sim.row, sim.col, sim.data):
        if i < j and value >= 0.90:
            union(int(i), int(j))
            near += 1
    seen = {}
    for i, row in enumerate(records):
        keys = [('exact', row['sha256'])]
        if row.get('repo') and '/' in row['repo']:
            keys.append(('repository', row['repo'].lower().rstrip('/')))
        if row.get('skill_name'):
            keys.append(('name', row['skill_name'].lower()))
        for key in keys:
            if key in seen:
                union(i, seen[key])
            else:
                seen[key] = i
    groups = defaultdict(list)
    for i in range(len(records)):
        groups[find(i)].append(i)
    for indices in groups.values():
        group = hashlib.sha256(('split-v1-20260906|' + '|'.join(sorted(records[i]['sha256'] for i in indices))).encode()).hexdigest()
        develop = int(group[:8], 16) % 10 < 7 and any(records[i]['dataset'] == 'agent_skill_malware' for i in indices)
        for i in indices:
            records[i]['group_id'] = group
            records[i]['split'] = 'development' if develop and records[i]['dataset'] == 'agent_skill_malware' else 'overlap_regression' if develop else 'holdout'
    return dict(groups=len(groups), near_duplicate_pairs=near, maximum_group_size=max(map(len, groups.values())))


def prepare(assets: Path, output: Path, records_file: Path | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    corpus = output / 'corpus'
    corpus.mkdir()
    records, texts, written_bytes = [], [], 0
    def write(path, text):
        nonlocal written_bytes
        payload = text.encode('utf-8')
        written_bytes += len(payload)
        if written_bytes > MAX_CORPUS:
            raise ValueError('materialization byte budget exceeded')
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as handle:
            handle.write(payload)
    for dataset, member, field in (('agent_skill_malware', 'skills.jsonl', 'content'), ('atr_skill_benchmark', 'atr-skill-benchmark.jsonl', 'text')):
        for i, row in enumerate(archive_rows(assets, dataset, member)):
            sid = f'{dataset}-{i:05d}'
            text = row[field]
            write(corpus / sid / 'SKILL.md', text)
            texts.append(text)
            records.append(dict(skill_id=sid, dataset=dataset, original_id=row['id'], label=row['label'], skill_name=row.get('skill_name', ''), source_family=row.get('source_family', ''), sha256=hashlib.sha256(text.encode()).hexdigest()))
    if records_file:
        if records_file.stat().st_size > MAX_MEMBER or hashlib.sha256(records_file.read_bytes()).hexdigest() != EXPECTED_RECORDS:
            raise ValueError('decoded records do not match verified parquet artifact')
        rows = [json.loads(line) for line in records_file.read_text(encoding='utf-8').splitlines() if line.strip()]
    else:
        rows = archive_rows(assets, 'skillbench_1650')
    if len(rows) != 1650:
        raise ValueError('unexpected SkillsBench count')
    for i, row in enumerate(rows):
        sid = f'skillbench_1650-{i:05d}'
        dest = corpus / sid
        text = row['content']
        write(dest / 'SKILL.md', text)
        texts.append(text)
        pieces, ambiguous = script_pieces(row.get('script_content') or '', json.loads(row.get('script_files') or '[]'))
        written = []
        for rel, content in pieces:
            path = safe_relative(rel)
            target = dest.joinpath(*path.parts)
            if target.exists():
                ambiguous = True
                target = dest / f'_duplicate_{len(written):03d}' / path
            write(target, content)
            written.append(str(path))
        records.append(dict(skill_id=sid, dataset='skillbench_1650', original_id=row['content_hash'], label=row['label'], repo=row.get('repo', ''), path=row.get('path', ''), attack_type=row.get('attack_type', ''), difficulty=row.get('difficulty', ''), sha256=hashlib.sha256(text.encode()).hexdigest(), files=written, materialization_warning=ambiguous))
    stats = assign_groups(records, texts)
    manifest = json.dumps(records, indent=2)
    digest = hashlib.sha256(manifest.encode()).hexdigest()
    if digest != EXPECTED_MANIFEST:
        raise ValueError('manifest differs from preregistered split; do not relabel as the frozen experiment')
    tree = hashlib.sha256()
    for path in sorted(corpus.rglob('*')):
        if path.is_file():
            name, payload = path.relative_to(corpus).as_posix().encode(), path.read_bytes()
            tree.update(len(name).to_bytes(8, 'big'))
            tree.update(name)
            tree.update(len(payload).to_bytes(8, 'big'))
            tree.update(payload)
    if tree.hexdigest() != EXPECTED_CORPUS:
        raise ValueError('materialized companion bytes differ from frozen corpus')
    (output / 'manifest.json').write_text(manifest, encoding='utf-8')
    stats |= dict(manifest_sha256=digest, materialized_bytes=written_bytes, corpus_sha256=tree.hexdigest(), rows=len(records), ambiguous_rows=sum(r.get('materialization_warning', False) for r in records))
    (output / 'materialization.json').write_text(json.dumps(stats, indent=2) + '\n')
    return stats

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--skillsbench-records', type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.assets, args.output, args.skillsbench_records), indent=2))
