#!/usr/bin/env python3
"""Fail-closed validation of sealed Skillscan reports and repository policy."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import stat
import sys
from collections import Counter
from pathlib import Path

VERDICTS = ("malicious", "suspicious", "benign")
REQUIRED_FIELDS = {"skill_id", "verdict", "engine_category", "evidence_text"}
REPORTS = ("results.jsonl", "scan-metadata.jsonl", "analysis-metadata.jsonl")
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_ROWS = 4096


def _object(pairs: list[tuple]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _json(text: str) -> object:
    return json.loads(text, object_pairs_hook=_object, parse_constant=_invalid_constant)


def _read(path: Path) -> bytes:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"report must be a regular file, not a link: {path.name}")
    with path.open("rb") as handle:
        data = handle.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError(f"report exceeds size limit: {path.name}")
    return data


def _rows(data: bytes) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for number, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = _json(line)
        if not isinstance(row, dict):
            raise ValueError(f"line {number}: expected an object")
        skill_id = row.get("skill_id")
        if not isinstance(skill_id, str) or not skill_id or skill_id in seen:
            raise ValueError(f"line {number}: missing, invalid, or duplicate skill_id")
        seen.add(skill_id)
        rows.append(row)
        if len(rows) > MAX_ROWS:
            raise ValueError("report exceeds row limit")
    if not rows:
        raise ValueError("results file contains no rows")
    return rows


def _results(data: bytes) -> tuple[list[dict], Counter]:
    rows = _rows(data)
    counts: Counter = Counter()
    for row in rows:
        if set(row) != REQUIRED_FIELDS or not all(isinstance(v, str) for v in row.values()):
            raise ValueError("results.jsonl must keep the stable four-field string contract")
        verdict, category = row["verdict"], row["engine_category"]
        if verdict not in VERDICTS:
            raise ValueError(f"invalid verdict {verdict!r}")
        if (verdict == "benign" and category != "benign") or (verdict != "benign" and not re.fullmatch(r"ast(?:0[1-9]|10)", category)):
            raise ValueError("verdict/category mismatch")
        counts[verdict] += 1
    return rows, counts


def load_results(path: Path) -> tuple[list[dict], Counter]:
    """Format-only loader for evaluation tools. NOT a completeness gate."""
    return _results(_read(path))


def load_sealed_reports(results: Path, metadata: Path | None = None, seal_path: Path | None = None) -> tuple[list[dict], Counter]:
    metadata = metadata or results.with_name("scan-metadata.jsonl")
    seal_path = seal_path or results.with_name("scan-complete.json")
    paths = {"results.jsonl": results, "scan-metadata.jsonl": metadata, "analysis-metadata.jsonl": results.with_name("analysis-metadata.jsonl")}
    seal = _json(_read(seal_path).decode("utf-8"))
    if not isinstance(seal, dict) or type(seal.get("schema_version")) is not int or seal["schema_version"] != 2:
        raise ValueError("missing or unsupported report seal")
    run_id = seal.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id):
        raise ValueError("invalid run identity")
    hashes = seal.get("reports")
    if not isinstance(hashes, dict) or set(hashes) != set(REPORTS):
        raise ValueError("incomplete report hash manifest")
    data = {name: _read(path) for name, path in paths.items()}
    for name, content in data.items():
        if hashlib.sha256(content).hexdigest() != hashes[name]:
            raise ValueError(f"report is stale, changed, or from another run: {name}")
    rows, counts = _results(data["results.jsonl"])
    ids = {row["skill_id"] for row in rows}
    if type(seal.get("skill_count")) is not int or seal["skill_count"] != len(rows):
        raise ValueError("sealed Skill count does not match results")
    for name in REPORTS[1:]:
        companions = _rows(data[name])
        if {row["skill_id"] for row in companions} != ids:
            raise ValueError(f"Skill IDs are not one-to-one: {name}")
        for row in companions:
            if type(row.get("schema_version")) is not int or row["schema_version"] != 2 or row.get("run_id") != run_id:
                raise ValueError(f"incompatible metadata or mixed run: {name}")
            coverage = row.get("coverage")
            if not isinstance(coverage, dict) or any(coverage.get(key) is not True for key in ("collection_complete", "content_complete", "analysis_complete")):
                raise ValueError(f"incomplete coverage: {row['skill_id']}")
            if name == "scan-metadata.jsonl":
                if row.get("complete") is not True or row.get("truncated") is not False or row.get("internal_error"):
                    raise ValueError(f"incomplete scan: {row['skill_id']}")
                for key in ("sampled_files", "read_errors", "skipped_symlinks", "skipped_opaque", "unreviewed_external_instructions"):
                    if type(row.get(key)) is not int or row[key] != 0:
                        raise ValueError(f"incomplete scan ({key}): {row['skill_id']}")
            else:
                dependencies = row.get("external_dependencies", [])
                if not isinstance(dependencies, list) or not all(isinstance(dep, dict) for dep in dependencies):
                    raise ValueError("invalid external dependency inventory")
                if any(dep.get("kind") == "instruction-delegation" and dep.get("content_reviewed") is not True for dep in dependencies):
                    raise ValueError(f"unreviewed external instructions: {row['skill_id']}")
    return rows, counts


def _cell(value: str) -> str:
    value = " ".join(value.split())[:240]
    return html.escape(value).replace("|", "&#124;").replace("`", "&#96;")


def render_summary(rows: list[dict], counts: Counter, *, verified: bool = False) -> str:
    lines = ["## Agent Skill Security Scanner", "", "Verified complete scan; report hashes and Skill IDs match." if verified else "Format-only summary; completeness has not been verified.", "", "| Verdict | Count |", "| --- | ---: |"]
    lines += [f"| {verdict} | {counts[verdict]} |" for verdict in VERDICTS]
    flagged = [row for row in rows if row["verdict"] != "benign"][:20]
    if flagged:
        lines += ["", "### Flagged Skills", "", "| Skill | Verdict | Category | Evidence |", "| --- | --- | --- | --- |"]
        lines += [f"| `{_cell(row['skill_id'])}` | {_cell(row['verdict'])} | {_cell(row['engine_category'])} | {_cell(row['evidence_text'])} |" for row in flagged]
    return "\n".join(lines) + "\n"


def write_outputs(counts: Counter) -> None:
    if output_path := os.environ.get("GITHUB_OUTPUT"):
        with Path(output_path).open("a", encoding="utf-8") as handle:
            for verdict in VERDICTS:
                handle.write(f"{verdict}={counts[verdict]}\n")


def should_fail(policy: str, counts: Counter) -> bool:
    if policy == "malicious":
        return counts["malicious"] > 0
    if policy == "suspicious":
        return counts["malicious"] + counts["suspicious"] > 0
    if policy == "never":
        return False
    raise ValueError("--fail-on must be malicious, suspicious, or never")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--scan-metadata", type=Path)
    parser.add_argument("--seal", type=Path)
    parser.add_argument("--fail-on", default="malicious", choices=("malicious", "suspicious", "never"))
    args = parser.parse_args()
    try:
        rows, counts = load_sealed_reports(args.results, args.scan_metadata, args.seal)
        summary = render_summary(rows, counts, verified=True)
        if summary_path := os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(summary_path).open("a", encoding="utf-8") as handle:
                handle.write(summary)
        else:
            print(summary, end="")
        write_outputs(counts)
        return 1 if should_fail(args.fail_on, counts) else 0
    except (OSError, ValueError, UnicodeError, TypeError, AttributeError) as exc:
        print(f"skillscan gate error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
