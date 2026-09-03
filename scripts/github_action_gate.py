#!/usr/bin/env python3
"""Validate skillscan JSONL, publish a GitHub summary, and enforce gate policy."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

VERDICTS = ("malicious", "suspicious", "benign")
REQUIRED_FIELDS = {"skill_id", "verdict", "engine_category", "evidence_text"}


def load_results(path: Path) -> tuple[list[dict], Counter]:
    rows: list[dict] = []
    counts: Counter = Counter()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: invalid JSON: {exc}") from exc
            missing = REQUIRED_FIELDS - set(row)
            if missing:
                raise ValueError(f"line {line_number}: missing fields {sorted(missing)}")
            if set(row) != REQUIRED_FIELDS:
                raise ValueError(f"line {line_number}: results.jsonl must keep the stable four-field contract")
            verdict = row["verdict"]
            if verdict not in VERDICTS:
                raise ValueError(f"line {line_number}: invalid verdict {verdict!r}")
            rows.append(row)
            counts[verdict] += 1
    if not rows:
        raise ValueError("results file contains no rows")
    return rows, counts


def render_summary(rows: list[dict], counts: Counter) -> str:
    lines = [
        "## Agent Skill Security Scanner v41",
        "",
        "| Verdict | Count |",
        "| --- | ---: |",
        f"| malicious | {counts['malicious']} |",
        f"| suspicious | {counts['suspicious']} |",
        f"| benign | {counts['benign']} |",
        "",
    ]
    flagged = [row for row in rows if row["verdict"] != "benign"][:20]
    if flagged:
        lines.extend(["### Flagged Skills", "", "| Skill | Verdict | Category | Evidence |", "| --- | --- | --- | --- |"])
        for row in flagged:
            evidence = str(row["evidence_text"]).replace("|", "\\|").replace("\n", " ")[:240]
            lines.append(f"| `{row['skill_id']}` | {row['verdict']} | {row['engine_category']} | {evidence} |")
        if counts["malicious"] + counts["suspicious"] > len(flagged):
            lines.extend(["", "Only the first 20 flagged Skills are shown; inspect the JSONL artifact for the full result."])
    return "\n".join(lines) + "\n"


def write_outputs(counts: Counter) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
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
    parser.add_argument("--fail-on", default="malicious")
    args = parser.parse_args()
    try:
        rows, counts = load_results(args.results)
        summary = render_summary(rows, counts)
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with Path(summary_path).open("a", encoding="utf-8") as handle:
                handle.write(summary)
        else:
            print(summary, end="")
        write_outputs(counts)
        return 1 if should_fail(args.fail_on, counts) else 0
    except (OSError, ValueError) as exc:
        print(f"skillscan gate error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
