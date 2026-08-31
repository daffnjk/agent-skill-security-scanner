# v38 benchmark baseline

This snapshot records the v38 detector's local static-analysis results so future releases can be compared against a stable baseline.

## Scope

- Detector source: repository commit `4d78e38f50a1195139827150de70406008af5b5c`.
- Detector executable SHA-256: `e7374f41448d0f175308f81023642287f6f2274b0960e71700d89a91aecbbff5`.
- Local malicious-skills corpus: 13 evaluation units; 11 completed and 2 metadata-only; 63,707 scans.
- PoisonedSkills: 1,070/1,070 canonical `V<number>/SKILL.md` samples scanned at commit `5068b39ff85c5e9a3afdb856a53b85867043c923`.
- All detector unit tests and bundled regression samples passed before evaluation.

Only aggregate metrics are committed. The downloaded corpora, materialized inputs, raw predictions, and malicious sample text are intentionally excluded.

## Headline results

| Evaluation unit | Strict precision | Strict recall | Strict F2 | Screening recall | Notes |
|---|---:|---:|---:|---:|---|
| Agent Skill Malware | 71.18% | 97.58% | 90.84% | 97.58% | Includes benign negatives |
| SkillTrustBench | 73.52% | 96.40% | 90.75% | 98.36% | Upstream suspicious labels excluded from binary metrics |
| Malicious Skill Bench, package view | N/A | 82.29% | 85.31% | 84.73% | Positive-only unit |
| Malicious Skill Bench, full-text view | 83.45% | 48.99% | 53.40% | 52.64% | Includes benign negatives |
| SkillGuard v2 | 32.82% | 20.79% | 22.44% | 21.23% | Includes benign negatives |
| PoisonedSkills | N/A | 83.18% | 86.07% | 83.18% | 1,070 malicious positives; 890 detected, 180 missed |

See `metrics.csv` for every evaluation unit. No global score is reported because datasets overlap and some contain only positive samples.

## Safety and materialization

All skill content was treated as untrusted static input. No skill, helper script, PoC, URL, test harness, or corpus dependency was executed.

Tabular datasets were deterministically materialized as skill directories. Complete-package views included regular package files without following symbolic links. PoisonedSkills excluded `.claude/` and `V786_poc/`, which are not part of the 1,070 canonical samples.
