# CI integration and report validation

This document describes `main` (`v0.3.0-dev` / `v41-hardening.1`). The published
`v0.2.0` Action uses the earlier v41 contract; its reports do not satisfy the
schema-v2 validator. See [hardening.md](hardening.md) for migration details and
[README_EN.md](../README_EN.md#github-actions-gate) for a pinned workflow example.

## Output contracts

- `results.jsonl` retains exactly `skill_id`, `verdict`, `engine_category`, and `evidence_text`.
- `scan-metadata.jsonl` carries schema-v2 run identity and collection/content/analysis coverage.
- `analysis-metadata.jsonl` carries matching identity and coverage, trigger evidence, scanner/ruleset identity, and external instruction inventory.
- `scan-complete.json` is written last and binds all three reports by SHA-256, run ID, and Skill count.

The four-field result format is preserved, but automated gates must consume the
complete report bundle. A seal is not a signature or proof of full coverage.

## GitHub pull-request gate

The composite Action builds the scanner from its selected source revision,
constrains input/output paths to `GITHUB_WORKSPACE`, rejects overlapping paths,
and scans complete Skill directories without executing target content.
`mode` selects `auto`, `single`, or `collection`; `timeout` defaults to `5m`.

After a successful CLI exit, the Python gate independently validates report
hashes, schema, run IDs, one-to-one Skill IDs, complete metadata, and coverage.
Only then does it apply `fail_on`:

| Policy | Risk blocking |
| --- | --- |
| `malicious` (default) | Block scanner verdicts labeled malicious |
| `suspicious` | Block suspicious and malicious verdicts |
| `never` | Disable risk blocking only |

Startup failures, sampling, truncation, unreviewed external instruction coverage,
and invalid or incomplete reports always block. The Action forces
`SKILLSCAN_ALLOW_PARTIAL=0`; the independent validator also rejects partial
reports even if a standalone caller suppressed the CLI exit code.

The validator returns `0` for a pass, `1` for a risk-policy block, and `2` for
invalid/incomplete reports. Validated runs produce verdict counts and a job
summary. The Action exposes those counts plus the `results` path.

Use an immutable scanner commit from a trusted source and a read-only
`pull_request` workflow. The Ubuntu example requires Bash, Python 3, and Go;
Action setup/build may access the network, while target analysis stays offline.
Scan an immutable local snapshot and retain all four output files together.
Do not execute target hooks to prepare a scan or interpret a `benign` result as
a guarantee that a Skill is safe to run.

## Generalization controls

- No dataset names, sample identifiers, or fixed benchmark titles are used by detection rules.
- New high-confidence rules require paired malicious and benign counterexamples.
- Public metrics are reported per dataset because benchmark families have different labels and may overlap.
- Dataset downloads and version pinning remain in the separate `agent-skill-security-datasets` repository.
- A release candidate should be evaluated on frozen revisions before tagging and should include incomplete, skipped, and unmatched sample counts alongside classification metrics.
