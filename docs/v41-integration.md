# v41 integration design

v41 combines two previously separate development lines:

1. the public mainline's fail-closed collection, resource accounting, deterministic output, and four-field compatibility contract;
2. the competition-derived Generalized Context Flow engine's bounded behavior relations and cross-dataset false-positive calibration.

The integration intentionally uses the hardened public `main` branch as the operational boundary. v41 detection logic may change a verdict or AST category, but it does not bypass input validation, scan-completeness enforcement, atomic output writes, or the non-root container contract.

## Output contracts

- `results.jsonl` remains exactly four fields: `skill_id`, `verdict`, `engine_category`, and `evidence_text`.
- `scan-metadata.jsonl` records whether supported input was scanned completely. An incomplete scan cannot remain benign and exits with status 3 unless explicitly overridden outside the GitHub Action.
- `analysis-metadata.jsonl` contains v41 trigger layer, score, condition, finding IDs, category scores, and explain-only context.

Keeping operational and analytical metadata separate prevents downstream schema breakage while retaining enough detail to diagnose false positives and missed behavior chains.

## GitHub pull-request gate

The root `action.yml` builds the trusted scanner source, constrains scan and output paths to `GITHUB_WORKSPACE`, scans each complete Skill directory, validates the result schema, writes a job summary, and applies the configured gate:

- `malicious`: fail only on confirmed malicious verdicts;
- `suspicious`: fail on suspicious or malicious verdicts;
- `never`: report verdicts without policy failure.

Scanner startup errors and incomplete scans always fail closed. The Action uses `pull_request` safely without requiring repository secrets and never executes target Skill code.

## Generalization controls

- No dataset names, sample identifiers, or fixed benchmark titles are used by detection rules.
- New high-confidence rules require paired malicious and benign counterexamples.
- Public metrics are reported per dataset because benchmark families have different labels and may overlap.
- Dataset downloads and version pinning remain in the separate `agent-skill-security-datasets` repository.
- A release candidate should be evaluated on frozen revisions before tagging and should include incomplete, skipped, and unmatched sample counts alongside classification metrics.
