## Unreleased — v0.3.0-dev / v41-hardening.1

- Enforce independent complete-scan validation and sealed, run-bound reports in GitHub Action.
- Use exclusive randomized temporary files for all reports; reject overlapping input/output paths.
- Add explicit single/collection modes, SKILL.md-aware auto discovery, and visible symlink failures.
- Treat sampling and bounded-analysis truncation as incomplete; disable partial-analysis benign dampeners.
- Bound discovery, streaming directory traversal, depth, Skill count, and whole-process scan duration.
- Add explicit stable rule IDs, structured verified-flow positions, scanner/ruleset identity, and scoped input digests.
- Inventory external instruction delegation offline without changing historical AST05 semantics.
- Upgrade production Go to 1.27.1, pin the builder digest, and remove the runtime shell via scratch.
- Add end-to-end regressions and strict/screening benchmark comparison with source/attack/split breakdowns.
- Public benchmark datasets have NOT been rerun for this change.

# Changelog

All notable public changes are documented here.

## Unreleased

## 0.2.0 - 2026-09-03

- Integrate the v41 Generalized Context Flow engine on top of the hardened public mainline, including bounded behavior-flow verification and context-aware Markdown, credential, update, plugin, and PII rules.
- Preserve the stable four-field `results.jsonl` contract and move v41 trigger scores, rule IDs, and secondary explanations into `analysis-metadata.jsonl`.
- Preserve fail-closed input handling and scan-completeness reporting while adding bounded executable-binary perimeter inspection.
- Add malicious and benign counterexample tests for v41 rules, including HTML-comment scope, verified artifact execution, provider-matched authentication, safe YAML loading, and privacy-evasion context.
- Add a reusable GitHub composite Action that scans complete Skill directories, fails closed on incomplete scans, and supports configurable malicious/suspicious merge gates.

- Change the current `main` branch license from MIT to GNU AGPLv3 (`AGPL-3.0-only`), with separate commercial licensing available, and add contribution licensing terms. The frozen `competition/v38-final` snapshot remains unchanged.
- Fail closed on missing, unreadable, truncated, symlinked, or opaque scan input; incomplete scans can no longer remain benign.
- Add `scan-metadata.jsonl` with per-Skill completeness and resource/error telemetry while preserving the four-field competition result schema.
- Prioritize manifests, lifecycle files, CI/project configuration, and source code before documentation consumes the bounded scan budget.
- Normalize mixed-case rule needles, make plain `SKILL.md` content reachable by document rules, and add Terraform file collection.
- Use deterministic blended-score and secondary-evidence ordering, strengthen JSON capability parsing, and add hardening/fuzz regression seeds.
- Pin CI actions to commit SHAs, add vet/race/coverage/container checks, and make Docker/Makefile builds architecture-aware.

- Corrected the competition provenance: the open-source v38 / recall micro-loop 115 engine is the final Track B submission, not a post-contest successor.
- Added the final score and component breakdown: 7.27/10 total, with 4.34 detection quality, 1.10 explainability, 0.83 runtime robustness, and 1.00 performance.
- Added the final rank statement of 20+ to both Chinese and English project pages.
- Added prominent score and rank badges plus a weighted-score reconciliation table.
- Reframed the project around its competition origin, cross-file behavior analysis, deterministic explainability, and bounded offline operation.
- Added a Chinese-first project page and an English README.
- Added an explicit competition-result, version-integrity, and disclosure-boundary note.

## 0.1.0 - 2026-08-31

- Open-source release of the final competition v38 rule engine with recall micro-rules through loop 115.
- Renamed the project to Agent Skill Security Scanner and the binary to `skillscan`.
- Added portable host tests, GitHub Actions CI, public documentation, and community health files.
- Preserved offline, deterministic scanning and the stable four-field JSONL output schema.
