# Changelog

All notable public changes are documented here.

## Unreleased

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
