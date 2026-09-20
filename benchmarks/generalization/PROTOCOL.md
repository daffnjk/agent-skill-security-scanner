# Frozen generalization experiment — 2026-09-06

## Baseline and safety

Baseline scanner source: `9a69854cbcbd1dd2d092f2f3ec0409ed50868932` (current main, not the historical v41 result). The initial artifact at commit `3ad27e0e6a91b1694411ed5d0ff2f8d04fb627e1` only adds an acquisition workflow; its detector sources are unchanged.

Use only static reading. Never install, import, execute, or fetch URLs contained in samples. Keep sample content and label/provenance metadata in separate directories. Preserve the fail-closed completeness contract. Freeze and verify each release SHA-256 before parsing.

## Sources

| Dataset | Upstream revision | Release SHA-256 | Rows |
|---|---|---|---:|
| agent_skill_malware | 5cff435ddab2cc34261875885de9ac50d40393ec | d66676ce9afce9d14f9c9c715c238f66b78458cf77bc23e4f1eb75a701c61fd3 | 347 |
| atr_skill_benchmark | 7219b10d2ac077e3db8c87d43d653a67935cdb5d | 2971c42c9d0f9d30b788cf6f9de679f8c27b4e8ff322fc67cd42de47d16b7d81 | 498 |
| skillbench_1650 | 68c0d4bf857f48e5fa4f3baa4613f0c0980a7fb2 | 1b027da5b2f21007b8ac620532c37d598fdf73bcced1f42262efbc78da886462 | 1650 |

Sources and original licenses are recorded by daffnjk/agent-skill-security-datasets. The first two are MIT; SkillsBench-1650 is CC-BY-4.0, attributed to Xinze Chen and the upstream skill authors. It includes synthetic malicious injections and dummy binaries, not a representative estimate of production prevalence.

## Development and holdout boundary

Register this protocol before inspecting individual development errors. Only Agent Skill Malware is eligible for development. ATR and SkillsBench-1650 sample errors must not be inspected or used to tune rules before freezing the candidate.

Label-free connected components join exact SKILL.md SHA-256 matches, identical available skill names, identical available repositories, and normalized word-trigram cosine similarity >= 0.90. Normalization lowercases text and replaces URL and long hexadecimal literals for similarity only, never in scanner input. Components receive a SHA-256 ID from the sorted member content hashes and the fixed prefix `split-v1-20260906|`. A component is eligible for development when its first eight hexadecimal digits modulo 10 are below 7 and it contains Agent Skill Malware records. Only its Agent Skill Malware records become development data; other sources in the same component become `overlap_regression`, never clean holdout.

| Source | Development | Holdout | Overlap regression |
|---|---:|---:|---:|
| Agent Skill Malware | 232 (84 malicious / 148 benign) | 115 (40 / 75) | 0 |
| ATR | 0 | 490 (26 / 464) | 8 (6 / 2) |
| SkillsBench-1650 | 0 | 1615 (149 / 1466) | 35 (1 / 34) |

There are 1,718 components and 556 near-duplicate pairs. Initial complete manifest SHA-256: `24ae1d054adc0bf1708aadf2b4d34037c08016eaaea57b18fc92451a274e5879`.

These are content/repository groups, NOT guaranteed attack-campaign families. Malware lacks campaign metadata. All three public sources were used by earlier scanner versions: holdout means untouched by this change, not historically unseen by the project. No claim of an unbiased production estimate is permitted.

## Materialization and integrity

SKILL.md contains only the source content/text field. Companion scripts are separated at upstream `--- filename ---` boundaries. Preserve relative paths; reject traversal, absolute paths and SKILL.md collisions. Duplicate filenames are retained under numbered duplicate directories rather than overwritten. Eight SkillsBench rows have ambiguous materialization; retain and count them, and provide a sensitivity analysis excluding them. No sample may silently disappear because parsing or scanning failed.

## Acceptance and reporting

Strict positive = malicious; separately report screening positive = malicious or suspicious. Report per-source and per-split confusion matrices, precision, recall, F1, F2, FPR, specificity, accuracy, balanced accuracy, MCC, completeness, execution errors, and elapsed time. Undefined metrics are null, not perfect scores. Verify exact prediction IDs, companion metadata and report seals. Incomplete rows remain in denominators and are also reported separately; a return code of 3 is not a clean pass.

Keep thresholds fixed initially. Develop behavior-based changes using positive/negative pairs, with no dataset identifiers, sample allowlists, campaign domains or test-set-specific thresholds in detector code. Freeze candidate source and regression tests before opening holdout outcomes. A holdout regression must be reported, not tuned away while continuing to call the same set blind. Use paired group bootstrap intervals for meaningful changes and disclose small positive support. Do not collapse unlike sources into one headline score or claim that every metric improved without measurement.
