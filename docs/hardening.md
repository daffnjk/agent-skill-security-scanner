# Security boundaries and migration (unreleased)

Release namespace: `v0.3.0-dev`. Engine namespace: `v41-hardening.1`.
Published `v0.2.0` / engine `v41` metrics remain historical. This change does not
claim a new release or a public-dataset precision/recall improvement.

## Input and output

```
skillscan --single --timeout 5m ./my-skill ./reports
skillscan --collection ./skills ./reports
skillscan --mode auto ./my-skill ./reports
```

Flags precede positional paths. Auto mode treats a root containing `SKILL.md`
as one Skill, even when it contains `scripts/`. Without that marker, visible
immediate directories (including symlinks recorded as incomplete) form a
collection; a directory without such entries retains the single-root fallback.
Use explicit modes for ambiguous layouts. Collection mode rejects an empty
collection. A symbolic-link input root is rejected.

Input and output paths must be disjoint in either direction after canonicalizing
existing ancestors. Each report uses an exclusive randomized temporary file,
flushes and syncs before rename, and cleans up its own temporary file. A
pre-existing predictable `.tmp` link is never opened. A destination link is
replaced as a directory entry, not followed. The previous completion seal is
invalidated before scanning. Individual report files may remain after failure;
they MUST NOT be consumed without the new verified seal.

Output parents must be trusted. Scan an immutable, pre-extracted input snapshot;
concurrent modification, mounts/device changes, network filesystems and hostile
mutation of the output parent are outside this portable implementation's threat
model. Checksums bind reports together; they are NOT signatures and do not
protect against an actor authorized to replace all reports and their seal.

## Coverage and mandatory gates

`results.jsonl` keeps exactly `skill_id`, `verdict`, `engine_category` and
`evidence_text`. `scan-metadata.jsonl` and `analysis-metadata.jsonl` are additive
schema-v2 companions. `scan-complete.json` is written last and contains a random
run ID, exact Skill count and SHA-256 hashes of all three reports.

The gate checks report hashes, schema/type correctness, duplicate IDs, one-to-one
Skill IDs, matching run IDs, metadata completeness and all coverage dimensions.
It rejects absent, mixed, modified, sampled, truncated or incomplete reports
before evaluating `fail_on`. `never` disables risk blocking ONLY.

`coverage.collection_complete` concerns discovery/collection of supported local
input; `content_complete` concerns full readable content rather than sampling;
`analysis_complete` concerns the bounded behavior analyzer and inventory.
The inherited allow-partial environment variable cannot affect the Action:
`SKILLSCAN_ALLOW_PARTIAL=0` is set explicitly and the gate independently verifies
metadata. The standalone CLI retains `SKILLSCAN_ALLOW_PARTIAL=1` for exploratory
research, but it changes only the exit code, not metadata or a non-benign
completeness verdict.

Limits: 4,096 Skills; 100,000 collection entries; 100,000 visited filesystem entries
per Skill; depth 64; existing 4,096 blobs/profile and 24 MiB/profile limits; 1 MiB
head/tail file sampling; 12,000 behavior statements/file; 32,768 bytes/statement;
256 external URL records/document and 1,024/Skill (2,048 displayed URL bytes);
32 MiB/report; 1,000,000 aggregate visited entries/collection; default whole-run deadline
five minutes. Traversal reads directories in bounded batches. Touching a limit
fails closed. The process deadline covers discovery and scanning after output
preparation; deployment-level job/container deadlines should cover startup and
filesystem preparation too. All per-Skill limits are aggregated under this
whole-process deadline, rather than claiming a fixed whole-collection memory or
CPU quota. Use container resource limits for those bounds.

Sampling or behavior truncation cannot retain a benign verdict, and partial
behavior summaries cannot apply provider-auth or safe-deserialization dampeners.
Directory exclusions and unsupported ordinary formats remain scoped out; a
complete scan is NOT proof of absence of malicious behavior.

Exit codes: `0` completed (or explicit standalone partial override); `2` usage,
input/output, discovery or deadline failure; `3` incomplete local/analysis/external
instruction coverage. Risk blocking is performed by the gate (`1` for a policy
block, `2` for invalid/incomplete reports).

## Identity and evidence

Production `Finding` literals carry explicit persisted `SKILL-Rnnnn` IDs. The
migration catalog is in `rule-catalog.json`; retain IDs when editing wording.
Dynamic emitters identify a rule family; they must be split into separate IDs
when new independent logic is introduced. New findings must use explicit IDs.
`legacy_rule_id` preserves the previous reason-hash identifier for migration.
An in-process caller omitting an ID is labeled `legacy-evidence-derived`, never
silently advertised as stable.

Verified-flow findings expose structured source-file statement locations where
the analyzer actually has them. Other legacy findings do not invent line/column
positions. A fingerprint uses rule ID, file and statement range; locationless
legacy findings additionally use evidence to distinguish them, so those
fingerprints can change with prose even though their rule IDs remain stable.

Analysis metadata includes scanner version, engine version, Git revision when
available, SHA-256 of embedded detection/boundary sources, the taxonomy version,
and an input digest. `supported-read-bytes-v1` hashes each readable candidate's
relative path, original size and inspected raw bytes in deterministic candidate
order. It is NOT a whole-directory digest: skipped and unread bytes are not
covered. Always interpret it together with completeness and coverage.

## External instructions and taxonomy compatibility

Historical categories use `skillscan-legacy-v41`. In particular historical
`ast05` continues to mean deserialization/configuration-injection findings.
It is NOT silently renamed to the current OWASP meaning.

External inventory annotations use
`owasp-ast-v1-public-review-observed-2026-09-05`: the OWASP project page observed
on that date labels AST05 "Untrusted External Instructions" and identifies the
v1 document as under public review. This is an observed draft mapping, not a
claim of a finalized normative standard.

- Ordinary documentation URLs are recorded as references, not maliciousness.
- Explicit requests to follow/execute externally hosted instructions are marked
  as unreviewed delegation and make the scan incomplete. Detection is lexical,
  English/Chinese and deliberately bounded; it is not complete semantic analysis.
- URLs are NEVER fetched. Immutable-looking GitHub commit references are marked
  as version-pinned, but pinning never means reviewed or safe.
- URL userinfo, query and fragment are redacted; an exact-URL hash is retained.
  Sampled views do not claim original-file line numbers.

Review and vendor dependencies into an immutable local Skill snapshot for
rescanning. This change does not implement an automatic remote fetcher,
network-enabled sandbox, or signed snapshot-review authorization protocol.

| Internal family | Historical output | Observed draft annotation |
| --- | --- | --- |
| Deserialization/config injection | AST05 (unchanged) | No automatic one-to-one migration; requires rule-specific review |
| External instruction delegation | Completeness warning AST08 | AST05 in external dependency metadata |
| Other historical rules | AST01–AST10 (unchanged) | No blanket claim of conformance to an unversioned draft |

Sources: https://owasp.org/www-project-agentic-skills-top-10/ and
https://go.dev/doc/devel/release (verified 2026-09-05). Production CI and Action use
Go 1.27.1; `go.mod`'s Go 1.23 language floor is not a production-toolchain pin.
The container has a digest-pinned Go builder and a static `scratch` runtime.

## Benchmark acceptance

```
python3 scripts/compare_benchmarks.py \
  --labels labels.jsonl --baseline old/results.jsonl \
  --candidate new/results.jsonl --output comparison.json
```

Labels contain `skill_id`, `label` (`malicious`/`benign`), optional `source`,
`attack_type`, and `split`. Population mismatch and duplicate prediction IDs
fail; non-binary labels are explicitly counted as excluded. Undefined rates
are null, not zero. Reports separate strict and screening metrics, newly fixed
and newly introduced false positives/negatives, and source/attack/split groups.
Assign holdouts before tuning, including source/author/time separation where
available. Do not describe an unspecified split as independent validation.

Do not tune a single global threshold from the published v41 headline scores.
That snapshot includes low strict recall on SkillGuard v2 and high false
positive rate on SkillTrustBench. Keep both boundary failures and detection
failures visible; do not relabel an incomplete scan as a true negative.
Full public-dataset reruns remain an explicit release acceptance requirement.

## Verification

CI runs Go formatting/vet, full unit tests with coverage, race tests, historical
self-tests, Python gate/benchmark tests, real CLI/gate regression tests, and a
container build. The implementation run records its actual outcomes separately;
this document does not assert that an unexecuted test passed.
