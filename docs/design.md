# Scanner design

This document describes the current `main` branch design (v41). Historical
competition behavior is frozen on the
[`competition/v38-final`](https://github.com/daffnjk/agent-skill-security-scanner/tree/competition/v38-final)
branch; version-to-version release details belong in [`CHANGELOG.md`](../CHANGELOG.md).

## Purpose and design goals

`skillscan` is an offline static analyzer for Agent Skills, MCP tools, IDE rules,
and plugin packages. It treats every target package as untrusted data and reports
reviewable evidence without installing, importing, or executing target content.

The design prioritizes:

- high recall for concrete malicious behavior chains;
- bounded resource use on adversarial directory trees;
- deterministic results for the same scanner build and input;
- explicit scan-completeness reporting instead of fail-open `benign` results;
- a stable, minimal result contract for downstream integrations; and
- category-specific evidence that maps non-benign results to AST01-AST10.

The scanner is a triage tool, not a proof of safety. A `benign` verdict means that
the inspected content did not reach the configured risk thresholds; it does not
guarantee that the package is safe.

## Trust boundary and non-goals

The scanner binary and its rule set are trusted. The input directory, file names,
file contents, manifests, documentation, generated code, and embedded URLs are
untrusted.

The scanner does not:

- execute target commands, lifecycle hooks, scripts, or binaries;
- import target packages or resolve their dependencies;
- follow target symlinks;
- fetch target URLs or call external analysis services;
- provide runtime isolation or sandboxing; or
- fully interpret encrypted, deeply obfuscated, generated, or unsupported content.

Unsupported ordinary files are outside the analyzed surface. A skipped symlink,
opaque executable/archive, read failure, exhausted scan budget, or supported file
that cannot be decoded makes the scan incomplete rather than silently safe.

## Architecture

```text
input directory
    |
    v
skill discovery
    |
    v
bounded one-pass collection
    |-- conservative/base profile
    |-- broader/explain profile
    `-- scan-completeness status
    |
    v
candidate findings
    |-- per-file rules
    |-- cross-file correlations
    |-- executable-binary perimeter checks
    `-- bounded Source -> Transform -> Sink verification
    |
    v
weighting and root-cause selection
    |-- benign-context dampening
    |-- verified-flow calibration
    |-- category and blended scores
    `-- document-only verdict cap
    |
    v
controlled explain-profile promotion
    |
    v
scan-completeness enforcement
    |
    +--> results.jsonl
    +--> scan-metadata.jsonl
    `--> analysis-metadata.jsonl
```

The implementation still uses historical `v25` and `v26` names for the base and
explain extractors. These are internal compatibility labels, not the current
product version.

## Input and skill discovery

The first positional argument selects the input directory and the second selects
the output directory. `SKILLS_DIR` and `OUTPUT_DIR` are fallbacks; the container
defaults are `/data/skills` and `/output`.

Each visible first-level directory under the input root is treated as one Skill.
If the root contains no visible child directory, the root itself is scanned as a
single Skill. Skills and retained file paths are sorted before analysis so file
system enumeration order cannot change the result.

## Bounded collection

A single filesystem walk builds two views:

- the **base profile** contains the conservative, verdict-bearing surface;
- the **explain profile** includes additional generated code, configuration, and
  less common text formats that can supply context or pass a stricter promotion
  gate.

Security-sensitive manifests, package lifecycle files, CI and project
configuration, and source code receive budget priority over ordinary documents.
Current per-profile limits are:

- 1 MiB retained from each text-like file;
- 24 MiB retained text per Skill profile; and
- 4,096 retained blobs per Skill profile.

Files larger than 1 MiB are sampled from both head and tail. A successfully
sampled text file is recorded but does not by itself make the scan incomplete.
UTF-8-like text and UTF-16LE/UTF-16BE text are decoded before matching. Known
executable paths receive bounded magic-byte perimeter inspection; opaque content
is not treated as if its behavior had been analyzed.

## Detection layers

### Candidate rules and correlations

Per-file rules emit findings with an AST category, weight, file, evidence reason,
and `strong` flag. Cross-file rules then correlate behavior that is split across
manifests, code, lifecycle files, browser extensions, remote loaders, local
control endpoints, and security metadata.

The rules cover the following primary categories:

| Category | Primary risk represented by this scanner |
| --- | --- |
| AST01 | Malicious skill behavior, including credential exfiltration, command-and-control, persistence, and execution lures |
| AST02 | Supply-chain compromise, lifecycle execution, dependency confusion, CI/build hooks, and project auto-run hijacking |
| AST03 | Excessive authorization, broad host/filesystem access, or dangerous enabled capabilities |
| AST04 | Insecure or deceptive metadata, hidden instructions, prompt injection, and trusted-brand impersonation |
| AST05 | Unsafe deserialization, prototype pollution, and execution-sensitive config injection |
| AST06 | Weak isolation, cloud/container boundary access, or local agent-control hijacking |
| AST07 | Update drift, mutable remote plugins/configuration, and hot-loaded code |
| AST08 | Insufficient scanning, audit tampering, payload evasion, or incomplete analysis |
| AST09 | Governance weakness; normally a weak modifier rather than a primary malicious driver |
| AST10 | Unsafe cross-platform reuse of credentials, sessions, identity, or security metadata |

A result has one primary `engine_category`. Other category scores remain available
as audit metadata and may appear as secondary evidence.

### Bounded behavior-flow verification

v41 adds a small relation layer after broad recall rules. It follows selected
Source -> Transform -> Sink paths in executable files and security-sensitive
configuration, including exact-artifact bridges across files. It is deliberately
bounded and is not a general parser or whole-program taint engine.

Verified flows can:

- add a strong, category-specific finding;
- let a specific AST02/05/06/07 root cause outrank generic AST01 co-occurrence;
- distinguish safe deserialization from unsafe loader paths; and
- dampen broad credential-plus-network heuristics when all observed use is a
  narrow, provider-matched authentication flow.

This layer supplements the existing rules. It cannot erase specific wallet,
metadata-service, persistence, lifecycle, or policy-tampering evidence merely
because a separate safe authentication flow exists.

## Scoring and verdict selection

For each profile, the scanner:

1. collects per-file, cross-file, binary-perimeter, and verified-flow findings;
2. reduces weak findings in documentation, examples, tests, fixtures, and known
   safe-flow contexts;
3. sums the remaining weights by AST category;
4. applies category-specific calibration so a concrete root cause can outrank a
   generic command or network sink;
5. computes a blended score from the primary category plus 18% of every other
   category score, capped at 4.0 per secondary category; and
6. applies deterministic category tie-breaking and the document-only verdict cap.

The current base-profile thresholds are implementation policy:

- `malicious` when the primary score is at least 4.65, or at least 3.25 with a
  strong finding in that category, or the blended score is at least 5.35, or at
  least two strong findings survive weighting;
- `suspicious` when the primary score is at least 1.75 or the blended score is at
  least 2.35; and
- `benign` otherwise.

Strong findings from documentation can still be malicious when they are direct
agent instructions or concrete attack chains. Broad or descriptive document-only
signals are capped at `suspicious` for categories where prose commonly discusses
risk without implementing it.

Threshold changes are behavior changes. They require regression tests and
benchmark comparison; they must not be presented as documentation-only edits.

## Base and explain profile contract

The base profile owns a non-benign verdict and its primary category, evidence,
score, and trigger findings. Broader explain-only findings may add secondary
context but cannot rewrite an already non-benign base result.

If the base profile is benign, the explain profile may promote it only when the
selected category has at least one strong finding and reaches the following
minimum score:

| Explain category | Promotion score |
| --- | ---: |
| AST01, AST02, AST05, AST06, AST07 | 5.0 |
| AST08 | 6.0 |
| AST04 | 6.2 |
| AST10 | 7.5 |

AST03 and AST09 do not promote a benign base result. Known benign examples and
test fixtures are also excluded from explain-profile promotion.

## Scan completeness and failure behavior

Completeness is independent of the classification score. The scanner records
visited, analyzed, skipped, sampled, unreadable, symlinked, opaque, and truncated
input counts for each Skill.

If a scan is incomplete:

- an otherwise benign result becomes `suspicious / ast08`;
- an existing non-benign result is preserved and prefixed with a completeness
  warning;
- an internal scanner panic is recovered as `suspicious / ast08`; and
- the process exits with status 3 after writing available output.

`SKILLSCAN_ALLOW_PARTIAL=1` suppresses exit status 3 for non-Action integrations,
but it does not restore an incomplete Skill to `benign`. The GitHub Action always
treats an incomplete scan as a gate failure.

## Output contracts

The scanner writes three JSONL files to the selected output directory:

| File | Contract |
| --- | --- |
| `results.jsonl` | Stable integration output with exactly `skill_id`, `verdict`, `engine_category`, and `evidence_text` |
| `scan-metadata.jsonl` | Completeness, resource accounting, skipped-input counts, and bounded error samples |
| `analysis-metadata.jsonl` | Trigger layer, score, condition, rule IDs, category scores, and explain-only context |

Separating operational and analytical metadata keeps the four-field ranking
contract stable while retaining enough detail to audit false positives and missed
behavior chains. Non-benign evidence starts with an explicit `OWASP ASTxx` prefix.

Each output is first written to a same-directory temporary file and committed by
rename where supported. A conservative fallback still writes a complete JSONL
file on filesystems with unusual replacement semantics.

Process exit codes are:

- `0`: the scan completed;
- `2`: startup, input, or output failure; and
- `3`: at least one Skill scan was incomplete.

Finding a `suspicious` or `malicious` Skill does not by itself change the CLI exit
code. Policy gating belongs to the GitHub Action or another caller.

## Determinism, deployment, and dependencies

Determinism is provided by sorted Skill/file traversal, stable category priority,
bounded evidence selection, and the absence of time-, randomness-, network-, or
model-dependent decisions. For the same binary, input bytes, arguments, and
environment policy, output is expected to be identical.

The detector uses the Go standard library only. The runtime image is BusyBox,
runs as `USER 1000`, and contains no package manager or model weights. The scanner
does not need network access at runtime.

## Validation and change policy

Changes to collection, rules, scoring, category calibration, or completeness must
include focused regression coverage. New high-confidence rules should have both a
malicious case and a nearby benign counterexample. Provider-authentication,
safe-deserialization, documentation-context, resource-bound, and deterministic
ordering cases are specifically protected against regression.

Public evaluations use frozen dataset revisions and report each dataset
separately because their labels and samples may overlap. Dataset names, sample
IDs, and benchmark-specific allowlists must not appear in detection rules. See
[`benchmarks/v41`](../benchmarks/v41/README.md) for the current public evidence and
[`SELFTEST.md`](../SELFTEST.md) for portable regression coverage.

## Historical evolution

- **v32:** introduced controlled promotion from the broader explain profile.
- **v33-v34:** combined profile collection into one filesystem pass and added
  bounded head/tail sampling, UTF-16 handling, and format-specific hardening.
- **v35:** stabilized the four-field result schema and narrowed permission parsing.
- **v36-v38:** added compound, recall-oriented rules for Agentic Skills Top 10
  behaviors while retaining specificity guards; v38 is the frozen competition
  submission.
- **v39:** added bounded Source -> Transform -> Sink relation verification and
  narrow safe-flow dampening.
- **v40:** made the base verdict provenance explicit: explain-only findings cannot
  rewrite an already non-benign result.
- **v41:** integrated the relation layer with fail-closed collection, executable
  perimeter inspection, analysis metadata, regression calibration, and the GitHub
  pull-request gate.

For release details and competition provenance, see [`CHANGELOG.md`](../CHANGELOG.md)
and [`docs/competition.md`](competition.md).
