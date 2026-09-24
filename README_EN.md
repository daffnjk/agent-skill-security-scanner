<div align="center">

# Agent Skill Security Scanner

### Review prompts, code, and permissions before installing or running Agent Skills

`skillscan` is an offline static security scanner for AI Agent Skills, MCP tools, IDE rules, and plugin bundles. Built with the Go standard library, it combines rules, cross-file correlation, and bounded behavior-flow analysis to produce reviewable evidence, with scan-completeness and report-integrity checks for CI.

[![CI](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Offline](https://img.shields.io/badge/runtime-offline-1f883d)](Dockerfile)
[![License](https://img.shields.io/badge/license-AGPL--3.0-663399)](LICENSE)

[中文](README.md)

</div>

## Versions and scope

| Version | Status | Documentation |
| --- | --- | --- |
| `main`: `v0.3.0-dev` / `v` | Unreleased development build | Commands, input modes, and report validation on this page |
| `v0.2.0` / `v` | Published release | [Version-specific README](https://github.com/daffnjk/agent-skill-security-scanner/blob/v0.2.0/README_EN.md); does not include the new completeness contract |
| [Frozen competition snapshot](https://github.com/daffnjk/agent-skill-security-scanner/tree/competition/v38-final) | Frozen competition snapshot | Historical reproduction only; scores do not describe current main |

Read the [security boundaries and migration notes](docs/hardening.md) before upgrading from v0.2.0. Historical v public benchmarks have not been rerun for the current development build.

## What is `skillscan`?

An Agent Skill can contain more than prompts: scripts, permission manifests, install hooks, CI workflows, and auto-run configuration may all be part of the package. Meaningful risk often spans several files.

`skillscan` treats every package as **untrusted data**. It does not install, import, or execute package code, and it does not contact URLs declared by the package. Instead, it correlates permissions, command execution, sensitive-data access, and network behavior into reviewable findings.

> [!NOTE]
> This is a heuristic static-analysis tool. Findings are security-review leads, not final proof that a package is safe or malicious.

## Use cases

- **Pre-installation review** of third-party Skill instructions, scripts, permissions, and dependency declarations.
- **Repository and PR gates** that scan complete Skill directories, apply risk policy, and reject incomplete scans.
- **Security review and regression analysis** using rule IDs, behavior evidence, and coverage metadata to investigate false positives, misses, and version changes.

Provide MCP tools, IDE rules, and plugins as local directories. The scanner does not connect to running MCP servers or install or launch plugins.

## How it works

| Stage | What it does |
| --- | --- |
| **Collect** | Reads supported code, documentation, manifests, and configuration in security-aware order with bounded resource use |
| **Correlate** | Combines file-level rules with cross-file behavior chains instead of judging isolated keywords |
| **Report** | Emits a verdict, primary AST category, evidence, and separate scan-completeness metadata |

```text
Skill directories
      ↓
Bounded file collection
      ↓
Rules + cross-file correlation
      ↓
Risk result ───→ results.jsonl
Scan state ────→ scan-metadata.jsonl
Trigger audit ─→ analysis-metadata.jsonl
Report seal ───→ scan-complete.json
```

## What it detects

- Credential, browser, wallet, cloud-token, and workspace-data exfiltration
- Install hooks, dependency confusion, CI download-and-execute, and project auto-run risks
- Broad filesystem, network, shell, host, and container permissions
- Hidden prompts, tool-description injection, brand impersonation, and metadata/runtime contradictions
- Unsafe deserialization, encoded payloads, dynamic loading, and scan evasion
- Remote update drift, isolation-boundary risks, and lost security metadata during platform reuse

Non-benign findings use `ast01`–`ast10` in the `v` taxonomy. These retain historical meanings rather than claiming conformance to an unversioned OWASP taxonomy; historical `ast05` still means deserialization/configuration injection. See the [design notes](docs/design.md) and [migration mapping](docs/hardening.md).

## Quick start

The source language floor is Go 1.23; CI, Action, and Docker builds currently pin Go 1.27.1. This builds the development version from `main`:

```bash
git clone https://github.com/daffnjk/agent-skill-security-scanner.git
cd agent-skill-security-scanner
make build

./skillscan --collection ./testdata/skills ./out
cat ./out/results.jsonl
```

For a collection, use `--collection` with one complete Skill in each visible first-level directory:

```text
skills/
├── calendar-helper/
│   ├── SKILL.md
│   └── manifest.json
└── code-reviewer/
    ├── package.json
    └── index.js
```

```bash
./skillscan --collection ./skills ./out

# Scan one whole Skill, including nested scripts/ directories
./skillscan --single --timeout 5m ./skills/calendar-helper ./out-single
```

Flags must precede both paths. Default `--mode auto` treats a root with `SKILL.md` as one Skill; otherwise it uses visible immediate directories as a collection, falling back to the root when none exist. Use explicit modes for ambiguous layouts; `--collection` rejects empty collections.

Input and output directories must be disjoint: neither may equal or contain the other. `SKILLS_DIR` and `OUTPUT_DIR` are fallbacks, overridden by positional paths; defaults are `/data/skills` and `/output`. The default `5m` deadline covers discovery and analysis after output preparation.

## Output

`results.jsonl` contains one object per Skill:

```json
{"skill_id":"chain-supply-update","verdict":"malicious","engine_category":"ast02","evidence_text":"OWASP AST02 ..."}
```

| Field | Meaning |
| --- | --- |
| `skill_id` | Skill directory name |
| `verdict` | `benign`, `suspicious`, or `malicious` |
| `engine_category` | Primary `ast01`–`ast10` category, or `benign` |
| `evidence_text` | Matched behavior, relevant files, and the reason for the result |

A scan produces three JSONL reports and one seal:

| File | Content |
| --- | --- |
| `results.jsonl` | Stable four-field verdict records shown above |
| `scan-metadata.jsonl` | Collection, content, and analysis coverage; sampling, read failures, skipped inputs, and resource limits |
| `analysis-metadata.jsonl` | Trigger conditions, scores, stable rule IDs, available statement locations, scanner identity, and external instruction inventory |
| `scan-complete.json` | Written last, containing a run ID, Skill count, and SHA-256 hashes of all three reports |

A seal alone does not prove completeness: validate report hashes, run IDs, Skill IDs, and coverage together. It detects mixed or modified reports, but is not a digital signature. Reuse the bundled validator for automated gates:

```bash
python3 scripts/github_action_gate.py --results ./out/results.jsonl --fail-on malicious
```

The gate returns `0` when validation and policy pass, `1` for a risk-policy block, and `2` for invalid or incomplete reports. `--fail-on never` disables risk blocking only.

CLI status is independent of risk policy:

| CLI exit code | Meaning |
| --- | --- |
| `0` | Complete scan; findings may still be present |
| `2` | Usage, input/output, discovery, or deadline error |
| `3` | Incomplete local content, analysis, or external instruction coverage for at least one Skill |

An incomplete scan promotes an otherwise `benign` result to `suspicious / ast08`; existing non-benign results retain their verdict with a completeness warning. A risk verdict alone does not change CLI status. Standalone `SKILLSCAN_ALLOW_PARTIAL=1` suppresses status `3`, but does not repair coverage or bypass the Action gate.

## Docker

```bash
docker build -t skillscan:local .
mkdir -p out

docker run --rm --network none \
  -v "$PWD/skills:/data/skills:ro" \
  -v "$PWD/out:/output" \
  skillscan:local --collection
```

The `scratch` runtime runs as UID `1000` without a shell or package manager. The host output directory must be writable by UID `1000`. Building may require network access; scanning does not, and the example disables container networking.

## GitHub Actions gate

This example pins the mainline commit containing the current completeness contract. It is a development snapshot, not `v0.2.0`. The Action uses Bash, Python 3, and a Go build environment on an Ubuntu runner:

```yaml
name: Scan Agent Skills

on:
  pull_request:

permissions:
  contents: read

jobs:
  skill-security:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: daffnjk/agent-skill-security-scanner@9a69854cbcbd1dd2d092f2f3ec0409ed50868932 # v0.3.0-dev snapshot
        with:
          path: skills
          mode: collection
          output: .skillscan
          timeout: 5m
          fail_on: malicious
```

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `skills` | Workspace-relative Skill or collection directory |
| `mode` | `auto` | `auto`, `single`, or `collection` |
| `output` | `.skillscan` | Workspace-relative report directory, disjoint from input |
| `timeout` | `5m` | Discovery and scan deadline, in Go duration format |
| `fail_on` | `malicious` | `malicious` blocks malicious verdicts; `suspicious` blocks both suspicious and malicious verdicts; `never` disables risk blocking only |

Scanner errors, incomplete coverage, and invalid reports always block. The Action does not execute target Skills. Scan complete Skill directories in PRs to preserve cross-file evidence. Step outputs include `malicious`, `suspicious`, and `benign` counts plus the `results` path, with a job summary. See the [CI integration contract](docs/v41-integration.md).

## Public evaluation

Selected historical results from frozen v commit `6dae4d982223e4bb6528f300f607d163a00b21d5`. Strict-binary metrics count only `malicious` as positive; these do not measure the current `v` development engine:

| Dataset | Samples | Strict precision | Strict recall | Strict F2 |
| --- | ---: | ---: | ---: | ---: |
| Agent Skill Malware | 347 | 90.98% | 97.58% | 96.18% |
| SkillTrustBench | 5,520 | 77.64% | 94.59% | 90.63% |
| SkillsBench 1,650 | 1,650 | 38.57% | 93.33% | 72.69% |

These are selected results: the full evaluation also reports **6.22%** strict recall on SkillGuard v2 and **47.47%** false-positive rate on SkillTrustBench. Of the 5,520 SkillTrustBench inputs, 1,014 non-binary labels were excluded from binary metrics. Seven of the 56,004 total inputs had incomplete scans and must not be treated as complete passes.

Datasets may overlap and are not combined into a global score. See [v generalized evaluation benchmark](benchmarks/v41/README.md) for TP/FP/TN/FN counts, false-positive rates, accuracy, completeness, and materialization notes. The historical competition snapshot remains under the [competition evaluation benchmark](benchmarks/v38/README.md).

The project originated in Track B of the inaugural 2026 Volcengine AI Security Challenge. The final submission is frozen on the [competition snapshot branch](https://github.com/daffnjk/agent-skill-security-scanner/tree/competition/v38-final) with a score of **7.27 / 10**. The current `main` branch is a post-competition development line and has not been re-evaluated in the same environment. See the [competition notes](docs/competition.md).

## Limitations

- Static rules and bounded behavior relations can produce false positives and false negatives; this is not a complete cross-language semantic or taint analyzer.
- URLs are never fetched. Ordinary references are not automatically malicious; detected unreviewed external instruction delegation makes coverage incomplete.
- Large-file sampling, analysis truncation, symlinks, and opaque executables affect completeness; unsupported ordinary formats and excluded directories remain outside coverage.
- Encrypted, generated, deeply obfuscated, binary, or unsupported content may not be fully interpreted.
- `benign` means the scan found insufficient risk evidence; it is not a security guarantee.
- This tool is not a runtime sandbox and should not be the sole basis for executing an untrusted Skill.

## Development and docs

```bash
make verify
```

- [Security boundaries and migration](docs/hardening.md)
- [Design and rule evolution](docs/design.md)
- [CI integration and report validation](docs/v41-integration.md)
- [Complete evaluation data](benchmarks/README.md)
- [Performance and resource limits](PERFORMANCE.md)
- [Contribution guide](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

## License

The public version of this project is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0-only)](LICENSE), including for personal and educational use. It may also be used in commercial or proprietary environments when the AGPL-3.0 terms are followed.

**Commercial use**: If you wish to use this project in a commercial or proprietary environment without the open-source obligations of AGPL-3.0, **please contact me to obtain a separate commercial license.**

**Contributions**: By submitting a pull request, you agree that your contributions may be used under both GNU AGPLv3 and the project's commercial license.
