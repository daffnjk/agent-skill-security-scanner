<div align="center">

# Agent Skill Security Scanner

### See what an Agent Skill does before you run it

`skillscan` is a fast, offline, and explainable static security scanner for Agent Skills, MCP tools, IDE rules, and plugin packages. v41 adds bounded Source → Transform → Sink relationship verification, with cross-dataset regression checks and benign counterexamples as anti-overfitting constraints.

[![CI](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Offline](https://img.shields.io/badge/runtime-offline-1f883d)](Dockerfile)
[![License](https://img.shields.io/badge/license-AGPL--3.0-663399)](LICENSE)

[中文](README.md)

</div>

## What is `skillscan`?

An Agent Skill can contain more than prompts: scripts, permission manifests, install hooks, CI workflows, and auto-run configuration may all be part of the package. Meaningful risk often spans several files.

`skillscan` treats every package as **untrusted data**. It does not install, import, or execute package code, and it does not contact URLs declared by the package. Instead, it correlates permissions, command execution, sensitive-data access, and network behavior into reviewable findings.

> [!NOTE]
> This is a heuristic static-analysis tool. Findings are security-review leads, not final proof that a package is safe or malicious.

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
```

## What it detects

- Credential, browser, wallet, cloud-token, and workspace-data exfiltration
- Install hooks, dependency confusion, CI download-and-execute, and project auto-run risks
- Broad filesystem, network, shell, host, and container permissions
- Hidden prompts, tool-description injection, brand impersonation, and metadata/runtime contradictions
- Unsafe deserialization, encoded payloads, dynamic loading, and scan evasion
- Remote update drift, isolation-boundary risks, and lost security metadata during platform reuse

Non-benign findings map to the project's `AST01`–`AST10` risk categories. See the [design notes](docs/design.md) for full coverage.

## Quick start

Requires Go 1.23 or later:

```bash
git clone https://github.com/daffnjk/agent-skill-security-scanner.git
cd agent-skill-security-scanner
make build

./skillscan ./testdata/skills ./out
cat ./out/results.jsonl
```

For your own packages, place one Skill in each top-level input directory:

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
./skillscan ./skills ./out
```

`SKILLS_DIR` and `OUTPUT_DIR` are also supported. Positional arguments take precedence.

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

`scan-metadata.jsonl` records read errors, resource truncation, sampled files, symbolic links, and opaque payloads. An incomplete scan cannot remain a trustworthy `benign` result.

`analysis-metadata.jsonl` contains v41 trigger layers, scores, decision conditions, rule IDs, and secondary explanations. It is separate from the stable four-field `results.jsonl`, so existing integrations do not need a schema migration.

Exit status is `0` for a complete scan, `2` for startup/input/output errors, and `3` when at least one Skill was not scanned completely. A `suspicious` or `malicious` finding alone does not change the exit status.

## Docker

```bash
docker build -t skillscan:local .
mkdir -p out

docker run --rm \
  -v "$PWD/skills:/data/skills:ro" \
  -v "$PWD/out:/output" \
  skillscan:local
```

The runtime image uses a non-root user, and scanning requires no network access.

## GitHub Actions gate

After the v41 tag is published, repositories that store Skills can use the bundled composite Action:

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
- uses: daffnjk/agent-skill-security-scanner@v0.2.0
  with:
    path: skills
    output: .skillscan
    fail_on: malicious
```

`fail_on` accepts `malicious`, `suspicious`, or `never`. Startup failures and incomplete scans always fail closed. The Action builds trusted scanner source and statically reads complete Skill directories; it never executes target Skill code.

## Public evaluation

Selected strict-binary results from v41 on frozen public datasets:

| Dataset | Samples | Strict precision | Strict recall | Strict F2 |
| --- | ---: | ---: | ---: | ---: |
| Agent Skill Malware | 347 | 90.98% | 97.58% | 96.18% |
| SkillTrustBench | 5,520 | 77.64% | 94.59% | 90.63% |
| SkillsBench 1,650 | 1,650 | 38.57% | 93.33% | 72.69% |

Datasets may overlap and are not combined into a global score. See [`benchmarks/v41`](benchmarks/v41/README.md) for TP/FP/TN/FN counts, false-positive rates, accuracy, completeness, and materialization notes. The historical v38 snapshot remains under [`benchmarks/v38`](benchmarks/v38/README.md).

The project originated in Track B of the inaugural 2026 Volcengine AI Security Challenge. The final submission is frozen at [`competition/v38-final`](https://github.com/daffnjk/agent-skill-security-scanner/tree/competition/v38-final) with a score of **7.27 / 10**. The current `main` branch is a post-competition development line and has not been re-evaluated in the same environment. See the [competition notes](docs/competition.md).

## Limitations

- Static rules and behavior-chain analysis can produce false positives and false negatives.
- Encrypted, generated, deeply obfuscated, binary, or unsupported content may not be fully interpreted.
- `benign` means the scan found insufficient risk evidence; it is not a security guarantee.
- This tool is not a runtime sandbox and should not be the sole basis for executing an untrusted Skill.

## Development and docs

```bash
make verify
```

- [Design and rule evolution](docs/design.md)
- [v41 GitHub integration design](docs/v41-integration.md)
- [Complete evaluation data](benchmarks/README.md)
- [Performance and resource limits](PERFORMANCE.md)
- [Contribution guide](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

## License

The public version of this project is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0-only)](LICENSE), including for personal and educational use. It may also be used in commercial or proprietary environments when the AGPL-3.0 terms are followed.

**Commercial use**: If you wish to use this project in a commercial or proprietary environment without the open-source obligations of AGPL-3.0, **please contact me to obtain a separate commercial license.**

**Contributions**: By submitting a pull request, you agree that your contributions may be used under both GNU AGPLv3 and the project's commercial license.
