# Agent Skill Security Scanner

[![CI](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml)

`skillscan` is a fast, offline static scanner for AI agent skills, MCP-style tool packages, IDE rules, and plugin bundles. It looks for high-signal behavior chains such as credential exfiltration, prompt injection, unsafe install hooks, overly broad permissions, unsafe deserialization, sandbox escape paths, and unverified remote updates.

The scanner is written in Go, has no third-party runtime dependencies, makes no network calls, and emits deterministic JSONL results with human-readable evidence.

> [!IMPORTANT]
> This is a heuristic static-analysis tool. Treat findings as review leads, not proof that a package is safe or malicious. Do not execute untrusted packages to validate a result.

## What it detects

- Agent-facing prompt injection and hidden instruction smuggling
- Credential, browser, wallet, cloud-token, and workspace-data exfiltration
- Package lifecycle, CI, project auto-run, and mutable installer risks
- Broad filesystem, network, shell, host, and container permissions
- Unsafe deserialization and encoded-payload execution chains
- Local agent-control, container-boundary, and remote plugin-loading risks
- Security metadata contradictions and cross-platform policy weakening

Findings use `ast01` through `ast10` category identifiers, following the Agentic Skills security taxonomy used by the original v38 detector.

## Quick start

Requirements: Go 1.23 or newer.

```bash
git clone https://github.com/daffnjk/agent-skill-security-scanner.git
cd agent-skill-security-scanner
make build
```

Arrange packages as one directory per skill:

```text
skills/
├── calendar-helper/
│   ├── SKILL.md
│   └── manifest.json
└── code-reviewer/
    ├── package.json
    └── index.js
```

Run the scanner:

```bash
mkdir -p out
./skillscan ./skills ./out
cat ./out/results.jsonl
```

You can also set `SKILLS_DIR` and `OUTPUT_DIR`. Positional arguments take precedence.

## Output

Each input directory produces one JSON object:

```json
{"skill_id":"calendar-helper","verdict":"suspicious","engine_category":"ast03","evidence_text":"OWASP AST03 ..."}
```

| Field | Meaning |
| --- | --- |
| `skill_id` | Input directory name |
| `verdict` | `benign`, `suspicious`, or `malicious` |
| `engine_category` | Primary `ast01`–`ast10` category, or `benign` |
| `evidence_text` | Concise explanation and relevant file context |

Results are written atomically to `results.jsonl` in the output directory.

## Docker

```bash
docker build -t agent-skill-security-scanner .
mkdir -p out
docker run --rm \
  -v "$PWD/skills:/data/skills:ro" \
  -v "$PWD/out:/output" \
  agent-skill-security-scanner
```

The runtime container is offline by design and runs as a non-root user.

## Development

```bash
make test
make selftest
```

The self-test creates inert malicious-looking fixtures under a temporary directory and scans their text. It does not run the fixture commands or contact their example domains.

Implementation details and resource limits are documented in [docs/design.md](docs/design.md), [PERFORMANCE.md](PERFORMANCE.md), and [SELFTEST.md](SELFTEST.md).

## Scope and limitations

- Static string and behavior-chain analysis can produce false positives and false negatives.
- Obfuscated, encrypted, generated, or unsupported binary content may evade inspection.
- The scanner samples large files and caps retained data to keep runtime bounded.
- A `benign` verdict is not a security guarantee or substitute for sandboxing, provenance checks, and human review.

This project is independent and is not affiliated with or endorsed by OWASP or any package/provider brand referenced by its detection rules.
