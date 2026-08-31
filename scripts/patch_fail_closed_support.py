#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_exact(text: str, old: str, new: str, *, expected: int = 1) -> str:
    actual = text.count(old)
    if actual != expected:
        raise RuntimeError(f"expected {expected} occurrences, found {actual}: {old[:100]!r}")
    return text.replace(old, new)


(ROOT / ".github/workflows/ci.yml").write_text(
    '''name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5
        with:
          go-version: "1.23.x"
          cache: false
      - name: Check formatting
        run: test -z "$(gofmt -l .)"
      - name: Vet
        run: go vet ./...
      - name: Unit tests and coverage
        run: |
          go test -covermode=atomic -coverprofile=coverage.out ./...
          go tool cover -func=coverage.out | tail -n 1
      - name: Race tests
        run: go test -race ./...
      - name: Regression self-test
        run: bash scripts/selftest.sh
      - name: Build
        run: go build -trimpath -o skillscan ./cmd/detector
      - name: Container build
        run: docker build -t skillscan:ci .
'''
)

(ROOT / "Dockerfile").write_text(
    '''# Compact, deterministic agent-skill security scanner image.
FROM golang:1.23-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -ldflags="-s -w -buildid=" -o /skillscan ./cmd/detector

FROM busybox:1.36-musl
COPY --from=build /skillscan /skillscan
RUN mkdir -p /output /data/skills && chown -R 1000:0 /output /data
USER 1000
ENTRYPOINT ["/skillscan"]
'''
)

(ROOT / "Makefile").write_text(
    '''.PHONY: build test selftest verify release

GOOS ?= linux
GOARCH ?= amd64

build:
	CGO_ENABLED=0 go build -trimpath -o skillscan ./cmd/detector

test:
	go test ./...

selftest:
	./scripts/selftest.sh

verify:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
	./scripts/selftest.sh

release:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w -buildid=" -o skillscan-$(GOOS)-$(GOARCH) ./cmd/detector
'''
)

selftest_path = ROOT / "scripts/selftest.sh"
selftest = selftest_path.read_text()
selftest = replace_exact(
    selftest,
    '"$TMP/skillscan" "$TMP/edge_skills" "$TMP/edge_output"',
    'SKILLSCAN_ALLOW_PARTIAL=1 "$TMP/skillscan" "$TMP/edge_skills" "$TMP/edge_output"',
)
selftest += r'''

# A missing input root must fail before producing a synthetic benign row.
if "$TMP/skillscan" "$TMP/does-not-exist" "$TMP/missing-output"; then
  echo "expected missing input root to fail" >&2
  exit 1
fi

# Opaque content keeps the four-field result available, but strict mode exits 3
# and records the incomplete scan in the metadata sidecar.
mkdir -p "$TMP/partial_skills/opaque" "$TMP/partial_output"
printf '%s\n' '{"name":"opaque","permissions":{"network":false}}' > "$TMP/partial_skills/opaque/manifest.json"
printf 'PK fake archive\n' > "$TMP/partial_skills/opaque/payload.zip"
set +e
"$TMP/skillscan" "$TMP/partial_skills" "$TMP/partial_output"
partial_rc=$?
set -e
if [[ "$partial_rc" -ne 3 ]]; then
  echo "expected incomplete scan exit 3, got $partial_rc" >&2
  exit 1
fi

python3 - <<'PY'
import json, os, pathlib
base = pathlib.Path(os.environ.get('TMPDIR', '/tmp'))/'agent-skill-security-scanner-selftest'
rows = [json.loads(line) for line in (base/'partial_output'/'results.jsonl').read_text().splitlines() if line.strip()]
meta = [json.loads(line) for line in (base/'partial_output'/'scan-metadata.jsonl').read_text().splitlines() if line.strip()]
assert rows[0]['verdict'] != 'benign', rows
assert meta[0]['complete'] is False, meta
assert meta[0]['skipped_opaque'] == 1, meta
print('fail-closed selftest ok')
PY
'''
selftest_path.write_text(selftest)

readme_path = ROOT / "README.md"
readme = readme_path.read_text()
needle = "结果先写入临时文件，再原子提交为 `results.jsonl`，降低中途失败留下不完整输出的风险。"
readme = replace_exact(
    readme,
    needle,
    needle
    + '''

扫描器同时写入 `scan-metadata.jsonl`，记录每个 Skill 的扫描完整性、读取错误、资源截断、采样文件以及跳过的链接或不透明载荷。默认情况下，只要存在不完整扫描，进程在完整写出两份结果后以退出码 `3` 结束，并且对应 Skill 不会保持 `benign`。兼容只消费 JSONL 的旧评测环境时，可显式设置 `SKILLSCAN_ALLOW_PARTIAL=1`；完整性警告仍会保留在结果和元数据中。''',
)
readme_path.write_text(readme)

readme_en_path = ROOT / "README_EN.md"
readme_en = readme_en_path.read_text()
needle_en = "Results are written to a temporary file and atomically committed as `results.jsonl` to reduce partial-output corruption."
readme_en = replace_exact(
    readme_en,
    needle_en,
    needle_en
    + '''

The scanner also writes `scan-metadata.jsonl` with per-Skill completeness, read errors, resource truncation, sampled files, skipped links, and opaque payloads. By default, any incomplete scan still writes both files and then exits with status `3`; the affected Skill cannot remain `benign`. Legacy ranking harnesses may explicitly set `SKILLSCAN_ALLOW_PARTIAL=1`, while the warning remains present in the result and metadata.''',
)
readme_en_path.write_text(readme_en)

performance_path = ROOT / "PERFORMANCE.md"
performance = performance_path.read_text()
performance += '''

## Completeness semantics

Security-sensitive metadata, package lifecycle files, CI/project configuration, and source code are prioritized before ordinary documentation consumes the bounded per-Skill budget. Reaching a byte/file budget, failing to read a supported file, or skipping a symlink or opaque executable/archive is recorded in `scan-metadata.jsonl`; strict mode exits with status 3 rather than treating the scan as a successful benign result. Oversized text files that are successfully head/tail sampled are counted in metadata but do not alone make the scan incomplete.
'''
performance_path.write_text(performance)

changelog_path = ROOT / "CHANGELOG.md"
changelog = changelog_path.read_text()
marker = "## Unreleased\n"
entry = '''
- Fail closed on missing, unreadable, truncated, symlinked, or opaque scan input; incomplete scans can no longer remain benign.
- Add `scan-metadata.jsonl` with per-Skill completeness and resource/error telemetry while preserving the four-field competition result schema.
- Prioritize manifests, lifecycle files, CI/project configuration, and source code before documentation consumes the bounded scan budget.
- Normalize mixed-case rule needles, make plain `SKILL.md` content reachable by document rules, and add Terraform file collection.
- Use deterministic blended-score and secondary-evidence ordering, strengthen JSON capability parsing, and add hardening/fuzz regression seeds.
- Pin CI actions to commit SHAs, add vet/race/coverage/container checks, and make Docker/Makefile builds architecture-aware.
'''
changelog = replace_exact(changelog, marker, marker + entry)
changelog_path.write_text(changelog)
