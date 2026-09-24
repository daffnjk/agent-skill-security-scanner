# Performance and resource limits

`skillscan` uses the Go standard library, with no model weights or external API
calls during scanning. This page describes `v0.3.0-dev` / `v`.

## Current limits

| Scope | Limit |
| --- | --- |
| Retained text per file | 1 MiB, sampled from head and tail when larger |
| Retained text / blobs per Skill profile | 24 MiB / 4,096 blobs; base and explain profiles have separate budgets |
| Visited entries / depth per Skill | 100,000 / 64 |
| Skills / discovery entries per collection | 4,096 / 100,000 |
| Aggregate visited entries per collection | 1,000,000 |
| Behavior analysis per file | 12,000 statements; 32,768 bytes per statement |
| External URL inventory | 256 records per document; 1,024 per Skill |
| Each report | 32 MiB |
| Discovery and scan deadline | `5m` by default; configurable with `--timeout` |

These bound retained data and work; they are not a whole-process RSS or CPU
quota. The deadline starts after output preparation. Use deployment-level
resource limits and job/container deadlines for those additional bounds.

## Completeness semantics

Security-sensitive manifests, lifecycle files, CI/project configuration, and
source code receive priority over ordinary documents. Sampling, budget-driven
truncation, supported-file read failures, symlinks, opaque executables/archives,
and unreviewed external instruction delegation make coverage incomplete.
An incomplete scan cannot retain a benign verdict and normally exits with `3`;
discovery, deadline, and report-writing failures exit with `2`.

Excluded dependency/cache directories and unsupported ordinary formats remain
outside coverage. Binary perimeter inspection does not analyze binary behavior,
and archives are not unpacked. Review coverage and validate all reports with
`scan-complete.json` before applying a gate. See [hardening.md](docs/hardening.md)
for detailed limits and trust assumptions.

## Historical benchmark

The original competition benchmark scanned a focused synthetic corpus of 4,000 Skills
in approximately 3.8 seconds with about 21.5 MiB maximum RSS. These are historical,
hardware-specific measurements, not current-engine performance guarantees.
Record the scanner commit, toolchain, hardware, dataset, coverage, elapsed time,
and peak RSS when measuring deployment performance.

Build a stripped Linux binary with:

```bash
make release
```
