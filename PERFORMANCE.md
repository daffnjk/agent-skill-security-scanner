# Performance and resource limits

`skillscan` is a single Go binary with no third-party module dependencies, external API calls, or model weights.

The scanner applies these bounds per skill directory:

- At most 1 MiB sampled per text-like file, using head and tail content.
- At most 24 MiB of retained text across the skill tree.
- At most 4,096 retained file blobs.
- Binary files, archives, dependency directories, and common caches are skipped.

The original v38 benchmark scanned a focused synthetic corpus of 4,000 skills in approximately 3.8 seconds with about 21.5 MiB maximum RSS. That number is historical and hardware-specific; run a local benchmark for deployment decisions.

Build a stripped Linux binary with:

```bash
make release
```


## Completeness semantics

Security-sensitive metadata, package lifecycle files, CI/project configuration, and source code are prioritized before ordinary documentation consumes the bounded per-Skill budget. Reaching a byte/file budget, failing to read a supported file, or skipping a symlink or opaque executable/archive is recorded in `scan-metadata.jsonl`; strict mode exits with status 3 rather than treating the scan as a successful benign result. Oversized text files that are successfully head/tail sampled are counted in metadata but do not alone make the scan incomplete.
