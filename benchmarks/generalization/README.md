# Frozen generalization experiment

**Status: EXTERNAL ACCEPTANCE FAILED — DRAFT ONLY, DO NOT MERGE DETECTOR CHANGES.**

Read [REPORT.md](REPORT.md) for measured results, rejected variants and limitations. Normal CI tests engineering contracts, not statistical acceptance. The final external experiment added two false negatives; a small reduction in false positives does not override that failure.

## Recorded artifacts

- PROTOCOL.md: original development/holdout registration.
- CANDIDATE_FREEZE.json: first rejected detector, frozen before opening original holdouts.
- ABLATION_PROTOCOL.md and ablation-results.json: preregistered alternatives and every measured selection outcome. Original holdouts became selection/regression data after opening.
- FINAL_FREEZE.json: final minimal candidate frozen before new external scoring. The commit label in measured binaries is `context-safe-frozen`; source hashes bind it to the published Go files.
- EXTERNAL_FREEZE.json: fourth-source representative selection, overlap exclusions, manifest and corpus hashes, registered before outcomes.
- final-counts.json: compact machine-readable final confusion counts and gate decisions.

The accompanying audit archive contains complete JSON/CSV metrics, paired decisions without evidence payloads, manifests, source hashes and patches. Raw Skill content, compiled sample binaries and installed dependencies are not distributed with it.

## Safety and sources

Use a disposable research environment. Never install or execute any sample, import sample modules, or follow sample URLs. The preparation scripts only read checksum-verified archives and create inert files. Keep labels and manifests outside scanner input directories. Static scanning does not justify assuming the underlying packages are safe.

Acquire these immutable release archives from `daffnjk/agent-skill-security-datasets`, each under the matching `<name>-2026-08-30` release tag. Each preparation script checks the archive checksum before parsing.

| Name | SHA-256 | License |
|---|---|---|
| agent_skill_malware | d66676ce9afce9d14f9c9c715c238f66b78458cf77bc23e4f1eb75a701c61fd3 | MIT |
| atr_skill_benchmark | 2971c42c9d0f9d30b788cf6f9de679f8c27b4e8ff322fc67cd42de47d16b7d81 | MIT |
| skillbench_1650 | 1b027da5b2f21007b8ac620532c37d598fdf73bcced1f42262efbc78da886462 | CC-BY-4.0 |
| skilltrustbench | a1970087675a6991788c2624eb6101b72445a7c56b3e1720bd2b97f0add6622f | CC-BY-NC-SA-4.0 |

Upstream sources: yoonholee/agent-skill-malware; Agent-Threat-Rule/atr-skill-benchmark; zenith6888/SkillsBench-1650 (Xinze Chen and upstream skill authors); cuhk-zhuque/SkillTrustBench and upstream contributors. Upstream dataset cards and terms remain authoritative. SkillTrustBench is non-commercial/share-alike research material. The snapshots are not production-prevalence samples.

## Reproduce

Commands are run from this repository, with all four archives named `<name>-2026-08-30.tar.gz` in `../frozen-assets/`. Use a fresh `../repro/`; scripts reject output directory reuse. Local measurements used Go 1.23.2 and Python 3.13.5; repository CI also tested Go 1.27.1. Install preparation dependencies only from the trusted pinned requirements, never from sample files.

```bash
set -euo pipefail
BASE=9a69854cbcbd1dd2d092f2f3ec0409ed50868932
WORK="$(pwd)/../repro"
mkdir "$WORK"
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install -r benchmarks/generalization/requirements.txt
PY="$WORK/venv/bin/python"

# Build only trusted scanner sources, not dataset content.
git worktree add --detach "$WORK/baseline-src" "$BASE"
(cd "$WORK/baseline-src" && go build -trimpath -o "$WORK/baseline" ./cmd/detector)
go build -trimpath -o "$WORK/candidate" ./cmd/detector
SKILLSCAN_BIN="$WORK/candidate" PYTHONPATH=scripts python3 -m unittest discover -v -s scripts -p 'test_*.py'

"$PY" scripts/prepare_generalization.py \
  --assets ../frozen-assets --output "$WORK/core"
"$PY" scripts/prepare_external_generalization.py \
  --archive ../frozen-assets/skilltrustbench-2026-08-30.tar.gz \
  --selection-manifest "$WORK/core/manifest.json" \
  --selection-corpus "$WORK/core/corpus" --output "$WORK/external" --cap 300

for cohort in core external; do
  for version in baseline candidate; do
    "$PY" scripts/evaluate_generalization.py scan \
      --binary "$WORK/$version" --corpus "$WORK/$cohort/corpus" \
      --output "$WORK/$cohort-$version" --timeout 600
  done
done

# Expected PASS on selection/regression data; not blind validation.
"$PY" scripts/evaluate_generalization.py compare \
  --manifest "$WORK/core/manifest.json" \
  --baseline "$WORK/core-baseline" --candidate "$WORK/core-candidate" \
  --output "$WORK/core-report" --bootstrap 2000 --require-nonregression

# Expected FAILURE for the frozen candidate. Reports are written before rejection.
# Do not add `|| true`, remove the guardrail, relabel cases, or call this a clean pass.
"$PY" scripts/evaluate_generalization.py compare \
  --manifest "$WORK/external/manifest.json" \
  --baseline "$WORK/external-baseline" --candidate "$WORK/external-candidate" \
  --output "$WORK/external-report" --bootstrap 2000 --require-nonregression
```

Direct scanner exit code 3 means incomplete coverage. The scan wrapper records it and retains every row; it does not certify completeness. Other abnormal exits/timeouts or report integrity failures prevent metrics from being accepted. Strict positive is `malicious`; screening positive is `malicious|suspicious`. Undefined metrics are null. Both modes must preserve TP, FP and completeness per source to pass `--require-nonregression`.

Source changes after the registered external outcome require another experiment. The existing external dataset is now known and may serve as a regression set, not a fresh blind test. Do not infer statistically significant gains from this balanced 600-package subset or from the selected public regression sets.
