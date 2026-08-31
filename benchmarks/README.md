# Benchmark baselines

This directory stores immutable, versioned metric snapshots for comparing detector releases.

Each `benchmarks/<version>/` directory contains:

- `metrics.csv`: one normalized row per dataset evaluation unit;
- `manifest.json`: detector, dataset, runner, and artifact provenance;
- `source_revisions.tsv`: pinned upstream dataset revisions;
- `README.md`: scope, metric definitions, and limitations.

Rows are compared by the composite key `(suite, dataset_id)`. Do not aggregate efficacy across datasets: several benchmark families reuse or overlap samples. Runtime is informational and should only be compared on equivalent hardware and input materializations.

## Metric conventions

- **Strict:** only `verdict=malicious` is positive.
- **Screening:** `verdict=malicious` or `verdict=suspicious` is positive.
- Empty metrics mean the dataset was not scannable from the available artifact.
- `precision_applicable=false` means the unit has no benign negative samples, so mathematical precision does not measure false-positive behavior.

For a new detector release, copy the same schema into a new version directory, retain the pinned dataset revisions where possible, and document every corpus or materialization change in its manifest.
