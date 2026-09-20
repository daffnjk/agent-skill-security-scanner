# Contributing

Thanks for helping improve Agent Skill Security Scanner.

## Before opening a change

- Use an issue to describe significant rule or behavior changes.
- Keep new detections evidence-based and prefer compound behavior chains over single-keyword matches.
- Include both a malicious fixture and a nearby benign control when changing detection logic.
- Never include live credentials, working malware, or domains you do not control.

## Local checks

Requires Go and Python 3. The source language floor is Go 1.23; CI currently
pins Go 1.27.1. For routine changes, run:

```bash
make verify
```

For report, gate, or boundary changes, also run the complete Python suite with
the real CLI, as CI does:

```bash
make build
SKILLSCAN_BIN="$PWD/skillscan" PYTHONPATH=scripts python3 -m unittest discover -v -s scripts -p 'test_*.py'
```

Keep Chinese and English READMEs aligned. Distinguish release versions from
engine versions, preserve historical benchmark provenance, and document any
changes to input modes, completeness, report schemas, or Action inputs. Retain
existing `SKILL-Rnnnn` rule IDs when editing evidence wording. See
[the migration contract](docs/hardening.md) for identity and taxonomy rules.

Pull requests should explain the risk being detected, expected category and verdict, false-positive controls, and any performance impact.

## Contribution licensing

By submitting a pull request, you agree that your contributions may be used under both GNU AGPLv3 and the project's commercial license.
