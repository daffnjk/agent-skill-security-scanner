# Contributing

Thanks for helping improve Agent Skill Security Scanner.

## Before opening a change

- Use an issue to describe significant rule or behavior changes.
- Keep new detections evidence-based and prefer compound behavior chains over single-keyword matches.
- Include both a malicious fixture and a nearby benign control when changing detection logic.
- Never include live credentials, working malware, or domains you do not control.

## Local checks

Requires Go 1.23 or newer.

```bash
go fmt ./...
go test ./...
bash scripts/selftest.sh
```

Pull requests should explain the risk being detected, expected category and verdict, false-positive controls, and any performance impact.

## Contribution licensing

By submitting a pull request, you agree that your contributions may be used under both GNU AGPLv3 and the project's commercial license.
