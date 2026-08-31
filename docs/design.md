# Design notes

Version v35 keeps the v32-v34 targeted recall behavior, then improves Track B output compliance and specificity without adding external dependencies or changing the high-confidence promotion philosophy.

## Rationale

The previous engine already had a strong v25/v31 verdict path and used a broader v26 extractor only to improve AST category explanation on non-benign rows. The main gap was that some high-signal behavior chains located in generated extension code, docs-as-instructions, or less common config formats could remain benign because the broader extractor was never allowed to promote a benign result.

The v32 design keeps the stable verdict path and adds a controlled promotion gate: v26 can promote a benign result only when the promoted category is backed by concrete strong findings and a minimum category score. Weak AST09 governance hints, broad cross-platform reuse hints, and ordinary metadata are not promoted.

## Scoring flow

1. Collect bounded, text-like skill files from `/data/skills/{skill_id}/` with a one-pass dual-profile collector: conservative v25 view plus broader v26 view. Oversized text files are sampled from head and tail, and UTF-16 text is decoded before scanning.
2. Extract per-file findings with AST category, weight, and evidence reason.
3. Add cross-file correlations for manifest/code, package lifecycle, browser extension manifest+script pairs, remote dynamic loading, and localhost/metadata pivots.
4. Apply benign dampening to weak doc/test/demo signals.
5. Select deterministic root-cause AST category.
6. If the stable path returns benign, evaluate the already-collected broader explain-only view and promote only high-confidence AST01/02/05/06/07 chains, with stricter thresholds for AST04/08/10.
7. Emit stable ranking-mode JSONL using exactly `skill_id`, `verdict`, `engine_category`, and `evidence_text`.

## v32/v33 targeted rules

- AST01: ClickFix-style command paste lures, browser-extension credential bridges, wallet/credential exfiltration, reverse shell/backdoor chains.
- AST02: package lifecycle, build/install/update hooks, dependency integrity disablement, MCP / config-file hijack chains.
- AST03: broad permissions, with precise wildcard handling and explicit false-boolean handling so ordinary `network: false` / `filesystem: false` manifests are not over-flagged.
- AST04: invisible instruction smuggling through zero-width/bidi/control text, HTML comments, CSS-hidden text, or encoded prompt payloads.
- AST05: unsafe YAML/pickle-capable loaders plus prototype pollution or config injection chains that can influence execution-sensitive options.
- AST06: cloud metadata, localhost admin, Docker/Kubernetes/Redis/etcd/Vault/Consul/Elasticsearch pivots and existing container boundary checks.
- AST07: hot-reload remote plugin/config/manifest/module loading and update drift.
- AST08: scanner/audit result tampering and stronger evasive encoded payload chains.
- AST09: remains a weak modifier rather than a primary malicious verdict driver.
- AST10: remains useful for reusable credential/session material, but is not used to broadly promote benign rows without strong evidence.

## Compliance

The image is offline and deterministic, has no third-party Go module dependency, writes `/output/results.jsonl`, uses a BusyBox runtime stage, and includes `USER 1000` in the Dockerfile. The detector does not call external services or use model weights.


## v33/v34 robustness/performance hardening

- One filesystem pass creates both file profiles, reducing duplicate I/O without changing detection thresholds.
- Oversized text files are capped at 1 MiB and, in v34, sampled from both head and tail so padded malicious files can expose leading or trailing indicators while memory remains bounded.
- Per-skill total bytes and retained blob count are capped to avoid pathological packages causing timeout or OOM.
- Output is written through a temp file plus rename, with a conservative fallback commit path to preserve a complete JSONL file if overwrite semantics are unusual.
- The final Docker image uses BusyBox instead of Alpine, reducing image footprint while keeping allowed-base compatibility and non-root execution.

## v34 specificity and edge-format hardening

- Explicit disabled capabilities such as `"filesystem": false` are not treated as broad authorization. Enabled/listed all-host, shell, exec, admin, root, host, or broad filesystem capabilities remain AST03 signals.
- UTF-16LE/UTF-16BE text-like files are decoded before scanning, improving coverage for PowerShell-oriented material that otherwise resembles binary data.
- HTML/HTM/XML/SVG/MDX and selected dot/config files are considered skill-facing text where appropriate, improving AST04 hidden instruction smuggling coverage.
- Cross-file encoded-payload correlation no longer constructs a joined global string; it uses bounded boolean aggregation to preserve behavior with lower allocation overhead.


## v35 schema and specificity hardening

- The result schema now uses only the ranking evidence-strategy fields: `skill_id`, `verdict`, `engine_category`, and `evidence_text`. This reduces JSONL size and avoids carrying legacy compatibility fields in ranking output.
- Manifest privilege parsing distinguishes explicit enabled dangerous privileges from benign key names or false booleans. `project_root`, `admin_mode:false`, `privileged:false`, and `network:true` with `write:false` are no longer promoted to AST03/AST06 by keyword alone.
- Metadata-only browser extension cookie/all-URL declarations are treated as over-privileged AST03 suspicious findings rather than malicious AST10. If a script reads cookies/storage and sends them outbound, the AST01 malicious browser-credential bridge rule still fires.

## v36 F2 recall hardening

v36 is intentionally recall-oriented because Track B uses F2. The patch does not lower global malicious thresholds; instead it adds OWASP AST10-derived high-confidence chains that v35 could miss or misclassify:

- AST04 metadata/runtime mismatch: safe, low-risk, `network:false`, `shell:false`, or clean-scan metadata is correlated with executable outbound, credential, command, decoded, or destructive behavior.
- AST01 agent-facing credential exfiltration instructions: skill prose instructs the assistant/agent to read `.env`, SSH keys, cookies, wallet/browser data, or cloud/package-manager credentials and send/report them externally.
- AST01 WebSocket C2: persistent remote WebSocket/control channels receive commands or send process/environment/credential data.
- AST06 local agent-control hijack: localhost agent/MCP/debug/devtools WebSocket or JSON-RPC endpoints are used for unauthenticated tool or command invocation.
- AST05 unsafe serialized payloads: direct YAML `!!python/object/apply` / Python pickle-style / node-serialize-style gadgets near command or network payloads are detected even when the vulnerable loader is not present in the same file.
- AST04 MCP/tool-description prompt injection: tool descriptions and schemas that carry hidden policy overrides tied to credential access or command execution are categorized as insecure metadata.
- AST02 dependency confusion / mutable installer paths: alternate registries, package runners, `@latest`/mutable refs, and install-time command execution are treated as supply-chain compromise signals.

The patch also narrows a doc-only false-positive class by requiring generic cross-file AST01/AST10 credential signals to come from active material rather than benign security-training or demo prose.


## v37 F2 edge-recall hardening

v37 continues the v36 philosophy: do not lower global thresholds; add only high-signal, AST-specific chains that are likely to appear in hidden malicious skill packages. The added rules target gaps found by reviewing the OWASP Agentic Skills Top 10 material and by testing v36 on focused edge samples.

- AST02 exact typosquat/dependency-confusion metadata: known misspelled skill dependencies and self-described dependency-confusion markers are malicious supply-chain signals. Alternate private indexes without lock/provenance are only suspicious unless paired with stronger install-exec evidence.
- AST02 CI/workflow execution: GitHub/GitLab/CircleCI/Buildkite/Jenkins-style config that downloads and executes remote script content is treated as an active supply-chain/config execution path.
- AST01 opaque binary-helper lures: skill-facing instructions requiring users or agents to run bundled opaque binaries or installer helpers are treated as malicious when the wording forms an execution prerequisite.
- AST01 startup persistence configs: plist, systemd, cron, desktop, timer, and related startup material that launches network/shell/download behavior is detected even when the file is configuration rather than ordinary source code.
- AST10 cross-platform metadata loss: source/target manifest pairs that show platform porting together with dropped security metadata and broad target permissions are classified as cross-platform reuse risk.

These additions intentionally rely on compound conditions rather than single keywords to avoid regressing the v35/v36 specificity improvements.

## v38 F2 + explainability hardening

v38 keeps the v37 recall posture and adds only high-confidence, category-specific rules where v37 either missed a malicious chain or produced a less precise OWASP AST category.

New coverage includes:

- AST04 trusted-brand impersonation metadata when a skill claims an official/verified provider while carrying unverified/typosquat publisher signals and sensitive permissions.
- AST04 MCP/tool/Cursor-style prompt injection that tells an agent to read workspace/source-code files and upload them externally.
- AST02 project auto-run config hijacking through devcontainer, direnv, VS Code tasks, Husky/pre-commit, and related repository-open/build/commit hooks.
- AST02 Docker/build recipes that fetch mutable remote entrypoints without integrity checks.
- AST08 escaped payload evasion based on hex/unicode/url-encoded string reconstruction paired with eval/exec, remote loading, or credential exfiltration.
- AST01 language coverage for Rust/non-Python secret exfiltration sinks, plus skill-facing `.mdc`, `.prompt`, and `.prompty` text handling.

Evidence text now includes an explicit `OWASP ASTxx` prefix for non-benign findings. This does not change the ranking JSONL schema, but makes the natural-language evidence easier to map back to the reported `engine_category`.
