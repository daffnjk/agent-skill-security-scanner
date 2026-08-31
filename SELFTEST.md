# Self-test

The fixtures contain inert malicious-looking strings. The scanner reads them as text; it does not execute their commands or contact their example domains.

Run:

```bash
bash scripts/selftest.sh
```

Bundled regression data:

- `benign-notes` -> `benign`
- `chain-supply-update` -> `malicious / ast02`
- `gray-permissions` -> `suspicious / ast03`
- `unsafe-loader` -> `malicious / ast05`

The self-test also generates edge cases at runtime:

- explicit false manifest permissions -> `benign / benign`
- ordinary `project_root` / `admin_mode:false` / `privileged:false` metadata -> `benign / benign`
- `network:true` with `write:false` and a specific API allowlist -> `benign / benign`
- enabled root/privileged shell manifest -> `malicious / ast06`
- browser `<all_urls>` + cookie permission without outbound bridge -> `suspicious / ast03`
- browser cookie/storage outbound bridge -> `malicious / ast01`
- oversized padded file with malicious tail -> `malicious / ast01`
- UTF-16LE PowerShell-like material -> `malicious / ast01`
- hidden prompt smuggling in HTML -> `malicious / ast04`
- metadata says low-risk / no-network while code exfiltrates secrets -> `malicious / ast01` with AST04 secondary evidence
- remote WebSocket command channel -> `malicious / ast01`
- direct unsafe YAML object/apply payload -> `malicious / ast05`
- MCP tool-description prompt injection -> `malicious / ast04`
- mutable installer / dependency-confusion path -> `malicious / ast02`
- localhost agent-control WebSocket/JSON-RPC hijack -> `malicious / ast06`
- benign security-training document mentioning credential theft patterns -> `benign / benign`

- exact typosquat dependency metadata -> `malicious / ast02`
- CI/workflow remote installer execution -> `malicious / ast02`
- opaque local binary execution lure -> `malicious / ast01`
- startup persistence payload -> `malicious / ast01`
- cross-platform metadata loss -> `malicious / ast10`
- Cursor `.mdc` hidden prompt with source-code exfiltration -> `malicious / ast04`
- Dockerfile remote mutable entrypoint without integrity pinning -> `malicious / ast02`
- Rust environment-secret exfiltration via non-Python/JS HTTP client -> `malicious / ast01`
- trusted-brand impersonation metadata with sensitive permissions -> `malicious / ast04`
- benign unofficial Google helper with explicit non-affiliation and scoped permissions -> `benign / benign`

All checks require valid ranking-mode JSONL rows with exactly `skill_id`, `verdict`, `engine_category`, and `evidence_text`.
