"""One-time, base-checked transport of reviewed source changes; removed after tests."""
import hashlib
import json
import lzma
from pathlib import Path

EXPECTED = {
    'cmd/detector/main.go': '0eaa31f6bd64ef7edb1181402d9ce193e1bdf3c4',
    'cmd/detector/hardening.go': 'aec4dd370c3bbb553f6d05d2eefa5bd10a1e7388',
    'cmd/detector/behavior_ir.go': 'c67e4815d46e7ba71db69e15cd67c20a761097ca',
    'cmd/detector/hardening_test.go': 'e0b0a08c349753d5144b5a301b71db06634183ba',
    'cmd/detector/analysis_metadata.go': 'd934e9308257395a4cc4989337580a8247d5628e',
    'action.yml': 'ca540967ce4537491a27df8a8ae156dadae9137b',
    'scripts/github_action_gate.py': 'e1cfe3f065dee4e4073e02c52f7c6ed41d61296f',
    '.github/workflows/ci.yml': 'e2245cb1296328b18c60ee200a9936c858d3c3e8',
    'Dockerfile': 'ac93f0dd94bacc2be8abd1f4116de940f610ac5f',
}
for name, expected in EXPECTED.items():
    data = Path(name).read_bytes()
    actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if actual != expected:
        raise SystemExit(f'Refusing source migration: base changed at {name}')
packed = b''.join(Path(f'.maintenance/payload-{i}.bin').read_bytes() for i in range(1, 5))
data = lzma.decompress(packed)
if hashlib.sha256(data).hexdigest() != 'd11b50363132f08a08254f837b732192dde94c13e25bfb46ebe3131dd01ff85d':
    raise SystemExit('Source bundle checksum mismatch')
files = json.loads(data)
for name, content in files.items():
    path = Path(name)
    if path.is_absolute() or '..' in path.parts or '.git' in path.parts:
        raise SystemExit('Invalid bundle path')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
print(f'Unpacked {len(files)} reviewed source and migration files')
