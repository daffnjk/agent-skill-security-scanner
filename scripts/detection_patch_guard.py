#!/usr/bin/env python3
"""Validate an agent patch without trusting code, tests or policy in that patch."""
from __future__ import annotations
import argparse
from pathlib import Path
import re
import subprocess


def validate_patch(data: bytes) -> list[str]:
    if not data or len(data) > 60_000:
        raise ValueError("empty patch or patch exceeds 60 KB")
    text = data.decode("utf-8")
    if "\x00" in text or any(x in text for x in ("GIT binary patch", "Binary files ", "rename from ", "copy from ")):
        raise ValueError("only ordinary text modifications are allowed")
    files = []
    changed_lines = 0
    for line in text.splitlines():
        if line.startswith("diff --git "):
            match = re.fullmatch(r"diff --git a/(cmd/detector/[A-Za-z0-9_]+\.go) b/\1", line)
            if not match:
                raise ValueError("only cmd/detector/*.go may change")
            files.append(match[1])
        elif line.startswith(("new file mode ", "old mode ", "new mode ", "deleted file mode ")):
            if line != "new file mode 100644":
                raise ValueError("deletions and executable/symlink/mode changes are forbidden")
        elif line.startswith(("--- ", "+++ ")):
            path = line[4:]
            expected = ("a/" if line.startswith("---") else "b/") + (files[-1] if files else "")
            if path != expected and not (line == "--- /dev/null"):
                raise ValueError("patch header identity mismatch")
        elif line.startswith("index "):
            mode = line.split()[-1]
            if mode.isdigit() and mode != "100644":
                raise ValueError("non-regular file")
        elif line.startswith(("+", "-")):
            changed_lines += 1
    if not 1 <= len(files) <= 5 or len(set(files)) != len(files) or changed_lines > 300:
        raise ValueError("patch exceeds one bounded hypothesis (5 files / 300 changed lines)")
    if not any(p.endswith("_test.go") for p in files):
        raise ValueError("paired regression tests must accompany every proposal")
    if not any(not p.endswith("_test.go") for p in files):
        raise ValueError("proposal needs a detector change, not only tests")
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("patch", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    expected = validate_patch(args.patch.read_bytes())
    # Git validates hunks; the allowlist is independently checked before and after.
    subprocess.run(["git", "apply", "--check", str(args.patch.resolve())], check=True)
    if args.apply:
        subprocess.run(["git", "apply", "--index", str(args.patch.resolve())], check=True)
        actual = subprocess.check_output(["git", "diff", "--cached", "--name-only", "-z"]).decode().split("\0")
        if set(filter(None, actual)) != set(expected):
            raise SystemExit("staged file set differs from validated patch")
        for name in expected:
            path = Path(name)
            if not path.is_file() or path.is_symlink():
                raise SystemExit("candidate contains a non-regular file")
    print("Bounded detector-and-tests patch validated.")


if __name__ == "__main__":
    main()
