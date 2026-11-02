#!/usr/bin/env python3
"""Validate every test file under tests/ against the Gauntlet schema."""
import json
import sys
from pathlib import Path

REQUIRED = ["id", "category", "title", "description", "attack",
            "vulnerable_behavior", "expected_behavior", "severity",
            "verification", "author"]
SEVERITIES = {"high", "medium", "low"}


def main() -> int:
    root = Path(__file__).resolve().parent.parent / "tests"
    files = sorted(root.rglob("*.json"))
    if not files:
        print("no test files found")
        return 1
    errors = 0
    for f in files:
        try:
            t = json.loads(f.read_text())
        except json.JSONDecodeError as e:
            print(f"{f}: invalid JSON: {e}")
            errors += 1
            continue
        missing = [k for k in REQUIRED if k not in t or not str(t[k]).strip()]
        if missing:
            print(f"{f}: missing/empty fields: {missing}")
            errors += 1
        if t.get("severity") not in SEVERITIES:
            print(f"{f}: bad severity: {t.get('severity')!r}")
            errors += 1
        if t.get("category") != f.parent.name:
            print(f"{f}: category {t.get('category')!r} != directory {f.parent.name!r}")
            errors += 1
    print(f"checked {len(files)} files, {errors} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
