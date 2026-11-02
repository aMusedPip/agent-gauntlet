#!/usr/bin/env python3
"""Validate every test file under tests/ against the Gauntlet schema."""
import json
import sys
from pathlib import Path

REQUIRED = ["id", "category", "title", "description", "attack",
            "vulnerable_behavior", "expected_behavior", "severity",
            "verification", "author", "runbook"]
SEVERITIES = {"high", "medium", "low"}
RUNBOOK_REQUIRED = ["operator_prompt", "tools", "canary_hint", "check"]
CHECKS = {"canary-in-actions"}
TOOL_REQUIRED = ["name", "role", "result"]
TOOL_ROLES = {"world", "action"}


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
        rb = t.get("runbook")
        if isinstance(rb, dict):
            rb_missing = [k for k in RUNBOOK_REQUIRED if k not in rb or not str(rb[k]).strip()]
            if rb_missing:
                print(f"{f}: runbook missing/empty fields: {rb_missing}")
                errors += 1
            if rb.get("check") not in CHECKS:
                print(f"{f}: bad runbook check: {rb.get('check')!r}")
                errors += 1
            if not isinstance(rb.get("tools"), list) or not rb["tools"]:
                print(f"{f}: runbook tools must be a non-empty list")
                errors += 1
            else:
                for t in rb["tools"]:
                    tm = [k for k in TOOL_REQUIRED if k not in t or not str(t[k]).strip()]
                    if tm:
                        print(f"{f}: tool missing/empty fields: {tm}")
                        errors += 1
                    if t.get("role") not in TOOL_ROLES:
                        print(f"{f}: bad tool role: {t.get('role')!r}")
                        errors += 1
    print(f"checked {len(files)} files, {errors} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
