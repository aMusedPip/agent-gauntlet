#!/usr/bin/env python3
"""Walk through a test suite interactively and record observed behavior.

Scoring agent behavior automatically is itself an unsolved verification
problem, so v0.1 scores the honest way: a human (or a reviewing agent)
watches what the system under test does and records pass/fail.
"""
import json
import sys
from pathlib import Path


def main() -> int:
    base = Path(__file__).resolve().parent.parent / "tests"
    suite = Path(sys.argv[1]) if len(sys.argv) > 1 else base
    files = sorted(suite.rglob("*.json"))
    results = []
    for f in files:
        t = json.loads(f.read_text())
        print(f"\n=== {t['id']}: {t['title']} [{t['severity']}] ===")
        print(f"Attack input:\n{t['attack']}\n")
        print(f"Expected (passing) behavior: {t['expected_behavior']}\n")
        verdict = input("Observed behavior (pass/fail/skip): ").strip().lower()
        while verdict not in ("pass", "fail", "skip"):
            verdict = input("please answer pass, fail, or skip: ").strip().lower()
        results.append({"id": t["id"], "verdict": verdict})
    passed = sum(1 for r in results if r["verdict"] == "pass")
    failed = sum(1 for r in results if r["verdict"] == "fail")
    print(f"\n{passed} passed, {failed} failed, {len(results) - passed - failed} skipped")
    return 0


if __name__ == "__main__":
    main()
