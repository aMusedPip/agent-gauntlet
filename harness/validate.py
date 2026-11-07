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
CHECKS = {"canary-in-actions", "trace-diff"}
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
            action_tools = {t["name"] for t in rb.get("tools", [])
                            if isinstance(t, dict) and t.get("role") == "action"}
            for trace_name in ("expected_trace", "steered_trace"):
                trace = rb.get(trace_name)
                if trace is None:
                    continue
                if not isinstance(trace, list) or not trace:
                    print(f"{f}: runbook {trace_name} must be a non-empty list")
                    errors += 1
                    continue
                for step in trace:
                    if (not isinstance(step, dict) or "tool" not in step
                            or not isinstance(step.get("arguments"), dict)):
                        print(f"{f}: runbook {trace_name} step must be "
                              f"{{'tool', 'arguments': {{...}}}}: {step!r}")
                        errors += 1
                    elif step["tool"] not in action_tools:
                        print(f"{f}: runbook {trace_name} step tool "
                              f"{step['tool']!r} is not an action-role tool")
                        errors += 1
            if rb.get("check") == "trace-diff":
                if not rb.get("expected_trace"):
                    print(f"{f}: trace-diff check requires runbook expected_trace")
                    errors += 1
                if not rb.get("steered_trace"):
                    print(f"{f}: trace-diff check requires runbook steered_trace "
                          "(the scripted wrong-but-legitimate behavior: a "
                          "divergent trace only convicts when it matches it, "
                          "so a test that cannot name the wrong behavior "
                          "cannot distinguish steering from legitimate "
                          "variation)")
                    errors += 1
                if (rb.get("steered_trace") is not None
                        and rb.get("steered_trace") == rb.get("expected_trace")):
                    print(f"{f}: steered_trace must differ from expected_trace")
                    errors += 1
                br = rb.get("baseline_runs")
                if (br is not None
                        and (not isinstance(br, int) or isinstance(br, bool)
                             or br < 1)):
                    print(f"{f}: baseline_runs must be a positive integer")
                    errors += 1
                # The baseline must be genuinely clean: at least one tool
                # has to declare the unpoisoned result, or the "clean"
                # runs would silently measure the agent under poison.
                if not any(isinstance(t, dict) and t.get("clean_result")
                           for t in rb.get("tools", [])):
                    print(f"{f}: trace-diff check requires at least one "
                          "tool with clean_result (the unpoisoned result "
                          "for baseline runs)")
                    errors += 1
            elif rb.get("expected_trace") is not None:
                print(f"{f}: expected_trace only applies to trace-diff checks")
                errors += 1
            if rb.get("check") != "trace-diff" and rb.get("baseline_runs") is not None:
                print(f"{f}: baseline_runs only applies to trace-diff checks")
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
                    if ("clean_result" in t
                            and not str(t["clean_result"]).strip()):
                        print(f"{f}: tool {t.get('name')!r} has an empty "
                              "clean_result")
                        errors += 1
    print(f"checked {len(files)} files, {errors} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
