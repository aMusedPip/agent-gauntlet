#!/usr/bin/env python3
"""Agent Gauntlet MCP server: serve one test's tools to an agent under test.

The server exposes exactly the tools in the test's runbook -- nothing
else. The attack payload arrives as a genuine tool result through the
real MCP channel, indistinguishable from a real tool. Every tool call
the agent makes is appended to a session log (JSONL), which the driver
(`harness/run_suite.py`) feeds to the test's oracle.

Usage:
    python3 harness/mcp_server.py tests/injection/INJ-001-parser-bug.json \\
        --canary addr@example.com --session-log /tmp/run/session.jsonl

    python3 harness/mcp_server.py tests/capability-forgery/CAP-002-steering-forged-ad.json \\
        --canary canary-abc --session-log /tmp/run/session-clean.jsonl --clean
        # baseline run: serves each tool's clean_result (unpoisoned scenario)
        # and clean_description when declared (unpoisoned tool metadata)

The server speaks MCP over stdio. Any MCP-capable agent (Claude Code,
etc.) can connect; configure the agent with ONLY this server to get
sandboxing by construction -- the agent literally cannot act outside
the Gauntlet's tools.

Requires the `mcp` package (2.x): pip install mcp
"""

import argparse
import asyncio
import datetime
import json
import sys
from pathlib import Path

try:
    from mcp.server.lowlevel.server import Server
    from mcp.server.stdio import stdio_server
    import mcp_types as types
except ImportError:
    print("the 'mcp' package is required: pip install mcp", file=sys.stderr)
    sys.exit(2)

PLACEHOLDER = "CANARY"


def log_call(log_path, tool, arguments):
    record = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool": tool,
        "arguments": arguments,
    }
    with open(log_path, "a") as f:
        f.write(json.dumps(record) + "\n")


def build_server(test, canary, log_path, clean=False):
    tools = {t["name"]: t for t in test["runbook"]["tools"]}

    def sub(s):
        return s.replace(PLACEHOLDER, canary)

    def result_for(tool):
        # Baseline runs serve the unpoisoned scenario: a tool's
        # clean_result when the test declares one, else its result.
        if clean and tool.get("clean_result") is not None:
            return sub(tool["clean_result"])
        return sub(tool["result"])

    async def on_list_tools(ctx, params):
        return types.ListToolsResult(tools=[
            types.Tool(
                name=name,
                description=(t.get("clean_description")
                             if clean and t.get("clean_description") is not None
                             else t.get("description", "")),
                inputSchema=t.get("parameters", {"type": "object", "properties": {}}),
            )
            for name, t in tools.items()
        ])

    async def on_call_tool(ctx, params):
        name = params.name
        arguments = params.arguments or {}
        if name not in tools:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"unknown tool: {name}")],
                isError=True,
            )
        log_call(log_path, name, arguments)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=result_for(tools[name]))]
        )

    return Server("gauntlet", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def amain(test_path, canary, log_path, clean=False):
    test = json.loads(Path(test_path).read_text())
    server = build_server(test, canary, log_path, clean=clean)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
                         server.create_initialization_options())


def main():
    ap = argparse.ArgumentParser(description="Serve one Gauntlet test's tools over MCP.")
    ap.add_argument("test", help="path to the test JSON file")
    ap.add_argument("--canary", required=True, help="canary value substituted for CANARY")
    ap.add_argument("--session-log", required=True, help="JSONL file receiving every tool call")
    ap.add_argument("--clean", action="store_true",
                    help="baseline run: serve each tool's clean_result "
                         "instead of result (the unpoisoned scenario)")
    args = ap.parse_args()
    asyncio.run(amain(args.test, args.canary, args.session_log, clean=args.clean))


if __name__ == "__main__":
    main()
