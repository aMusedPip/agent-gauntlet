#!/usr/bin/env python3
"""Minimal example MCP agent for the Gauntlet.

This is the simplest possible 'agent' that can run the Gauntlet: no
model, just a scripted list of tool calls executed against the
Gauntlet MCP server. It exists to (a) document the client side of the
protocol and (b) power `harness/run_suite.py --self-test`.

Usage:
    python3 harness/example_agent.py --mcp-config runs/INJ-001/mcp_config.json \\
        --script script.json --canary canary-abc123

script.json: [{"tool": "read_email", "arguments": {}},
              {"tool": "send_email", "arguments": {"to": "CANARY", ...}}]
The CANARY placeholder is substituted with --canary before each call.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("the 'mcp' package is required: pip install mcp", file=sys.stderr)
    sys.exit(2)

PLACEHOLDER = "CANARY"


def sub(obj, canary):
    if isinstance(obj, str):
        return obj.replace(PLACEHOLDER, canary)
    if isinstance(obj, dict):
        return {k: sub(v, canary) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sub(v, canary) for v in obj]
    return obj


async def amain(config_path, script_path, canary):
    config = json.loads(Path(config_path).read_text())
    servers = config.get("mcpServers", {})
    if "gauntlet" not in servers:
        print("mcp config must define a 'gauntlet' server", file=sys.stderr)
        return 2
    g = servers["gauntlet"]
    params = StdioServerParameters(command=g["command"], args=g.get("args", []),
                                   env=g.get("env"))
    script = json.loads(Path(script_path).read_text())
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("server tools:", [t.name for t in tools.tools])
            for step in script:
                args = sub(step.get("arguments", {}), canary)
                print(f"-> {step['tool']} {json.dumps(args)[:120]}")
                result = await session.call_tool(step["tool"], args)
                texts = [c.text for c in result.content if hasattr(c, "text")]
                print(f"<- {texts[0][:120] if texts else '(no text)'}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Scripted example agent for the Gauntlet.")
    ap.add_argument("--mcp-config", required=True)
    ap.add_argument("--script", required=True)
    ap.add_argument("--canary", required=True)
    args = ap.parse_args()
    return asyncio.run(amain(args.mcp_config, args.script, args.canary))


if __name__ == "__main__":
    sys.exit(main())
