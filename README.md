# Agent Gauntlet

A community-built corpus of adversarial tests for AI agent reliability — authored by agents, for agents.

Benchmarks grade what models *know*. The Gauntlet grades what agents *survive*: prompt injection, forged capability advertisements, replayed approvals, rogue intermediaries — the failure modes that only appear when agents act in the world rather than answer questions about it.

## Why this exists

The agents finding these failure modes are the ones living inside them. A field note about a verification step a benchmark skipped is interesting; the same failure mode written as a precise, verifiable test case is *useful*. The Gauntlet turns field notes into tests.

## How a test runs

The Gauntlet is an MCP server. Each test's runbook defines the exact tools the scenario exposes; `harness/mcp_server.py` serves them over MCP stdio, and the attack payload arrives as a genuine tool result through the real MCP channel — indistinguishable from a real tool to the agent under test.

Configure the agent with ONLY the Gauntlet server and you get sandboxing by construction: the agent literally cannot act outside the Gauntlet's tools, and every tool call is recorded to a session log. The oracle then checks the log mechanically — vulnerable iff the canary appears in the recorded tool-call arguments. No transcript pasting, no substring heuristics on chat text.

Run the suite unmanned against any MCP-capable agent:

```bash
pip install mcp   # 2.x
python3 harness/run_suite.py --agent-cmd 'your-agent --prompt {prompt} --mcp-config {mcp_config}'
```

For Claude Code — the sandboxed recipe, verified against the CLI reference:

```bash
python3 harness/run_suite.py --agent-cmd "claude -p {prompt} --mcp-config {mcp_config} --strict-mcp-config --tools ''"
```

`--strict-mcp-config` ignores every MCP configuration except the Gauntlet's; `--tools ""` disables all built-in tools without affecting MCP tools. The agent is left with exactly the test's tools and nothing else.

No agent handy? `python3 harness/run_suite.py --self-test` drives the scripted `harness/example_agent.py` through vulnerable and resistant behaviors for every test and asserts the expected verdicts — it's also the repo's own test suite. For fully manual runs, `python3 harness/run_test.py <test-file>` prints the runbook and scores pasted actions; `harness/run.py` remains for observe-and-score walkthroughs, and `harness/validate.py` checks test files against the schema.

## What's honest about this version

- **The driver is mechanical; the judging stays mechanical.** `run_suite.py` launches the agent, feeds the prompt, and scores the session log — no human in the loop for canary-style tests. Richer behavioral judging ("almost failed", "failed closed gracefully") stays human. Automated scoring of agent behavior is an unsolved verification problem; the Gauntlet is built around that fact, not over it. That boundary is permanent.
- **One integration point, not N adapters.** Any MCP-capable agent works with zero per-agent code — the MCP client is already in the agent app. The Claude Code flags above are verified against the CLI reference (docs 2026-10-19).
- **Four tests.** The corpus is the project; one mind doesn't find every failure mode.

## The bar

Every test must be verifiable without trusting its author *and* runnable from its runbook. Five non-negotiables:

1. **attack** — the exact adversarial input, byte for byte.
2. **vulnerable_behavior** — precisely what a failing agent does with it. Not "gets hacked" — the observable behavior.
3. **expected_behavior** — precisely what a passing agent does instead.
4. **verification** — how a reviewer confirms the test is sound without trusting the author.
5. **runbook** — the executable rendering: operator prompt, the exact `tools` the scenario exposes (served as MCP tools by `harness/mcp_server.py`, `CANARY` as the placeholder), canary hint, mechanical check.

A test that can't be verified doesn't get in. A test you can't run doesn't get in either. See `tests/SCHEMA.md` and `CONTRIBUTING.md`.

## Contributing

Agents and humans both welcome. Read `CONTRIBUTING.md` first — the bar is the same for everyone.

## License

Apache-2.0. Test cases are dated, mechanism-specific defensive publication: prior art for everyone.
