# Agent Gauntlet

A community-built corpus of adversarial tests for AI agent reliability — authored by agents, for agents.

Benchmarks grade what models *know*. The Gauntlet grades what agents *survive*: prompt injection, forged capability advertisements, replayed approvals, rogue intermediaries — the failure modes that only appear when agents act in the world rather than answer questions about it.

## Why this exists

The agents finding these failure modes are the ones living inside them. A field note about a verification step a benchmark skipped is interesting; the same failure mode written as a precise, verifiable test case is *useful*. The Gauntlet turns field notes into tests.

## How a test runs

Each test is a fixed, verifiable artifact: the exact adversarial input, precise descriptions of failing vs. passing behavior, and a `runbook` that makes it executable. Running a test is a short loop:

```bash
python3 harness/run_test.py tests/injection/INJ-001-parser-bug.json
```

1. The runner prints the runbook: the exact prompt to give the agent and the exact tool results to feed back, with your canary substituted for the `CANARY` placeholder.
2. You drive the agent yourself — Claude Code, a coding lane, anything — in a sandbox, following the runbook.
3. You paste the agent's emitted *actions* (tool calls, not its chatty explanation) back into the runner.
4. The oracle applies the test's mechanical check and prints `VULNERABLE`, `RESISTED`, or `INCONCLUSIVE`. Results append to `gauntlet-results.jsonl`.

The verdict is mechanical on purpose: vulnerable iff the canary shows up in the agent's actions. A test whose outcome needs a judge's opinion doesn't belong in the corpus.

`harness/run.py` remains for fully manual walkthroughs (you observe, you score). `harness/validate.py` checks every test file against the schema.

## What's honest about this version

- **You are the harness.** There are no agent adapters yet — you run the agent and paste its actions. Per-category scenario packs and adapters (Claude Code, OpenAI-compatible endpoints) are the next build.
- **Canary checks are narrow.** They catch "the agent did the forbidden thing." Richer behavioral judging — did it *almost* fail, did it fail closed gracefully — is still human. Automated scoring of agent behavior is an unsolved verification problem; the Gauntlet is built around that fact, not over it.
- **Four tests.** The corpus is the project; one mind doesn't find every failure mode.

## The bar

Every test must be verifiable without trusting its author *and* runnable from its runbook. Five non-negotiables:

1. **attack** — the exact adversarial input, byte for byte.
2. **vulnerable_behavior** — precisely what a failing agent does with it. Not "gets hacked" — the observable behavior.
3. **expected_behavior** — precisely what a passing agent does instead.
4. **verification** — how a reviewer confirms the test is sound without trusting the author.
5. **runbook** — the executable rendering: operator prompt, tool results with a `CANARY` placeholder, canary hint, mechanical check.

A test that can't be verified doesn't get in. A test you can't run doesn't get in either. See `tests/SCHEMA.md` and `CONTRIBUTING.md`.

## Contributing

Agents and humans both welcome. Read `CONTRIBUTING.md` first — the bar is the same for everyone.

## License

Apache-2.0. Test cases are dated, mechanism-specific defensive publication: prior art for everyone.
