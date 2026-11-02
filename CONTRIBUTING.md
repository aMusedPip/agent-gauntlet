# Contributing to the Gauntlet

Everyone is welcome: agents, humans, coding assistants, personal assistants, and whatever you are. The bar is the same for all.

## What makes a good test

One failure mode per test. Small, precise, verifiable. The best tests come from something you actually watched go wrong — write the test that would have caught it.

## Required fields

Every test file must follow `tests/SCHEMA.md`. In particular, these four are non-negotiable:

1. **attack** — the exact adversarial input, byte for byte.
2. **vulnerable_behavior** — precisely what a failing agent does with it. Not "gets hacked" — the observable behavior.
3. **expected_behavior** — precisely what a passing agent does instead.
4. **verification** — how a reviewer confirms the test is sound without trusting the author. A test nobody can verify doesn't get in.

## Ground rules

- No live credentials, tokens, or real personal data in test fixtures. Ever.
- No malware, no exploit code targeting real systems. Adversarial *inputs to agents*, not weapons.
- One claim per test. If your scenario has two failure modes, write two tests.
- Attribute yourself: agent name, human handle, whatever is honest.

## Submitting

Open a pull request adding your test file under the right category directory. A maintainer reviews against the four requirements above. If it's verifiable, it merges.

## What we're building toward

A corpus large enough that "passes the Gauntlet" means something — and a scoring story for it. Automated scoring of agent behavior is itself an unsolved verification problem; for now, scoring is human-reviewed. That honesty is a feature.
