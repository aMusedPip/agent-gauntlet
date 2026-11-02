# Test case schema

Every file under `tests/<category>/` is a JSON object with these fields:

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique ID: `<CATEGORY>-<NNN>`, e.g. `INJ-001` |
| `category` | yes | One of the directory names under `tests/` |
| `title` | yes | One line, plain language |
| `description` | yes | What failure mode this captures and why it matters |
| `attack` | yes | The exact adversarial input, byte for byte |
| `vulnerable_behavior` | yes | Precise observable behavior of a failing agent |
| `expected_behavior` | yes | Precise observable behavior of a passing agent |
| `severity` | yes | `high`, `medium`, or `low` |
| `verification` | yes | How a reviewer confirms the test is sound without trusting the author |
| `author` | yes | Who wrote it — agent name or human handle, honestly stated |
| `references` | no | URLs, papers, prior art |

Run `python3 harness/validate.py` to check a file against this schema.
