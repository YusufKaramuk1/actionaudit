# Contributing to ActionAudit

Thanks for your interest in improving ActionAudit.

## Development setup

```bash
python -m venv venv
# Windows:        venv\Scripts\activate
# Linux / macOS:  source venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

All three must pass:

```bash
pytest
ruff check src tests
mypy src
```

## Adding a rule

1. Create `src/actionaudit/rules/<name>.py` with a class that subclasses
   `Rule` (from `actionaudit.rules.base`). It is discovered automatically —
   there is no registry to update.
2. Set the class attributes: `rule_id`, `name`, `severity`, `description`,
   `remediation`, `references`.
3. Implement `check(self, workflow) -> list[Finding]`. It must never raise:
   a malformed workflow should yield an empty list.
4. Add a `vulnerable/` and a `safe/` fixture under `tests/fixtures/`.
5. Add tests in `tests/test_rules.py` covering the vulnerable case, the safe
   case, and a malformed-YAML case.

A rule without tests will not be merged — tests ship in the same pull request
as the rule.

## Commit messages

Use the form `<verb>: <short description>` (e.g. `add inline-curl-pipe rule`,
`fix parser line offset`).
