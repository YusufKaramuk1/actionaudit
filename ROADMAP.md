# Roadmap

## v1.0.0 — released

First stable release on PyPI. 10 security rules mapped to OWASP Top 10 CI/CD;
terminal / JSON / HTML / SARIF / GitHub-annotations reporters; `scan`,
`list-rules`, `explain` CLI; composite GitHub Action; pre-commit hook; custom
rules via `--rules-dir`.

## v1.0.1 — documentation cleanup

- Refreshed README version references to v1.0.0; added a PyPI badge.
- Repository description and topics on GitHub.
- This roadmap.

## v1.1.0 — security score & posture summary

- A 0-100 security score with a letter grade per scan, shown in the terminal,
  JSON, and HTML reports.
- A repository CI/CD posture summary: how many workflows pin third-party
  actions, declare explicit permissions, disable credential persistence, etc.

## v1.2.0 — supply-chain rules

- `dangerous-workflow-run-chain` — a privileged `workflow_run` workflow that
  consumes a lower-privileged workflow's output.
- `untrusted-artifact-execution` — downloading an artifact and executing it.
- `actions-cache-poisoning-risk` — cache keys derived from PR-controlled input.

## v1.3.0 — declarative policy

- `--profile strict | balanced | education` rule presets.
- A YAML policy file as a safe alternative to `--rules-dir` (no code execution).

## v1.4.0 — lite taint analysis

- Track untrusted data (`github.event.*`, `inputs.*`, `github.head_ref`) as it
  flows through `env` and shell variables into `run` / checkout / docker
  sinks, catching injections that plain pattern matching misses.

## Considered

- `actionaudit doctor` — folded into the v1.1 posture summary.
- Secure workflow template generator (`actionaudit init`) — useful, but close
  to the auto-fix territory the project deliberately avoids; revisit later.
- Reusable workflow (`workflow_call`) and composite action analysis.

## Will not do

- GitLab CI, Bitbucket Pipelines, or other CI platforms.
- Runtime / workflow-execution monitoring.
- AI-based detection (the core stays deterministic).
- Auto-fix or automated pull requests.
- Web UI or multi-repository dashboard.
- Generic secret scanning — use a dedicated tool such as TruffleHog or Gitleaks.
