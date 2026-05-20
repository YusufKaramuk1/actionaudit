# Roadmap

## v0.1.0 — released

Six security rules; terminal, JSON, and HTML reporters; `scan`, `list-rules`,
and `explain` CLI commands; CI with self-scan.

## v0.2.0 — in progress

- SARIF v2.1.0 output for GitHub Code Scanning. **(done)**
- Additional security rules — total of ten. **(done)**
- OWASP Top 10 CI/CD category mapping for every rule. **(done)**
- Inline ignore comments (`# actionaudit: ignore <rule-id>`).
- Configuration file support (`[tool.actionaudit]` in `pyproject.toml`):
  per-repository severity overrides and disabled rules.

## v0.3.0

- GitHub Action package (`action.yml`) and Marketplace listing.
- GitHub annotations output (`::error file=...,line=...::`) so findings appear
  inline on pull requests when ActionAudit runs as an Action.

## v0.4.0

- Pre-commit hook integration.
- Custom rules (BYOR): a `--rules-dir` option to load user-defined rule
  modules, turning ActionAudit into a Policy-as-Code platform. Needs a careful
  API: rule discovery, error handling, and an explicit "this executes code"
  warning, since loading external Python is itself a trust boundary.

## v1.0.0

- PyPI release.
- Documentation polish.

## Considered but deferred

- Reusable workflow (`workflow_call`) and composite action analysis.
- Pwn Request variants beyond explicit checkout (requires taint analysis).
- Entropy-based secret detection (the current rule stays format-anchored).
- `continue-on-error-on-security-step` rule — needs a reliable definition of
  what counts as a "security step" before it can avoid false positives.

## Will not do

These are intentionally out of scope — ActionAudit stays focused.

- GitLab CI, Bitbucket Pipelines, or other CI platforms.
- Runtime / workflow-execution monitoring.
- AI-based detection (the core stays deterministic).
- Auto-fix or automated pull requests.
- Web UI or multi-repository dashboard.
- Generic secret scanning — use a dedicated tool such as TruffleHog or Gitleaks.
