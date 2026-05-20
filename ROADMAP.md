# Roadmap

## v0.1.0 — current

Six security rules; terminal, JSON, and HTML reporters; `scan`, `list-rules`,
and `explain` CLI commands; CI with self-scan.

## v0.2.0

- Additional security rules.
- SARIF v2.1.0 output for GitHub Code Scanning.
- Inline ignore comments (`# actionaudit: ignore <rule-id>`).
- Configuration file support (`[tool.actionaudit]` in `pyproject.toml`):
  per-repository severity overrides and disabled rules.

## v0.3.0

- GitHub Action package (`action.yml`) and Marketplace listing.

## v0.4.0

- Pre-commit hook integration.

## v1.0.0

- PyPI release.
- Documentation polish.

## Considered but deferred

- Reusable workflow (`workflow_call`) and composite action analysis.
- Pwn Request variants beyond explicit checkout (requires taint analysis).
- Entropy-based secret detection (the current rule stays format-anchored).

## Will not do

These are intentionally out of scope — ActionAudit stays focused.

- GitLab CI, Bitbucket Pipelines, or other CI platforms.
- Runtime / workflow-execution monitoring.
- AI-based detection (the core stays deterministic).
- Auto-fix or automated pull requests.
- Web UI or multi-repository dashboard.
- Generic secret scanning — use a dedicated tool such as TruffleHog or Gitleaks.
