# Changelog

All notable changes to ActionAudit are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `--baseline <report.json>` suppresses findings already present in a previous
  JSON scan report; the run reports only NEW findings and `--fail-on` applies
  only to them. This is the missing piece for adopting ActionAudit on
  brownfield repositories where the existing finding count must not break CI.

## [1.3.0] - 2026-05-21

### Added

- `--profile strict|balanced|education` built-in configuration presets that
  layer underneath any user configuration.
- `--policy <file.yaml>` loads configuration from a standalone YAML policy
  file (same schema as `[tool.actionaudit]` in pyproject.toml) -- a safe,
  declarative alternative to `--rules-dir` that does not execute any code.

## [1.2.0] - 2026-05-21

### Added

- Three supply-chain rules (total 13):
  - `dangerous-workflow-run-chain` (HIGH) — a `workflow_run` workflow that
    consumes an upstream workflow's artifacts in a privileged context.
  - `untrusted-artifact-execution` (HIGH) — a downloaded artifact executed
    in the same job without verification.
  - `actions-cache-poisoning-risk` (MEDIUM) — cache key derived from
    PR-controlled input, allowing a poisoned cache slot.

## [1.1.0] - 2026-05-21

### Added

- Security score: a 0-100 severity-weighted score with an A-F letter grade,
  shown in the terminal, JSON, and HTML reports.
- CI/CD posture summary: positive metrics across the scanned workflows
  (explicit permissions, SHA-pinned third-party actions, checkout credential
  hygiene, `pull_request_target` usage), shown in all three report formats.

### Changed

- JSON output schema bumped to 1.1: `summary` now includes `score` and
  `grade`, and a top-level `posture` block is added.

## [1.0.0] - 2026-05-21

### Changed

- First stable release, published to PyPI — install with `pip install actionaudit`.
- Automated PyPI publishing via a release-triggered workflow using trusted
  publishing (OIDC, no stored credentials).

## [0.4.0] - 2026-05-21

### Added

- pre-commit hook support via `.pre-commit-hooks.yaml`: use ActionAudit with
  `repo: https://github.com/YusufKaramuk1/actionaudit` in `.pre-commit-config.yaml`.
- Custom rules (BYOR): `--rules-dir <dir>` loads user-defined rule modules
  alongside the built-in rules.

## [0.3.0] - 2026-05-21

### Added

- GitHub Actions annotations reporter (`--format github`): emits workflow
  commands so findings appear inline on pull requests.
- Composite GitHub Action (`action.yml`): run ActionAudit in any repository
  with `uses: YusufKaramuk1/actionaudit@v0.3.0`.

## [0.2.0] - 2026-05-21

### Added

- SARIF v2.1.0 reporter (`--format sarif`) for GitHub Code Scanning; the
  self-scan workflow now uploads its results to Code Scanning.
- OWASP Top 10 CI/CD category mapping for every rule, surfaced in the terminal,
  JSON, HTML, and SARIF output and in `explain` / `list-rules`.
- Inline ignore directives: `# actionaudit: ignore <rule-id>` in a workflow
  comment suppresses findings on that line (and the line below it).
- Configuration via a `[tool.actionaudit]` table in `pyproject.toml`:
  `disabled_rules` and per-rule severity overrides.
- Four additional security rules:
  - `inline-curl-pipe-bash` (MEDIUM)
  - `workflow-dispatch-input-injection` (HIGH)
  - `bash-with-set-x` (LOW)
  - `self-hosted-runner-fork-trigger` (MEDIUM)

## [0.1.0] - 2026-05-20

### Added

- YAML parser with source-location tracking, including correct line numbers
  inside multi-line `run:` block scalars.
- Plugin-discovery rule engine: a new rule is just a new module.
- Six security rules:
  - `expression-injection-in-run` (CRITICAL)
  - `pull-request-target-with-checkout` (CRITICAL)
  - `github-token-write-all` (HIGH)
  - `third-party-action-not-pinned-sha` (HIGH)
  - `hardcoded-secret` (HIGH)
  - `persist-credentials-default-true` (MEDIUM)
- Scan orchestrator that discovers workflow files and tolerates malformed input.
- Reporters: terminal (rich), JSON, HTML (dark theme with per-finding
  remediation).
- CLI commands: `scan` (with `--format`, `--output`, `--fail-on`),
  `list-rules`, `explain`.
- CI: test matrix workflow and a self-scan (dogfooding) workflow.
