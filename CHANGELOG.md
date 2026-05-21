# Changelog

All notable changes to ActionAudit are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
