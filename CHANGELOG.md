# Changelog

All notable changes to ActionAudit are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
