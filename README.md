# ActionAudit

[![Tests](https://github.com/YusufKaramuk1/actionaudit/actions/workflows/tests.yml/badge.svg)](https://github.com/YusufKaramuk1/actionaudit/actions/workflows/tests.yml)
[![Self-Scan](https://github.com/YusufKaramuk1/actionaudit/actions/workflows/self-scan.yml/badge.svg)](https://github.com/YusufKaramuk1/actionaudit/actions/workflows/self-scan.yml)

Static security scanner for GitHub Actions workflows.

ActionAudit reads `.github/workflows/*.yml`, parses the YAML, and runs a set of
security rules over it. Each finding comes with the exact location
(`workflow.yml:42`), a severity, an OWASP CI/CD category, a human-readable
explanation of *why* it is dangerous, and *how* to fix it.

## Why ActionAudit

- **Local-first and deterministic.** No network calls during a scan, no AI in
  the core. The same input always produces the same output.
- **Educational.** Every finding explains the risk and the fix, not just the
  rule name. `actionaudit explain <rule>` gives the full background.
- **Standards-aligned.** Every rule maps to an
  [OWASP Top 10 CI/CD Security Risk](https://owasp.org/www-project-top-10-ci-cd-security-risks/).
- **Multiple output formats.** Coloured terminal, dark-theme HTML, JSON, and
  SARIF for GitHub Code Scanning.

## Install

ActionAudit is pre-release; install it from source:

```bash
git clone https://github.com/YusufKaramuk1/actionaudit.git
cd actionaudit
python -m venv venv
pip install -e .
```

## Usage

```bash
# Scan the workflows in the current repository
actionaudit scan .

# Scan a specific file or directory
actionaudit scan .github/workflows/ci.yml

# Produce an HTML or SARIF report
actionaudit scan . --format html --output report.html
actionaudit scan . --format sarif --output results.sarif

# Fail the process (exit 1) if a HIGH+ finding exists -- useful in CI
actionaudit scan . --fail-on high

# List and explain rules
actionaudit list-rules
actionaudit explain expression-injection-in-run
```

## Use as a GitHub Action

Add ActionAudit to any repository's workflow:

```yaml
- uses: YusufKaramuk1/actionaudit@v0.3.0
  with:
    path: .github/workflows
    fail-on: high
```

Findings are emitted as inline annotations on the pull request, and the step
fails when a finding at or above `fail-on` is present.

## Use as a pre-commit hook

Add ActionAudit to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/YusufKaramuk1/actionaudit
    rev: v0.4.0
    hooks:
      - id: actionaudit
```

The hook runs whenever a workflow file changes and fails the commit on a
HIGH-or-above finding (override with `args: ['--fail-on', 'critical']`).

## Rules

| ID | Severity | OWASP | What it catches |
|---|---|---|---|
| `expression-injection-in-run` | CRITICAL | CICD-SEC-4 | Untrusted `${{ ... }}` input interpolated into a `run:` script |
| `pull-request-target-with-checkout` | CRITICAL | CICD-SEC-4 | `pull_request_target` workflow checking out PR head code (Pwn Request) |
| `workflow-dispatch-input-injection` | HIGH | CICD-SEC-4 | Workflow input interpolated into a `run:` script |
| `github-token-write-all` | HIGH | CICD-SEC-5 | `permissions: write-all` or no `permissions:` block |
| `third-party-action-not-pinned-sha` | HIGH | CICD-SEC-3 | Third-party action pinned to a mutable tag instead of a commit SHA |
| `hardcoded-secret` | HIGH | CICD-SEC-6 | Literal credential (AWS / GitHub / Stripe / Slack / PEM) in the file |
| `inline-curl-pipe-bash` | MEDIUM | CICD-SEC-3 | Remote script piped straight into a shell |
| `persist-credentials-default-true` | MEDIUM | CICD-SEC-6 | `actions/checkout` keeping the default credential persistence |
| `self-hosted-runner-fork-trigger` | MEDIUM | CICD-SEC-7 | Self-hosted runner reachable by forked pull requests |
| `bash-with-set-x` | LOW | CICD-SEC-10 | Shell debug tracing (`set -x`) that can leak secrets into logs |

## Output formats

- `--format terminal` (default) — coloured summary in the console.
- `--format json` — stable JSON schema for automation.
- `--format html` — standalone dark-theme report with per-finding remediation.
- `--format sarif` — SARIF v2.1.0 for GitHub Code Scanning.

## Configuration

Add a `[tool.actionaudit]` section to `pyproject.toml`:

```toml
[tool.actionaudit]
disabled_rules = ["bash-with-set-x"]

[tool.actionaudit.severity]
hardcoded-secret = "critical"
```

To suppress a single finding, add an inline comment on the offending line (or
the line just above it):

```yaml
- uses: tj-actions/changed-files@v44  # actionaudit: ignore third-party-action-not-pinned-sha
```

## Custom rules

Write organisation-specific rules and load them alongside the built-in ones
with `--rules-dir`:

```bash
actionaudit scan . --rules-dir ./company-rules/
```

Each `.py` file in the directory may define `Rule` subclasses (see
[CONTRIBUTING.md](CONTRIBUTING.md) for the contract). **Note:** `--rules-dir`
imports and executes the Python files it finds — only point it at directories
you trust.

## Philosophy

ActionAudit only scans GitHub Actions workflow files. It is not a runtime
monitor, not a generic secret scanner, and not a multi-platform CI tool — that
focus is deliberate. See [ROADMAP.md](ROADMAP.md) for what is planned and what
is intentionally out of scope.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule.

## Türkçe özet

ActionAudit, GitHub Actions iş akışlarındaki (`.github/workflows/*.yml`)
güvenlik açıklarını ve hatalı yapılandırmaları statik olarak tespit eden,
yerel çalışan, deterministik bir CLI tarayıcısıdır. Her bulgu; kesin konum
(`workflow.yml:42`), önem derecesi, OWASP CI/CD kategorisi, riskin *neden*
tehlikeli olduğunun açıklaması ve *nasıl* düzeltileceği ile birlikte raporlanır.

```bash
git clone https://github.com/YusufKaramuk1/actionaudit.git
cd actionaudit && pip install -e .
actionaudit scan .
```

Şu an 10 kural içerir ve her biri OWASP Top 10 CI/CD risk kategorilerinden
biriyle eşleştirilmiştir. Çıktı biçimleri: terminal, JSON, koyu temalı HTML ve
SARIF. Bulgular `pyproject.toml` içindeki `[tool.actionaudit]` bölümünden veya
satır içi `# actionaudit: ignore` yorumlarıyla bastırılabilir.

## License

MIT — see [LICENSE](LICENSE).
