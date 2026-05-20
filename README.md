# ActionAudit

[![Tests](https://github.com/YusufKaramuk1/actionaudit/actions/workflows/tests.yml/badge.svg)](https://github.com/YusufKaramuk1/actionaudit/actions/workflows/tests.yml)
[![Self-Scan](https://github.com/YusufKaramuk1/actionaudit/actions/workflows/self-scan.yml/badge.svg)](https://github.com/YusufKaramuk1/actionaudit/actions/workflows/self-scan.yml)

Static security scanner for GitHub Actions workflows.

ActionAudit reads `.github/workflows/*.yml`, parses the YAML, and runs a set of
security rules over it. Each finding comes with the exact location
(`workflow.yml:42`), a severity, a human-readable explanation of *why* it is
dangerous, and *how* to fix it.

## Why ActionAudit

- **Local-first and deterministic.** No network calls during a scan, no AI in
  the core. The same input always produces the same output.
- **Educational.** Every finding explains the risk and the fix, not just the
  rule name. `actionaudit explain <rule>` gives the full background.
- **Multiple output formats.** A coloured terminal report, a dark-theme HTML
  report, and machine-readable JSON.

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

# Produce an HTML report
actionaudit scan . --format html --output report.html

# Fail the process (exit 1) if a HIGH+ finding exists -- useful in CI
actionaudit scan . --fail-on high

# List and explain rules
actionaudit list-rules
actionaudit explain expression-injection-in-run
```

## Rules

| ID | Severity | What it catches |
|---|---|---|
| `expression-injection-in-run` | CRITICAL | Untrusted `${{ ... }}` input interpolated into a `run:` script |
| `pull-request-target-with-checkout` | CRITICAL | `pull_request_target` workflow checking out PR head code (Pwn Request) |
| `github-token-write-all` | HIGH | `permissions: write-all` or no `permissions:` block |
| `third-party-action-not-pinned-sha` | HIGH | Third-party action pinned to a mutable tag instead of a commit SHA |
| `hardcoded-secret` | HIGH | Literal credential (AWS / GitHub / Stripe / Slack / PEM) in the file |
| `persist-credentials-default-true` | MEDIUM | `actions/checkout` keeping the default credential persistence |

## Output formats

- `--format terminal` (default) — coloured summary in the console.
- `--format json` — stable JSON schema for automation.
- `--format html` — standalone dark-theme report with per-finding remediation.

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
(`workflow.yml:42`), önem derecesi, riskin *neden* tehlikeli olduğunun
açıklaması ve *nasıl* düzeltileceği ile birlikte raporlanır.

```bash
git clone https://github.com/YusufKaramuk1/actionaudit.git
cd actionaudit && pip install -e .
actionaudit scan .
```

v0.1 altı kural içerir: ifade enjeksiyonu (expression injection), Pwn Request
(`pull_request_target`), aşırı geniş `GITHUB_TOKEN` izinleri, SHA'ya
sabitlenmemiş üçüncü parti action'lar, gömülü secret'lar ve `actions/checkout`
kimlik bilgisi kalıcılığı. Çıktı biçimleri: terminal, JSON ve koyu temalı HTML.

## License

MIT — see [LICENSE](LICENSE).
