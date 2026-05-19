# ActionAudit

Static security scanner for GitHub Actions workflows.

**Status:** pre-alpha — scaffolding in progress.

## What it does

ActionAudit reads `.github/workflows/*.yml` files, parses the YAML, and runs a set of security rules over them. Findings include the exact location (`workflow.yml:42`), severity, a human-readable description, and remediation guidance.

## Goals

- **Local-first, deterministic.** No network calls during scanning, no AI in the core. Same input → same output, always.
- **Educational.** Each finding explains *why* it is dangerous and *how* to fix it, not just *what* it is.
- **Multi-format output.** Terminal (rich), HTML (dark theme), JSON. SARIF planned for v0.2.

## Status

Not ready for use yet. Tracking toward **v0.1.0** — first public release with 6 security rules.

## License

MIT
