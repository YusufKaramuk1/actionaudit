"""Rule: hard-coded credentials with provider-defined, unambiguous formats.

This rule deliberately avoids entropy heuristics and generic guessing. It only
matches credential formats that are unambiguous by construction (fixed provider
prefixes), so a match is near-certain to be a real secret -- a deterministic
tool should rely on proof, not probability. For broad secret scanning, use a
dedicated tool such as TruffleHog or Gitleaks.
"""

import re

from actionaudit.models import Finding, Severity, WorkflowFile
from actionaudit.rules.base import Rule

# (label, pattern) pairs. Each pattern is anchored to a provider-defined prefix.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key ID", re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[porsu]_[A-Za-z0-9]{36}\b")),
    ("Stripe live secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "private key",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    ),
)


def _redact(secret: str) -> str:
    """Mask a matched secret so the report never echoes it verbatim."""
    if len(secret) <= 12:
        return secret[:4] + "***"
    return secret[:8] + "***" + secret[-2:]


class HardcodedSecretRule(Rule):
    """Detect literal credentials embedded in the workflow file."""

    rule_id = "hardcoded-secret"
    name = "Hardcoded secret in workflow file"
    severity = Severity.HIGH
    description = (
        "A literal credential with a recognised provider format (AWS access "
        "key, GitHub token, Stripe key, Slack token, or a PEM private key) is "
        "embedded directly in the workflow file. If the repository is public "
        "this is an immediate leak; even in a private repository the value "
        "persists in Git history and may surface in build logs."
    )
    remediation = (
        "Move the value into an encrypted repository or organisation secret "
        "and reference it via the secrets context:\n"
        "  - env:\n"
        "      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n"
        "Then rotate the exposed credential, since it must be considered "
        "compromised."
    )
    references = [
        "https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions",
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.raw_text:
            return findings

        for line_number, line in enumerate(workflow.lines, start=1):
            for label, pattern in _SECRET_PATTERNS:
                match = pattern.search(line)
                if match is None:
                    continue
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        workflow_path=workflow.path,
                        line=line_number,
                        column=match.start(),
                        snippet=f"{label}: {_redact(match.group(0))}",
                        message=(
                            f"Hard-coded {label} embedded in the workflow file; "
                            "move it to an encrypted secret and rotate it."
                        ),
                        confidence="high",
                    )
                )
        return findings
