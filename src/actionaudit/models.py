"""Core data models for actionaudit."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Severity of a finding, ordered most-to-least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank; higher is more severe. Used for sorting and filtering."""
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]


class OwaspCategory(str, Enum):
    """OWASP Top 10 CI/CD Security Risks (2022)."""

    FLOW_CONTROL = "CICD-SEC-1"
    IAM = "CICD-SEC-2"
    DEPENDENCY_CHAIN = "CICD-SEC-3"
    PPE = "CICD-SEC-4"
    PBAC = "CICD-SEC-5"
    CREDENTIAL_HYGIENE = "CICD-SEC-6"
    SYSTEM_CONFIG = "CICD-SEC-7"
    THIRD_PARTY = "CICD-SEC-8"
    ARTIFACT_INTEGRITY = "CICD-SEC-9"
    LOGGING = "CICD-SEC-10"

    @property
    def risk_name(self) -> str:
        """Human-readable name of the OWASP CI/CD category."""
        return _OWASP_TITLES[self]

    @property
    def label(self) -> str:
        """Code and name, e.g. 'CICD-SEC-4: Poisoned Pipeline Execution'."""
        return f"{self.value}: {self.risk_name}"


_OWASP_TITLES: dict[OwaspCategory, str] = {
    OwaspCategory.FLOW_CONTROL: "Insufficient Flow Control Mechanisms",
    OwaspCategory.IAM: "Inadequate Identity and Access Management",
    OwaspCategory.DEPENDENCY_CHAIN: "Dependency Chain Abuse",
    OwaspCategory.PPE: "Poisoned Pipeline Execution",
    OwaspCategory.PBAC: "Insufficient Pipeline-Based Access Controls",
    OwaspCategory.CREDENTIAL_HYGIENE: "Insufficient Credential Hygiene",
    OwaspCategory.SYSTEM_CONFIG: "Insecure System Configuration",
    OwaspCategory.THIRD_PARTY: "Ungoverned Usage of 3rd Party Services",
    OwaspCategory.ARTIFACT_INTEGRITY: "Improper Artifact Integrity Validation",
    OwaspCategory.LOGGING: "Insufficient Logging and Visibility",
}


@dataclass
class WorkflowFile:
    """A GitHub Actions workflow file: raw text plus parse result.

    Parsing never raises; failures are recorded in ``parse_error``.
    """

    path: Path
    raw_text: str
    parsed: Any = None
    parse_error: str | None = None

    @property
    def is_valid(self) -> bool:
        """True if the file parsed into a YAML mapping with no error."""
        return self.parse_error is None and isinstance(self.parsed, dict)

    @property
    def lines(self) -> list[str]:
        """Raw text split into lines, without line endings."""
        return self.raw_text.splitlines()


@dataclass
class Finding:
    """A single rule violation located within a workflow file."""

    rule_id: str
    severity: Severity
    workflow_path: Path
    line: int
    message: str
    column: int = 0
    job_name: str | None = None
    step_index: int | None = None
    snippet: str = ""
    confidence: str = "high"


@dataclass
class PostureSummary:
    """Aggregate, mostly-positive CI/CD posture metrics across scanned workflows."""

    total_workflows: int = 0
    workflows_with_permissions: int = 0
    pull_request_target_workflows: int = 0
    total_third_party_uses: int = 0
    pinned_third_party_uses: int = 0
    total_checkouts: int = 0
    checkouts_with_persist_false: int = 0


@dataclass
class ScanReport:
    """Aggregated result of scanning one or more workflow files."""

    findings: list[Finding]
    scanned_files: list[Path]
    skipped: list[tuple[Path, str]]
    duration_ms: int
    posture: PostureSummary = field(default_factory=PostureSummary)

    @property
    def total_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    def count(self, severity: Severity) -> int:
        """Number of findings at the given severity."""
        return sum(1 for finding in self.findings if finding.severity is severity)

    @property
    def overall_severity(self) -> Severity | None:
        """The most severe finding's severity, or None when there are none."""
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def findings_by_file(self) -> dict[Path, list[Finding]]:
        """Findings grouped by workflow file, preserving discovery order."""
        grouped: dict[Path, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.workflow_path, []).append(finding)
        return grouped

    @property
    def score(self) -> int:
        """A 0-100 security score; higher is better.

        Each finding subtracts a severity-weighted penalty from a perfect 100,
        clamped so the score never drops below zero.
        """
        penalty = (
            self.count(Severity.CRITICAL) * 25
            + self.count(Severity.HIGH) * 15
            + self.count(Severity.MEDIUM) * 7
            + self.count(Severity.LOW) * 2
        )
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        """A letter grade (A-F) derived from :attr:`score`."""
        score = self.score
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"
