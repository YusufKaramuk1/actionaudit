"""Core data models for actionaudit."""

from dataclasses import dataclass
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
