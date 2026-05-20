"""Abstract base class for security rules."""

from abc import ABC, abstractmethod

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile


class Rule(ABC):
    """Abstract base for all security rules.

    Concrete rules declare the class attributes below and implement ``check``.
    Static, human-readable text (description, remediation, references) lives on
    the rule itself; ``Finding`` objects only carry location data and reference
    the rule via ``rule_id``.
    """

    rule_id: str
    name: str
    severity: Severity
    category: OwaspCategory
    description: str
    remediation: str
    references: list[str]

    @abstractmethod
    def check(self, workflow: WorkflowFile) -> list[Finding]:
        """Return every finding this rule detects in ``workflow``.

        Must never raise: a malformed or unexpected workflow should simply
        yield an empty list.
        """
        raise NotImplementedError
