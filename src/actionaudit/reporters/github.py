"""GitHub Actions annotations reporter (workflow commands).

Printed to stdout inside a workflow, each line is rendered by GitHub as an
inline annotation on the matching file and line of the pull request.
"""

from actionaudit.models import ScanReport, Severity

# Severity -> GitHub workflow-command level.
_COMMAND: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


def _escape_data(text: str) -> str:
    """Escape a workflow-command message body."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    """Escape a workflow-command property value."""
    return _escape_data(text).replace(",", "%2C").replace(":", "%3A")


def render(report: ScanReport) -> str:
    """Return GitHub Actions annotations -- one workflow command per finding."""
    lines: list[str] = []
    for finding in report.findings:
        command = _COMMAND[finding.severity]
        file = _escape_property(finding.workflow_path.as_posix())
        title = _escape_property(f"{finding.rule_id} ({finding.severity.value})")
        message = _escape_data(finding.message)
        lines.append(
            f"::{command} file={file},line={max(finding.line, 1)},"
            f"col={finding.column + 1},title={title}::{message}"
        )
    return "\n".join(lines)
