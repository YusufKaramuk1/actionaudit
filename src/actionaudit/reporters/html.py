"""HTML reporter: render a ScanReport as a standalone dark-theme HTML page."""

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from actionaudit import __version__
from actionaudit.models import Finding, OwaspCategory, ScanReport, Severity
from actionaudit.rules import get_all_rules

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "j2"]),
)

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def _sorted_findings(report: ScanReport) -> list[Finding]:
    """Most severe first, then by file path and line."""
    return sorted(
        report.findings,
        key=lambda f: (-f.severity.rank, str(f.workflow_path), f.line),
    )


def render(report: ScanReport) -> str:
    """Return the scan report as a standalone HTML document."""
    rules_by_id = {rule.rule_id: rule for rule in get_all_rules()}

    # OWASP CI/CD category distribution across the findings.
    owasp_counts: dict[OwaspCategory, int] = {}
    for finding in report.findings:
        rule = rules_by_id.get(finding.rule_id)
        if rule is not None:
            owasp_counts[rule.category] = owasp_counts.get(rule.category, 0) + 1

    template = _env.get_template("report.html.j2")
    return template.render(
        tool_version=__version__,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        report=report,
        rules_by_id=rules_by_id,
        severities=_SEVERITY_ORDER,
        findings=_sorted_findings(report),
        owasp_counts=sorted(owasp_counts.items(), key=lambda kv: kv[0].value),
    )
