"""Terminal reporter: render a ScanReport to the console with rich."""

from rich.console import Console
from rich.text import Text

from actionaudit.models import Finding, OwaspCategory, ScanReport, Severity
from actionaudit.rules import get_all_rules

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def render(report: ScanReport, console: Console | None = None) -> None:
    """Print a human-readable scan report to the terminal."""
    console = console or Console()
    categories = {rule.rule_id: rule.category for rule in get_all_rules()}

    console.print()
    console.rule("[bold]ActionAudit[/bold]")

    for path, reason in report.skipped:
        console.print(Text(f"  skipped  {path} - {reason}", style="dim"))

    if report.findings:
        console.print()
        for finding in _sorted(report.findings):
            _render_finding(console, finding, categories)
    else:
        console.print(
            Text(
                f"\n  No findings. Scanned {len(report.scanned_files)} "
                "workflow file(s).\n",
                style="bold green",
            )
        )

    _render_summary(console, report)


def _sorted(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by file path and line."""
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, str(f.workflow_path), f.line),
    )


def _render_finding(
    console: Console, finding: Finding, categories: dict[str, OwaspCategory]
) -> None:
    header = Text("  ")
    header.append(
        f" {finding.severity.value} ", style=_SEVERITY_STYLE[finding.severity]
    )
    header.append(f"  {finding.workflow_path}:{finding.line}  ", style="bold")
    header.append(finding.rule_id, style="dim")
    console.print(header)

    meta: list[str] = []
    if finding.job_name:
        location = f"job: {finding.job_name}"
        if finding.step_index is not None:
            location += f", step: {finding.step_index}"
        meta.append(location)
    category = categories.get(finding.rule_id)
    if category is not None:
        meta.append(f"OWASP {category.value}")
    meta.append(f"confidence: {finding.confidence}")
    console.print(Text("    " + "  |  ".join(meta), style="dim"))

    if finding.snippet:
        console.print(Text(f"    {finding.snippet}", style="yellow"))
    console.print(Text(f"    {finding.message}"))
    console.print()


def _render_summary(console: Console, report: ScanReport) -> None:
    console.rule("[bold]Summary[/bold]")

    if report.findings:
        counts = Text("  ")
        for severity in _SEVERITY_ORDER:
            count = report.count(severity)
            if count:
                counts.append(
                    f" {severity.value}: {count} ",
                    style=_SEVERITY_STYLE[severity],
                )
                counts.append("  ")
        console.print(counts)

    console.print(
        Text(
            f"  Scanned {len(report.scanned_files)} file(s) "
            f"in {report.duration_ms} ms.",
            style="dim",
        )
    )

    overall = report.overall_severity
    if overall is not None:
        line = Text("  Overall severity: ")
        line.append(overall.value, style=_SEVERITY_STYLE[overall])
        console.print(line)
    console.print()
