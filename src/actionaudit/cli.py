"""Command-line interface for actionaudit."""

import sys
from collections.abc import Callable
from pathlib import Path

import click
from rich.console import Console

from actionaudit import __version__
from actionaudit.models import ScanReport, Severity
from actionaudit.reporters import html, json_reporter, sarif, terminal
from actionaudit.rules import get_all_rules
from actionaudit.scanner import scan as run_scan

# Renderers that produce a string (terminal writes to the console directly).
_RENDERERS: dict[str, Callable[[ScanReport], str]] = {
    "json": json_reporter.render,
    "html": html.render,
    "sarif": sarif.render,
}


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="actionaudit")
def cli() -> None:
    """ActionAudit: static security scanner for GitHub Actions workflows."""


@cli.command()
@click.argument(
    "path",
    type=click.Path(exists=True, path_type=Path),
    default=".",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json", "html", "sarif"], case_sensitive=False),
    default="terminal",
    help="Output format (default: terminal).",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write the report to a file instead of stdout.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Exit with code 1 when a finding at or above this severity exists.",
)
def scan(
    path: Path,
    output_format: str,
    output_path: Path | None,
    fail_on: str | None,
) -> None:
    """Scan PATH for GitHub Actions workflow security issues."""
    report = run_scan(path)
    fmt = output_format.lower()

    if fmt == "terminal":
        terminal.render(report)
    else:
        rendered = _RENDERERS[fmt](report)
        if output_path is not None:
            output_path.write_text(rendered, encoding="utf-8")
            click.echo(f"{fmt.upper()} report written to {output_path}")
        else:
            click.echo(rendered)

    if fail_on is not None:
        threshold = Severity[fail_on.upper()]
        if any(f.severity.rank >= threshold.rank for f in report.findings):
            sys.exit(1)


@cli.command(name="list-rules")
def list_rules() -> None:
    """List every available security rule."""
    rules = get_all_rules()
    id_width = max((len(rule.rule_id) for rule in rules), default=2)
    click.echo(f"{'ID':<{id_width}}  SEVERITY  OWASP        NAME")
    for rule in rules:
        click.echo(
            f"{rule.rule_id:<{id_width}}  {rule.severity.value:<8}  "
            f"{rule.category.value:<11}  {rule.name}"
        )
    click.echo(f"\n{len(rules)} rule(s)")


@cli.command()
@click.argument("rule_id")
def explain(rule_id: str) -> None:
    """Explain a rule in detail: description, remediation, references."""
    rules = {rule.rule_id: rule for rule in get_all_rules()}
    rule = rules.get(rule_id)
    if rule is None:
        click.echo(f"Unknown rule: {rule_id}", err=True)
        click.echo("Run 'actionaudit list-rules' to see available rules.", err=True)
        sys.exit(2)

    console = Console()
    console.print()
    console.rule(f"[bold]{rule.rule_id}[/bold]")
    console.print(f"[bold]{rule.name}[/bold]")
    console.print(f"Severity: {rule.severity.value}")
    console.print(f"OWASP CI/CD: {rule.category.label}\n")
    console.print("[bold]Description[/bold]")
    console.print(rule.description)
    console.print("\n[bold]Remediation[/bold]")
    console.print(rule.remediation)
    if rule.references:
        console.print("\n[bold]References[/bold]")
        for reference in rule.references:
            console.print(f"  - {reference}")
    console.print()


if __name__ == "__main__":
    cli()
