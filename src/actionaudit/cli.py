"""Command-line interface for actionaudit."""

import sys
from pathlib import Path

import click

from actionaudit import __version__
from actionaudit.models import Severity
from actionaudit.reporters import terminal
from actionaudit.scanner import scan as run_scan


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
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Exit with code 1 when a finding at or above this severity exists.",
)
def scan(path: Path, fail_on: str | None) -> None:
    """Scan PATH for GitHub Actions workflow security issues."""
    report = run_scan(path)
    terminal.render(report)

    if fail_on is not None:
        threshold = Severity[fail_on.upper()]
        if any(f.severity.rank >= threshold.rank for f in report.findings):
            sys.exit(1)


if __name__ == "__main__":
    cli()
