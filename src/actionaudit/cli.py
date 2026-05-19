"""Command-line interface for actionaudit."""

import click

from actionaudit import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="actionaudit")
def cli() -> None:
    """ActionAudit: static security scanner for GitHub Actions workflows."""


if __name__ == "__main__":
    cli()
