"""Tests for the command-line interface."""

from pathlib import Path

from click.testing import CliRunner

from actionaudit.cli import cli


def test_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.0.1" in result.output


def test_list_rules_shows_every_rule() -> None:
    result = CliRunner().invoke(cli, ["list-rules"])
    assert result.exit_code == 0
    assert "expression-injection-in-run" in result.output
    assert "hardcoded-secret" in result.output
    assert "6 rule(s)" in result.output


def test_explain_known_rule() -> None:
    result = CliRunner().invoke(cli, ["explain", "hardcoded-secret"])
    assert result.exit_code == 0
    assert "Remediation" in result.output
    assert "References" in result.output


def test_explain_unknown_rule_exits_with_2() -> None:
    result = CliRunner().invoke(cli, ["explain", "no-such-rule"])
    assert result.exit_code == 2
    assert "Unknown rule" in result.output


def test_scan_clean_directory_exits_0(tmp_path: Path) -> None:
    # An empty directory yields no workflows and no findings.
    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
