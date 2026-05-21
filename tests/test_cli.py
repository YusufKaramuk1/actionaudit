"""Tests for the command-line interface."""

import json
from pathlib import Path

from click.testing import CliRunner

from actionaudit.cli import cli


def test_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.3.0" in result.output


def test_list_rules_shows_every_rule() -> None:
    result = CliRunner().invoke(cli, ["list-rules"])
    assert result.exit_code == 0
    assert "expression-injection-in-run" in result.output
    assert "hardcoded-secret" in result.output
    assert "10 rule(s)" in result.output


def test_explain_known_rule() -> None:
    result = CliRunner().invoke(cli, ["explain", "hardcoded-secret"])
    assert result.exit_code == 0
    assert "Remediation" in result.output
    assert "References" in result.output
    assert "CICD-SEC" in result.output


def test_explain_unknown_rule_exits_with_2() -> None:
    result = CliRunner().invoke(cli, ["explain", "no-such-rule"])
    assert result.exit_code == 2
    assert "Unknown rule" in result.output


def test_scan_clean_directory_exits_0(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_scan_json_format(fixtures_dir: Path) -> None:
    target = fixtures_dir / "vulnerable" / "hardcoded_secret.yml"
    result = CliRunner().invoke(cli, ["scan", str(target), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1.0"
    assert payload["summary"]["total"] >= 1


def test_scan_fail_on_triggers_exit_1(fixtures_dir: Path) -> None:
    target = fixtures_dir / "vulnerable" / "hardcoded_secret.yml"
    result = CliRunner().invoke(cli, ["scan", str(target), "--fail-on", "high"])
    assert result.exit_code == 1
