"""Tests for the command-line interface."""

import json
from pathlib import Path

from click.testing import CliRunner

from actionaudit.cli import cli


def test_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "1.3.0" in result.output


def test_list_rules_shows_every_rule() -> None:
    result = CliRunner().invoke(cli, ["list-rules"])
    assert result.exit_code == 0
    assert "expression-injection-in-run" in result.output
    assert "hardcoded-secret" in result.output
    assert "13 rule(s)" in result.output


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
    assert payload["schema_version"] == "1.1"
    assert payload["summary"]["total"] >= 1


def test_scan_fail_on_triggers_exit_1(fixtures_dir: Path) -> None:
    target = fixtures_dir / "vulnerable" / "hardcoded_secret.yml"
    result = CliRunner().invoke(cli, ["scan", str(target), "--fail-on", "high"])
    assert result.exit_code == 1


def test_scan_education_profile_disables_set_x_rule(fixtures_dir: Path) -> None:
    target = fixtures_dir / "vulnerable" / "set_x.yml"
    result = CliRunner().invoke(
        cli,
        ["scan", str(target), "--profile", "education", "--format", "json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    assert "bash-with-set-x" not in rule_ids


def test_scan_baseline_suppresses_known_findings(
    fixtures_dir: Path, tmp_path: Path
) -> None:
    target = fixtures_dir / "vulnerable" / "expression_injection.yml"
    runner = CliRunner()
    # Capture the current findings as a baseline.
    first = runner.invoke(cli, ["scan", str(target), "--format", "json"])
    assert first.exit_code == 0
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(first.output, encoding="utf-8")

    # Re-run with --baseline: nothing new, so the report is empty.
    second = runner.invoke(
        cli,
        ["scan", str(target), "--format", "json", "--baseline", str(baseline_file)],
    )
    assert second.exit_code == 0
    payload = json.loads(second.output)
    assert payload["findings"] == []
