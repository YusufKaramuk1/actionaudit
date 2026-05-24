"""Tests for output reporters."""

import json
from pathlib import Path

from actionaudit.models import ScanReport
from actionaudit.reporters import github, html, json_reporter, sarif
from actionaudit.scanner import scan

# --- JSON reporter ---------------------------------------------------------


def test_json_reporter_produces_valid_json(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "expression_injection.yml")
    payload = json.loads(json_reporter.render(report))
    assert payload["schema_version"] == "1.1"
    assert payload["scan_metadata"]["tool"] == "actionaudit"
    assert payload["summary"]["total"] == len(payload["findings"])
    assert isinstance(payload["summary"]["score"], int)
    assert payload["summary"]["grade"] in ("A", "B", "C", "D", "F")
    rule_ids = {finding["rule_id"] for finding in payload["findings"]}
    assert "expression-injection-in-run" in rule_ids


def test_json_reporter_finding_has_expected_keys(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "hardcoded_secret.yml")
    payload = json.loads(json_reporter.render(report))
    finding = payload["findings"][0]
    for key in (
        "rule_id",
        "severity",
        "owasp_category",
        "workflow_path",
        "line",
        "column",
        "job_name",
        "step_index",
        "snippet",
        "message",
        "confidence",
    ):
        assert key in finding


def test_json_reporter_finding_carries_owasp_category(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "expression_injection.yml")
    payload = json.loads(json_reporter.render(report))
    injection = next(
        f for f in payload["findings"] if f["rule_id"] == "expression-injection-in-run"
    )
    assert injection["owasp_category"] == "CICD-SEC-4"


def test_json_reporter_empty_report() -> None:
    report = ScanReport(findings=[], scanned_files=[], skipped=[], duration_ms=0)
    payload = json.loads(json_reporter.render(report))
    assert payload["summary"]["total"] == 0
    assert payload["summary"]["overall_severity"] is None


def test_json_reporter_includes_posture(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "pwn_request.yml")
    payload = json.loads(json_reporter.render(report))
    assert payload["posture"]["total_workflows"] == 1
    assert payload["posture"]["pull_request_target_workflows"] == 1


# --- HTML reporter ---------------------------------------------------------


def test_html_reporter_produces_html_document(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "hardcoded_secret.yml")
    out = html.render(report)
    assert out.startswith("<!DOCTYPE html>")
    assert "ActionAudit Report" in out
    assert "hardcoded-secret" in out
    # The educational detail block must be present.
    assert "how to fix it" in out
    # OWASP category mapping must be surfaced.
    assert "OWASP CI/CD Top 10" in out
    assert "CICD-SEC" in out
    # The security score card must be present.
    assert "Security score" in out
    assert "Grade" in out
    # The CI/CD posture section must be present.
    assert "CI/CD posture" in out


def test_html_reporter_empty_report() -> None:
    report = ScanReport(findings=[], scanned_files=[], skipped=[], duration_ms=0)
    out = html.render(report)
    assert "No findings" in out


# --- SARIF reporter --------------------------------------------------------


def test_sarif_reporter_produces_valid_sarif(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "expression_injection.yml")
    payload = json.loads(sarif.render(report))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "ActionAudit"
    # Every rule must be described in the driver.
    assert len(run["tool"]["driver"]["rules"]) == 13
    assert len(run["results"]) == report.total_count


def test_sarif_result_has_location_and_level(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "expression_injection.yml")
    payload = json.loads(sarif.render(report))
    result = payload["runs"][0]["results"][0]
    assert result["ruleId"]
    assert result["level"] in ("error", "warning", "note")
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] >= 1
    assert region["startColumn"] >= 1


def test_sarif_rule_descriptor_carries_owasp_tags(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "expression_injection.yml")
    payload = json.loads(sarif.render(report))
    descriptors = payload["runs"][0]["tool"]["driver"]["rules"]
    for descriptor in descriptors:
        tags = descriptor["properties"]["tags"]
        assert any(tag.startswith("CICD-SEC-") for tag in tags)


def test_sarif_empty_report() -> None:
    report = ScanReport(findings=[], scanned_files=[], skipped=[], duration_ms=0)
    payload = json.loads(sarif.render(report))
    assert payload["runs"][0]["results"] == []
    assert len(payload["runs"][0]["tool"]["driver"]["rules"]) == 13


# --- GitHub annotations reporter -------------------------------------------


def test_github_reporter_emits_workflow_commands(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "expression_injection.yml")
    out = github.render(report)
    lines = out.splitlines()
    assert lines
    assert all(line.startswith(("::error ", "::warning ", "::notice ")) for line in lines)
    assert any("title=expression-injection-in-run" in line for line in lines)


def test_github_reporter_one_command_per_finding(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "expression_injection.yml")
    out = github.render(report)
    assert len(out.splitlines()) == report.total_count


def test_github_reporter_empty_report() -> None:
    report = ScanReport(findings=[], scanned_files=[], skipped=[], duration_ms=0)
    assert github.render(report) == ""
