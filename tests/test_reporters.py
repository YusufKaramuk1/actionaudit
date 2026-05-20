"""Tests for output reporters."""

import json
from pathlib import Path

from actionaudit.models import ScanReport
from actionaudit.reporters import json_reporter
from actionaudit.scanner import scan


def test_json_reporter_produces_valid_json(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "expression_injection.yml")
    payload = json.loads(json_reporter.render(report))
    assert payload["schema_version"] == "1.0"
    assert payload["scan_metadata"]["tool"] == "actionaudit"
    assert payload["summary"]["total"] == len(payload["findings"])
    rule_ids = {finding["rule_id"] for finding in payload["findings"]}
    assert "expression-injection-in-run" in rule_ids


def test_json_reporter_finding_has_expected_keys(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable" / "hardcoded_secret.yml")
    payload = json.loads(json_reporter.render(report))
    finding = payload["findings"][0]
    for key in (
        "rule_id",
        "severity",
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


def test_json_reporter_empty_report() -> None:
    report = ScanReport(findings=[], scanned_files=[], skipped=[], duration_ms=0)
    payload = json.loads(json_reporter.render(report))
    assert payload["summary"]["total"] == 0
    assert payload["summary"]["overall_severity"] is None
