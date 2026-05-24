"""Tests for the scan orchestrator."""

import json
from pathlib import Path

from actionaudit.scanner import discover_workflows, load_baseline_fingerprints, scan


def test_discover_single_file(fixtures_dir: Path) -> None:
    target = fixtures_dir / "vulnerable" / "expression_injection.yml"
    assert discover_workflows(target) == [target]


def test_discover_directory(fixtures_dir: Path) -> None:
    found = discover_workflows(fixtures_dir / "vulnerable")
    assert all(p.suffix in (".yml", ".yaml") for p in found)
    assert any(p.name == "expression_injection.yml" for p in found)


def test_scan_vulnerable_file_reports_finding(fixtures_dir: Path) -> None:
    target = fixtures_dir / "vulnerable" / "expression_injection.yml"
    report = scan(target)
    rule_ids = {f.rule_id for f in report.findings}
    assert "expression-injection-in-run" in rule_ids
    assert report.scanned_files == [target]
    assert report.skipped == []
    assert report.overall_severity is not None
    assert report.overall_severity.value == "CRITICAL"


def test_scan_clean_file_reports_nothing(fixtures_dir: Path) -> None:
    # token_permissions.yml is clean across every rule.
    report = scan(fixtures_dir / "safe" / "token_permissions.yml")
    assert report.total_count == 0
    assert report.overall_severity is None


def test_scan_broken_file_is_skipped(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "broken.yml")
    assert report.scanned_files == []
    assert len(report.skipped) == 1


def test_scan_missing_path_returns_empty(tmp_path: Path) -> None:
    report = scan(tmp_path / "nope.yml")
    assert report.total_count == 0
    assert report.scanned_files == []


def test_scan_respects_inline_ignore(fixtures_dir: Path) -> None:
    # ignore_directive.yml has an expression injection plus an inline
    # `# actionaudit: ignore expression-injection-in-run` on the same line.
    report = scan(fixtures_dir / "ignore_directive.yml")
    rule_ids = {f.rule_id for f in report.findings}
    assert "expression-injection-in-run" not in rule_ids


def test_scan_loads_custom_rules_from_rules_dir(fixtures_dir: Path) -> None:
    # token_permissions.yml has a `run: echo "build"` step that the example
    # custom rule (custom-no-echo) flags.
    target = fixtures_dir / "safe" / "token_permissions.yml"
    report = scan(target, rules_dir=fixtures_dir / "custom_rules")
    rule_ids = {f.rule_id for f in report.findings}
    assert "custom-no-echo" in rule_ids


def test_scan_includes_posture(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "vulnerable")
    assert report.posture.total_workflows == len(report.scanned_files)
    assert report.posture.total_workflows > 0


def test_load_baseline_fingerprints_parses_json_report(tmp_path: Path) -> None:
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(
        json.dumps(
            {
                "findings": [
                    {"rule_id": "rule-a", "workflow_path": "w.yml", "line": 5},
                    {"rule_id": "rule-b", "workflow_path": "w.yml", "line": 10},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert load_baseline_fingerprints(baseline_file) == {
        ("rule-a", "w.yml", 5),
        ("rule-b", "w.yml", 10),
    }


def test_load_baseline_fingerprints_missing_file(tmp_path: Path) -> None:
    assert load_baseline_fingerprints(tmp_path / "nope.json") == set()


def test_scan_with_baseline_suppresses_known_findings(fixtures_dir: Path) -> None:
    target = fixtures_dir / "vulnerable" / "expression_injection.yml"
    initial = scan(target)
    assert initial.findings  # sanity: the fixture has findings
    baseline = {
        (f.rule_id, str(f.workflow_path), f.line) for f in initial.findings
    }
    rescan = scan(target, baseline=baseline)
    assert rescan.findings == []
