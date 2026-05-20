"""Tests for the scan orchestrator."""

from pathlib import Path

from actionaudit.scanner import discover_workflows, scan


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
    assert report.total_count == 1
    assert report.scanned_files == [target]
    assert report.skipped == []
    assert report.overall_severity is not None
    assert report.overall_severity.value == "CRITICAL"


def test_scan_safe_file_reports_nothing(fixtures_dir: Path) -> None:
    report = scan(fixtures_dir / "safe" / "expression_injection.yml")
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
