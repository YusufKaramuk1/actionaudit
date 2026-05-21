"""Tests for data-model behaviour (ScanReport scoring)."""

from pathlib import Path

from actionaudit.models import Finding, ScanReport, Severity


def _report(*severities: Severity) -> ScanReport:
    findings = [
        Finding(
            rule_id="rule",
            severity=severity,
            workflow_path=Path("w.yml"),
            line=1,
            message="m",
        )
        for severity in severities
    ]
    return ScanReport(
        findings=findings, scanned_files=[], skipped=[], duration_ms=0
    )


def test_score_is_perfect_without_findings() -> None:
    report = _report()
    assert report.score == 100
    assert report.grade == "A"


def test_score_applies_severity_weighted_penalty() -> None:
    # 100 - 25 (critical) - 15 (high) = 60
    report = _report(Severity.CRITICAL, Severity.HIGH)
    assert report.score == 60
    assert report.grade == "C"


def test_score_is_clamped_at_zero() -> None:
    report = _report(*([Severity.CRITICAL] * 10))
    assert report.score == 0
    assert report.grade == "F"


def test_grade_boundaries() -> None:
    assert _report().grade == "A"  # 100
    assert _report(Severity.LOW).grade == "A"  # 98
    assert _report(Severity.HIGH).grade == "B"  # 85
    assert _report(Severity.HIGH, Severity.HIGH).grade == "C"  # 70
    assert _report(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM).grade == "D"  # 53
