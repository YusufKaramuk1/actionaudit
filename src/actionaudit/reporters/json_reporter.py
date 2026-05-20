"""JSON reporter: serialize a ScanReport to a stable, automation-friendly JSON."""

import json
from datetime import datetime, timezone
from typing import Any

from actionaudit import __version__
from actionaudit.models import Finding, ScanReport, Severity
from actionaudit.rules import get_all_rules

SCHEMA_VERSION = "1.0"


def _finding_dict(finding: Finding, categories: dict[str, str]) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "owasp_category": categories.get(finding.rule_id),
        "workflow_path": str(finding.workflow_path),
        "line": finding.line,
        "column": finding.column,
        "job_name": finding.job_name,
        "step_index": finding.step_index,
        "snippet": finding.snippet,
        "message": finding.message,
        "confidence": finding.confidence,
    }


def render(report: ScanReport) -> str:
    """Return the scan report as a pretty-printed JSON string."""
    categories = {rule.rule_id: rule.category.value for rule in get_all_rules()}
    overall = report.overall_severity
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scan_metadata": {
            "tool": "actionaudit",
            "tool_version": __version__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": report.duration_ms,
            "scanned_files": [str(path) for path in report.scanned_files],
            "skipped_files": [
                {"path": str(path), "reason": reason}
                for path, reason in report.skipped
            ],
        },
        "summary": {
            "total": report.total_count,
            "critical": report.count(Severity.CRITICAL),
            "high": report.count(Severity.HIGH),
            "medium": report.count(Severity.MEDIUM),
            "low": report.count(Severity.LOW),
            "info": report.count(Severity.INFO),
            "overall_severity": overall.value if overall is not None else None,
        },
        "findings": [_finding_dict(finding, categories) for finding in report.findings],
    }
    return json.dumps(payload, indent=2)
