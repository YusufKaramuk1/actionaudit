"""SARIF v2.1.0 reporter for GitHub Code Scanning integration."""

import json
from typing import Any

from actionaudit import __version__
from actionaudit.models import Finding, ScanReport, Severity
from actionaudit.rules import get_all_rules
from actionaudit.rules.base import Rule

_INFORMATION_URI = "https://github.com/YusufKaramuk1/actionaudit"

# SARIF only defines error / warning / note; map our five severities onto them.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rule_descriptor(rule: Rule) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "id": rule.rule_id,
        "name": rule.name,
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.remediation},
        "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
        # Tags surface in GitHub Code Scanning as filterable labels.
        "properties": {"tags": [rule.category.value], "owasp": rule.category.label},
    }
    if rule.references:
        descriptor["helpUri"] = rule.references[0]
    return descriptor


def _result(finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.workflow_path.as_posix()},
                    "region": {
                        "startLine": max(finding.line, 1),
                        "startColumn": finding.column + 1,
                    },
                }
            }
        ],
    }
    index = rule_index.get(finding.rule_id)
    if index is not None:
        result["ruleIndex"] = index
    return result


def render(report: ScanReport) -> str:
    """Return the scan report as a SARIF v2.1.0 JSON string."""
    rules = get_all_rules()
    rule_index = {rule.rule_id: i for i, rule in enumerate(rules)}

    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ActionAudit",
                        "version": __version__,
                        "informationUri": _INFORMATION_URI,
                        "rules": [_rule_descriptor(rule) for rule in rules],
                    }
                },
                "results": [
                    _result(finding, rule_index) for finding in report.findings
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)
