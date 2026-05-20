"""Tests for security rules."""

from pathlib import Path

from actionaudit.parser import parse_workflow
from actionaudit.rules import get_all_rules
from actionaudit.rules.expression_injection import ExpressionInjectionRule


def test_registry_discovers_expression_injection() -> None:
    rule_ids = {rule.rule_id for rule in get_all_rules()}
    assert "expression-injection-in-run" in rule_ids


def test_expression_injection_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "expression_injection.yml")
    findings = ExpressionInjectionRule().check(wf)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "expression-injection-in-run"
    assert finding.severity.value == "CRITICAL"
    # The injection sits inside a block scalar on line 13 of the fixture.
    assert finding.line == 13
    assert finding.job_name == "build"
    assert finding.step_index == 1


def test_expression_injection_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "expression_injection.yml")
    findings = ExpressionInjectionRule().check(wf)
    assert findings == []


def test_expression_injection_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert ExpressionInjectionRule().check(wf) == []
