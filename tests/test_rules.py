"""Tests for security rules."""

from pathlib import Path

from actionaudit.parser import parse_workflow
from actionaudit.rules import get_all_rules
from actionaudit.rules.expression_injection import ExpressionInjectionRule
from actionaudit.rules.github_token_perms import GithubTokenPermissionsRule
from actionaudit.rules.pull_request_target import PullRequestTargetCheckoutRule


def test_registry_discovers_all_rules() -> None:
    rule_ids = {rule.rule_id for rule in get_all_rules()}
    assert "expression-injection-in-run" in rule_ids
    assert "pull-request-target-with-checkout" in rule_ids
    assert "github-token-write-all" in rule_ids


# --- expression-injection-in-run -------------------------------------------


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
    assert ExpressionInjectionRule().check(wf) == []


def test_expression_injection_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert ExpressionInjectionRule().check(wf) == []


# --- pull-request-target-with-checkout -------------------------------------


def test_pwn_request_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "pwn_request.yml")
    findings = PullRequestTargetCheckoutRule().check(wf)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "pull-request-target-with-checkout"
    assert finding.severity.value == "CRITICAL"
    # The actions/checkout `uses:` is on line 10 of the fixture.
    assert finding.line == 10
    assert finding.confidence == "high"


def test_pwn_request_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "pwn_request.yml")
    assert PullRequestTargetCheckoutRule().check(wf) == []


def test_pwn_request_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert PullRequestTargetCheckoutRule().check(wf) == []


# --- github-token-write-all ------------------------------------------------


def test_token_write_all_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "token_write_all.yml")
    findings = GithubTokenPermissionsRule().check(wf)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "github-token-write-all"
    assert finding.severity.value == "HIGH"
    # `permissions: write-all` is on line 3 of the fixture.
    assert finding.line == 3
    assert finding.confidence == "high"


def test_token_permissions_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "token_permissions.yml")
    assert GithubTokenPermissionsRule().check(wf) == []


def test_token_permissions_flags_missing_block(fixtures_dir: Path) -> None:
    # sample_workflow.yml declares no permissions: block at all.
    wf = parse_workflow(fixtures_dir / "sample_workflow.yml")
    findings = GithubTokenPermissionsRule().check(wf)
    assert len(findings) == 1
    assert findings[0].confidence == "medium"


def test_token_permissions_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert GithubTokenPermissionsRule().check(wf) == []
