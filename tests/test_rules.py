"""Tests for security rules."""

from pathlib import Path

from actionaudit.parser import parse_workflow
from actionaudit.rules import get_all_rules
from actionaudit.rules.bash_set_x import BashSetXRule
from actionaudit.rules.expression_injection import ExpressionInjectionRule
from actionaudit.rules.github_token_perms import GithubTokenPermissionsRule
from actionaudit.rules.hardcoded_secret import HardcodedSecretRule
from actionaudit.rules.inline_curl_pipe import InlineCurlPipeRule
from actionaudit.rules.persist_credentials import PersistCredentialsRule
from actionaudit.rules.pull_request_target import PullRequestTargetCheckoutRule
from actionaudit.rules.self_hosted_runner import SelfHostedRunnerRule
from actionaudit.rules.unpinned_action import UnpinnedActionRule
from actionaudit.rules.workflow_dispatch_input import WorkflowDispatchInputRule


def test_registry_discovers_all_rules() -> None:
    rule_ids = {rule.rule_id for rule in get_all_rules()}
    assert rule_ids == {
        "expression-injection-in-run",
        "pull-request-target-with-checkout",
        "github-token-write-all",
        "third-party-action-not-pinned-sha",
        "hardcoded-secret",
        "persist-credentials-default-true",
        "inline-curl-pipe-bash",
        "workflow-dispatch-input-injection",
        "bash-with-set-x",
        "self-hosted-runner-fork-trigger",
    }


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


# --- third-party-action-not-pinned-sha -------------------------------------


def test_unpinned_action_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "unpinned_action.yml")
    findings = UnpinnedActionRule().check(wf)
    # actions/checkout is a trusted owner; only tj-actions is flagged.
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "third-party-action-not-pinned-sha"
    assert finding.severity.value == "HIGH"
    # The tj-actions `uses:` is on line 11 of the fixture.
    assert finding.line == 11


def test_unpinned_action_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "pinned_action.yml")
    assert UnpinnedActionRule().check(wf) == []


def test_unpinned_action_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert UnpinnedActionRule().check(wf) == []


# --- hardcoded-secret ------------------------------------------------------


def test_hardcoded_secret_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "hardcoded_secret.yml")
    findings = HardcodedSecretRule().check(wf)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "hardcoded-secret"
    assert finding.severity.value == "HIGH"
    # The AWS key literal is on line 11 of the fixture.
    assert finding.line == 11
    # The snippet must never echo the full secret.
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.snippet


def test_hardcoded_secret_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "no_secret.yml")
    assert HardcodedSecretRule().check(wf) == []


def test_hardcoded_secret_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert HardcodedSecretRule().check(wf) == []


# --- persist-credentials-default-true --------------------------------------


def test_persist_credentials_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "persist_credentials.yml")
    findings = PersistCredentialsRule().check(wf)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "persist-credentials-default-true"
    assert finding.severity.value == "MEDIUM"
    # The actions/checkout `uses:` is on line 10 of the fixture.
    assert finding.line == 10
    assert finding.confidence == "low"


def test_persist_credentials_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "persist_credentials_safe.yml")
    assert PersistCredentialsRule().check(wf) == []


def test_persist_credentials_skips_without_token_use(fixtures_dir: Path) -> None:
    # pinned_action.yml checks out code but never uses the token, so the
    # heuristic should suppress the finding entirely.
    wf = parse_workflow(fixtures_dir / "safe" / "pinned_action.yml")
    assert PersistCredentialsRule().check(wf) == []


def test_persist_credentials_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert PersistCredentialsRule().check(wf) == []


# --- inline-curl-pipe-bash -------------------------------------------------


def test_curl_pipe_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "curl_pipe.yml")
    findings = InlineCurlPipeRule().check(wf)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "inline-curl-pipe-bash"
    assert finding.severity.value == "MEDIUM"
    # The curl | bash command is on line 10 of the fixture.
    assert finding.line == 10


def test_curl_pipe_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "curl_pipe_safe.yml")
    assert InlineCurlPipeRule().check(wf) == []


def test_curl_pipe_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert InlineCurlPipeRule().check(wf) == []


# --- workflow-dispatch-input-injection -------------------------------------


def test_dispatch_input_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "dispatch_input.yml")
    findings = WorkflowDispatchInputRule().check(wf)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "workflow-dispatch-input-injection"
    assert finding.severity.value == "HIGH"
    # The `${{ inputs.target }}` use is on line 16 of the fixture.
    assert finding.line == 16


def test_dispatch_input_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "dispatch_input_safe.yml")
    assert WorkflowDispatchInputRule().check(wf) == []


def test_dispatch_input_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert WorkflowDispatchInputRule().check(wf) == []


# --- bash-with-set-x -------------------------------------------------------


def test_set_x_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "set_x.yml")
    findings = BashSetXRule().check(wf)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "bash-with-set-x"
    assert finding.severity.value == "LOW"
    # `set -x` is on line 11 of the fixture (inside a block scalar).
    assert finding.line == 11


def test_set_x_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "set_x_safe.yml")
    assert BashSetXRule().check(wf) == []


def test_set_x_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert BashSetXRule().check(wf) == []


# --- self-hosted-runner-fork-trigger ---------------------------------------


def test_self_hosted_flags_vulnerable_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "vulnerable" / "self_hosted.yml")
    findings = SelfHostedRunnerRule().check(wf)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "self-hosted-runner-fork-trigger"
    assert finding.severity.value == "MEDIUM"
    # `runs-on: self-hosted` is on line 8 of the fixture.
    assert finding.line == 8


def test_self_hosted_ignores_safe_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "safe" / "self_hosted_safe.yml")
    assert SelfHostedRunnerRule().check(wf) == []


def test_self_hosted_survives_broken_yaml(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert SelfHostedRunnerRule().check(wf) == []
