"""Tests for CI/CD posture analysis."""

from pathlib import Path

from actionaudit.parser import parse_workflow
from actionaudit.posture import analyze_posture


def test_posture_counts_workflows_with_permissions(fixtures_dir: Path) -> None:
    # token_permissions.yml declares permissions; sample_workflow.yml does not.
    workflows = [
        parse_workflow(fixtures_dir / "safe" / "token_permissions.yml"),
        parse_workflow(fixtures_dir / "sample_workflow.yml"),
    ]
    posture = analyze_posture(workflows)
    assert posture.total_workflows == 2
    assert posture.workflows_with_permissions == 1


def test_posture_counts_pinned_third_party_actions(fixtures_dir: Path) -> None:
    # Both files use actions/checkout (trusted, excluded) plus one tj-actions
    # use -- pinned in one file, a mutable tag in the other.
    workflows = [
        parse_workflow(fixtures_dir / "safe" / "pinned_action.yml"),
        parse_workflow(fixtures_dir / "vulnerable" / "unpinned_action.yml"),
    ]
    posture = analyze_posture(workflows)
    assert posture.total_third_party_uses == 2
    assert posture.pinned_third_party_uses == 1


def test_posture_counts_pull_request_target(fixtures_dir: Path) -> None:
    workflows = [parse_workflow(fixtures_dir / "vulnerable" / "pwn_request.yml")]
    posture = analyze_posture(workflows)
    assert posture.pull_request_target_workflows == 1


def test_posture_empty_for_no_workflows() -> None:
    posture = analyze_posture([])
    assert posture.total_workflows == 0
    assert posture.total_third_party_uses == 0
