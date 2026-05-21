"""Rule: self-hosted runner used in a workflow with fork-accessible triggers."""

from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_jobs, value_position
from actionaudit.rules.base import Rule

# Triggers that a forked pull request can reach.
_FORK_TRIGGERS = frozenset({"pull_request", "pull_request_target"})


def _on_block(parsed: Any) -> Any:
    """Return the workflow's ``on:`` value, handling YAML's bare-``on`` quirk."""
    if "on" in parsed:
        return parsed["on"]
    if True in parsed:
        return parsed[True]
    return None


def _triggers(on_value: Any) -> set[str]:
    """Normalise an ``on:`` value (string / list / mapping) into a name set."""
    if isinstance(on_value, str):
        return {on_value}
    if isinstance(on_value, list):
        return {str(item) for item in on_value}
    if isinstance(on_value, dict):
        return {str(key) for key in on_value}
    return set()


def _is_self_hosted(runs_on: Any) -> bool:
    """True if ``runs-on`` targets the built-in self-hosted runner label."""
    if isinstance(runs_on, str):
        return runs_on == "self-hosted"
    if isinstance(runs_on, list):
        return any(str(item) == "self-hosted" for item in runs_on)
    return False


class SelfHostedRunnerRule(Rule):
    """Detect self-hosted runners in workflows reachable by forked PRs."""

    rule_id = "self-hosted-runner-fork-trigger"
    name = "Self-hosted runner reachable by fork pull requests"
    severity = Severity.MEDIUM
    category = OwaspCategory.SYSTEM_CONFIG
    description = (
        "A job runs on a self-hosted runner in a workflow triggered by "
        "pull_request or pull_request_target. Self-hosted runners are not "
        "ephemeral: code from a forked pull request executes on infrastructure "
        "you own, where it can persist state, reach the internal network, or "
        "compromise later jobs that run on the same machine."
    )
    remediation = (
        "Use GitHub-hosted runners for fork-accessible workflows, or gate the "
        "self-hosted job so untrusted pull requests cannot reach it -- for "
        "example require a manual approval or a protected environment."
    )
    references = [
        "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.is_valid:
            return findings
        if not (_triggers(_on_block(workflow.parsed)) & _FORK_TRIGGERS):
            return findings

        for job_name, job in iter_jobs(workflow):
            runs_on = job.get("runs-on")
            if not _is_self_hosted(runs_on):
                continue
            position = value_position(job, "runs-on")
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    workflow_path=workflow.path,
                    line=position[0] if position else 0,
                    job_name=str(job_name),
                    snippet=f"runs-on: {runs_on}",
                    message=(
                        "Self-hosted runner used in a job that a forked pull "
                        "request can trigger."
                    ),
                    confidence="medium",
                )
            )
        return findings
