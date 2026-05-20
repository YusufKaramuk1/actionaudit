"""Rule: pull_request_target trigger combined with PR head checkout (Pwn Request)."""

from typing import Any

from actionaudit.models import Finding, Severity, WorkflowFile
from actionaudit.parser import value_position
from actionaudit.rules.base import Rule

# Context fields that resolve to attacker-controlled PR head code or refs.
_PR_HEAD_REFS: tuple[str, ...] = (
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.repo",
    "github.head_ref",
)


def _on_block(parsed: Any) -> Any:
    """Return the workflow's ``on:`` value, handling YAML's bare-``on`` quirk.

    In YAML 1.1 an unquoted ``on`` key parses as the boolean ``True``. ruamel
    uses YAML 1.2 (so it stays the string ``"on"``), but we check both keys to
    stay robust.
    """
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


class PullRequestTargetCheckoutRule(Rule):
    """Detect the Pwn Request pattern: a privileged ``pull_request_target``
    workflow that checks out (or otherwise consumes) attacker PR head code."""

    rule_id = "pull-request-target-with-checkout"
    name = "Pwn Request: pull_request_target with PR head checkout"
    severity = Severity.CRITICAL
    description = (
        "The workflow is triggered by pull_request_target, which runs with the "
        "base repository's secrets and a read/write GITHUB_TOKEN -- even for "
        "forked pull requests. When such a workflow also checks out the PR's "
        "head ref/sha, attacker-controlled code runs in this privileged "
        "context, allowing full repository compromise (the 'Pwn Request')."
    )
    remediation = (
        "Either switch the trigger to pull_request (which runs without secrets "
        "for forks), or keep pull_request_target but never check out PR head "
        "code -- check out the base commit instead:\n"
        "  - uses: actions/checkout@v4\n"
        "    with:\n"
        "      ref: ${{ github.event.pull_request.base.sha }}"
    )
    references = [
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.is_valid:
            return findings
        if "pull_request_target" not in _triggers(_on_block(workflow.parsed)):
            return findings

        jobs = workflow.parsed.get("jobs")
        if isinstance(jobs, dict):
            for job_name, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                steps = job.get("steps")
                if not isinstance(steps, list):
                    continue
                for step_index, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue
                    finding = self._check_checkout(
                        workflow, str(job_name), step_index, step
                    )
                    if finding is not None:
                        findings.append(finding)

        # No explicit PR-head checkout, but the workflow still touches PR head
        # context somewhere -- flag at lower confidence for manual review.
        if not findings and self._references_pr_head(workflow.raw_text):
            findings.append(self._workflow_level_finding(workflow))
        return findings

    def _check_checkout(
        self, workflow: WorkflowFile, job_name: str, step_index: int, step: Any
    ) -> Finding | None:
        uses = step.get("uses")
        if not isinstance(uses, str):
            return None
        if uses != "actions/checkout" and not uses.startswith("actions/checkout@"):
            return None
        with_block = step.get("with")
        if not isinstance(with_block, dict):
            return None
        ref = with_block.get("ref")
        if not isinstance(ref, str):
            return None
        if not any(head_ref in ref for head_ref in _PR_HEAD_REFS):
            return None

        position = value_position(step, "uses")
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            workflow_path=workflow.path,
            line=position[0] if position else 0,
            job_name=job_name,
            step_index=step_index,
            snippet=f"uses: {uses} (with.ref: {ref})",
            message=(
                "pull_request_target workflow checks out attacker-controlled "
                "PR head code, enabling repository compromise."
            ),
            confidence="high",
        )

    def _workflow_level_finding(self, workflow: WorkflowFile) -> Finding:
        position = None
        for key in ("on", True):
            position = value_position(workflow.parsed, key)
            if position is not None:
                break
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            workflow_path=workflow.path,
            line=position[0] if position else 0,
            snippet="on: pull_request_target",
            message=(
                "pull_request_target workflow references attacker-controlled "
                "PR head context; review whether untrusted code can run."
            ),
            confidence="medium",
        )

    @staticmethod
    def _references_pr_head(raw_text: str) -> bool:
        return any(head_ref in raw_text for head_ref in _PR_HEAD_REFS)
