"""Rule: actions/checkout persists the GITHUB_TOKEN in .git/config by default."""

import re
from typing import Any

from actionaudit.models import Finding, Severity, WorkflowFile
from actionaudit.parser import value_position
from actionaudit.rules.base import Rule

# Substrings that indicate the workflow actually consumes the GITHUB_TOKEN.
_TOKEN_USE_SUBSTRINGS: tuple[str, ...] = (
    "git push",
    "git remote",
    "GITHUB_TOKEN",
    "secrets.GITHUB_TOKEN",
    "github.token",
)

# The GitHub CLI (`gh <command>`) also consumes the token.
_GH_CLI = re.compile(r"\bgh\s")


def _uses_token(raw_text: str) -> bool:
    """Heuristic: does the workflow do anything that relies on the token?"""
    if any(substring in raw_text for substring in _TOKEN_USE_SUBSTRINGS):
        return True
    return _GH_CLI.search(raw_text) is not None


class PersistCredentialsRule(Rule):
    """Flag actions/checkout steps that keep the default credential
    persistence in a workflow that actually uses the token."""

    rule_id = "persist-credentials-default-true"
    name = "actions/checkout persists credentials by default"
    severity = Severity.MEDIUM
    description = (
        "actions/checkout writes the GITHUB_TOKEN into the local .git/config "
        "by default (persist-credentials defaults to true). Any later step in "
        "the same job can then read that token from disk or leak it into "
        "logs. This workflow uses the token (git push, gh CLI, or a "
        "GITHUB_TOKEN reference), so the persisted credential is a real "
        "exposure surface."
    )
    remediation = (
        "If the job does not need to push back to the repository using the "
        "checkout token, disable credential persistence explicitly:\n"
        "  - uses: actions/checkout@v4\n"
        "    with:\n"
        "      persist-credentials: false"
    )
    references = [
        "https://github.com/actions/checkout#usage",
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.is_valid:
            return findings
        # Heuristic gate: the default is only worth flagging when the workflow
        # actually relies on the token somewhere.
        if not _uses_token(workflow.raw_text):
            return findings

        jobs = workflow.parsed.get("jobs")
        if not isinstance(jobs, dict):
            return findings

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for step_index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                finding = self._check_checkout(workflow, str(job_name), step_index, step)
                if finding is not None:
                    findings.append(finding)
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
        if isinstance(with_block, dict) and with_block.get("persist-credentials") is False:
            return None  # explicitly disabled -- safe

        position = value_position(step, "uses")
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            workflow_path=workflow.path,
            line=position[0] if position else 0,
            job_name=job_name,
            step_index=step_index,
            snippet=f"uses: {uses}",
            message=(
                "actions/checkout persists the GITHUB_TOKEN in .git/config by "
                "default; a later step in this token-using workflow could read "
                "or leak it. Set persist-credentials: false unless needed."
            ),
            confidence="low",
        )
