"""Rule: third-party actions referenced by mutable tag instead of pinned SHA."""

import re
from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import value_position
from actionaudit.rules.base import Rule

# A pinned reference is a full 40-character lowercase hex commit SHA.
_FULL_SHA = re.compile(r"[0-9a-f]{40}")

# First-party owners maintained by GitHub itself -- treated as trusted.
_TRUSTED_OWNERS: frozenset[str] = frozenset({"actions", "github"})


class UnpinnedActionRule(Rule):
    """Detect third-party actions pinned to a mutable tag/branch rather than
    an immutable commit SHA."""

    rule_id = "third-party-action-not-pinned-sha"
    name = "Third-party action not pinned to a commit SHA"
    severity = Severity.HIGH
    category = OwaspCategory.DEPENDENCY_CHAIN
    description = (
        "A third-party action is referenced by a mutable Git tag or branch "
        "(@v4, @main) rather than an immutable commit SHA. Tags can be moved "
        "to point at new code; the March 2025 tj-actions/changed-files supply "
        "chain attack re-pointed version tags at malicious commits and "
        "compromised over 23,000 repositories."
    )
    remediation = (
        "Pin third-party actions to a full 40-character commit SHA and keep "
        "the human-readable version in a trailing comment:\n"
        "  - uses: owner/action@<full-sha>  # v4.5.2"
    )
    references = [
        "https://www.stepsecurity.io/blog/pinning-github-actions-for-enhanced-security-a-complete-guide",
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.is_valid:
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
                finding = self._check_step(workflow, str(job_name), step_index, step)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _check_step(
        self, workflow: WorkflowFile, job_name: str, step_index: int, step: Any
    ) -> Finding | None:
        uses = step.get("uses")
        if not isinstance(uses, str):
            return None
        # Local actions and Docker references are out of scope for SHA pinning.
        if uses.startswith(("./", "docker://")):
            return None
        if "@" not in uses:
            return None

        action, _, ref = uses.partition("@")
        owner = action.split("/", 1)[0]
        if owner in _TRUSTED_OWNERS:
            return None
        if _FULL_SHA.fullmatch(ref):
            return None

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
                f"Third-party action '{action}' is pinned to the mutable ref "
                f"'{ref}' instead of a full commit SHA."
            ),
            confidence="high",
        )
