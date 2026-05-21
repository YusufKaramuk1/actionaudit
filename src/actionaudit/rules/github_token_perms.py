"""Rule: GITHUB_TOKEN granted write-all or left at default permissions."""

from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_jobs, value_position
from actionaudit.rules.base import Rule


class GithubTokenPermissionsRule(Rule):
    """Detect over-broad GITHUB_TOKEN permissions: an explicit ``write-all``,
    or no ``permissions:`` block at all (which inherits the repo default)."""

    rule_id = "github-token-write-all"
    name = "GITHUB_TOKEN with write-all or default permissions"
    severity = Severity.HIGH
    category = OwaspCategory.PBAC
    description = (
        "With permissions: write-all -- or with no permissions: block, which "
        "inherits the repository default -- the GITHUB_TOKEN issued to the "
        "workflow can read and write every API scope. If any step is "
        "compromised (malicious dependency, expression injection, etc.) the "
        "attacker inherits that access and can push commits, merge pull "
        "requests, close issues, or publish releases."
    )
    remediation = (
        "Declare an explicit, minimal permissions: block at workflow or job "
        "level and grant only the scopes actually needed:\n"
        "  permissions:\n"
        "    contents: read\n"
        "    pull-requests: write"
    )
    references = [
        "https://docs.github.com/en/actions/security-guides/automatic-token-authentication",
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.is_valid:
            return findings
        parsed = workflow.parsed

        root_perms = parsed.get("permissions")
        if root_perms == "write-all":
            findings.append(self._write_all_finding(workflow, parsed, None))

        job_perms_flags: list[bool] = []
        for job_name, job in iter_jobs(workflow):
            job_perms = job.get("permissions")
            job_perms_flags.append(job_perms is not None)
            if job_perms == "write-all":
                findings.append(self._write_all_finding(workflow, job, job_name))

        # No workflow-level permissions and at least one job also lacks one:
        # the token scope is left to the repository default.
        if root_perms is None and (not job_perms_flags or not all(job_perms_flags)):
            findings.append(self._missing_finding(workflow))
        return findings

    def _write_all_finding(
        self, workflow: WorkflowFile, node: Any, job_name: str | None
    ) -> Finding:
        position = value_position(node, "permissions")
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            workflow_path=workflow.path,
            line=position[0] if position else 0,
            job_name=job_name,
            snippet="permissions: write-all",
            message=(
                "permissions: write-all grants the GITHUB_TOKEN full read/write "
                "access to every scope; a compromised step can push code, merge "
                "pull requests, or publish releases."
            ),
            confidence="high",
        )

    def _missing_finding(self, workflow: WorkflowFile) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            workflow_path=workflow.path,
            line=1,
            snippet="(no permissions: block)",
            message=(
                "No explicit permissions: block; the GITHUB_TOKEN scope falls "
                "back to the repository default, which is often read/write for "
                "all scopes. Declare a minimal permissions: block."
            ),
            confidence="medium",
        )
