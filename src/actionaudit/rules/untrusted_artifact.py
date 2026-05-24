"""Rule: a downloaded artifact is executed in the same job."""

import re
from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_jobs, value_position
from actionaudit.rules.base import Rule

# Heuristic patterns suggesting a script or binary is being executed.
_EXECUTE_PATTERN = re.compile(
    r"\b(?:chmod\s+\+x\s+\./|bash\s+\./|sh\s+\./|node\s+\./|python\s+\./)"
    r"|^\s*\./[\w./-]+",
    re.MULTILINE,
)


def _is_download_artifact(uses: Any) -> bool:
    return isinstance(uses, str) and (
        uses == "actions/download-artifact"
        or uses.startswith("actions/download-artifact@")
    )


class UntrustedArtifactExecutionRule(Rule):
    """A job downloads an artifact and a later step executes something from it."""

    rule_id = "untrusted-artifact-execution"
    name = "Downloaded artifact executed without verification"
    severity = Severity.HIGH
    category = OwaspCategory.DEPENDENCY_CHAIN
    description = (
        "A job downloads an artifact (actions/download-artifact) and then a "
        "later step executes a script or binary out of it. Artifacts can be "
        "produced by an earlier workflow run, including one triggered by a "
        "forked pull request, so the contents must be treated as untrusted. "
        "Running them directly hands code execution to whoever built the "
        "artifact."
    )
    remediation = (
        "Verify the artifact before executing anything from it (checksum or "
        "signature), or do not execute it at all -- inspect, repackage, or "
        "rebuild from a trusted source first."
    )
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.is_valid:
            return findings

        for job_name, job in iter_jobs(workflow):
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue

            download_index: int | None = None
            download_step: Any = None
            for index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                if _is_download_artifact(step.get("uses")):
                    download_index = index
                    download_step = step
                    continue
                if download_index is None:
                    continue
                run = step.get("run")
                if isinstance(run, str) and _EXECUTE_PATTERN.search(run):
                    position = value_position(download_step, "uses")
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            workflow_path=workflow.path,
                            line=position[0] if position else 0,
                            job_name=job_name,
                            step_index=download_index,
                            snippet=f"uses: {download_step.get('uses')}",
                            message=(
                                "Job downloads an artifact and a later step "
                                "executes a script or binary from it without "
                                "verification."
                            ),
                            confidence="medium",
                        )
                    )
                    break  # one finding per download per job is enough
        return findings
