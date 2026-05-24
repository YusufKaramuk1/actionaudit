"""Rule: workflow_run trigger consuming a lower-privileged workflow's artifacts."""

from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_steps, value_position, workflow_triggers
from actionaudit.rules.base import Rule


def _is_download_artifact(uses: Any) -> bool:
    return isinstance(uses, str) and (
        uses == "actions/download-artifact"
        or uses.startswith("actions/download-artifact@")
    )


class DangerousWorkflowRunChainRule(Rule):
    """Privileged ``workflow_run`` workflow that downloads an upstream artifact."""

    rule_id = "dangerous-workflow-run-chain"
    name = "workflow_run consuming another workflow's artifacts"
    severity = Severity.HIGH
    category = OwaspCategory.PPE
    description = (
        "The workflow is triggered by workflow_run and downloads artifacts "
        "produced by the upstream workflow. workflow_run always runs with the "
        "base repository's secrets and a privileged GITHUB_TOKEN -- even when "
        "the upstream workflow was triggered by a forked pull request. If the "
        "artifact contents are attacker-controlled (built from PR code), this "
        "chain hands attacker data to a privileged context and can lead to "
        "remote code execution."
    )
    remediation = (
        "Treat the downloaded artifact as untrusted: validate or sandbox its "
        "contents before using them. Better, restructure so the privileged "
        "step does not consume PR-built artifacts at all -- rebuild from a "
        "trusted source inside the workflow_run job."
    )
    references = [
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.is_valid:
            return findings
        if "workflow_run" not in workflow_triggers(workflow):
            return findings

        for job_name, step_index, step in iter_steps(workflow):
            uses = step.get("uses")
            if not _is_download_artifact(uses):
                continue
            position = value_position(step, "uses")
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    workflow_path=workflow.path,
                    line=position[0] if position else 0,
                    job_name=job_name,
                    step_index=step_index,
                    snippet=f"uses: {uses}",
                    message=(
                        "workflow_run workflow downloads an artifact from a "
                        "lower-privileged workflow into a privileged context."
                    ),
                    confidence="high",
                )
            )
        return findings
