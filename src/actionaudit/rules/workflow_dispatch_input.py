"""Rule: workflow_dispatch / workflow_call inputs interpolated into run:."""

import re
from typing import Any

from actionaudit.models import Finding, Severity, WorkflowFile
from actionaudit.parser import locate_in_run
from actionaudit.rules.base import Rule

# Matches a ${{ ... }} expression; DOTALL so it can span multiple lines.
_EXPRESSION = re.compile(r"\$\{\{(.+?)\}\}", re.DOTALL)

# Input contexts supplied as free-form text by whoever triggers the workflow
# (workflow_dispatch) or by the calling workflow (workflow_call).
_INPUT_PREFIXES = ("inputs.", "github.event.inputs.")


class WorkflowDispatchInputRule(Rule):
    """Detect workflow inputs interpolated directly into ``run:`` scripts."""

    rule_id = "workflow-dispatch-input-injection"
    name = "Workflow input interpolated into run: block"
    severity = Severity.HIGH
    description = (
        "A workflow_dispatch or workflow_call input is interpolated directly "
        "into a run: shell script. Inputs are free-form text supplied by "
        "whoever triggers the workflow, or by the calling workflow; the value "
        "is substituted before the shell runs, so a crafted input can inject "
        "arbitrary shell commands."
    )
    remediation = (
        "Pass the input through an environment variable instead of "
        "interpolating it into the script:\n"
        "  - env:\n"
        "      USER_INPUT: ${{ inputs.target }}\n"
        '    run: echo "$USER_INPUT"'
    )
    references = [
        "https://securitylab.github.com/research/github-actions-untrusted-input/",
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
                findings.extend(
                    self._check_step(workflow, str(job_name), step_index, step)
                )
        return findings

    def _check_step(
        self, workflow: WorkflowFile, job_name: str, step_index: int, step: Any
    ) -> list[Finding]:
        run = step.get("run")
        if not isinstance(run, str):
            return []

        findings: list[Finding] = []
        for match in _EXPRESSION.finditer(run):
            inner = match.group(1).strip()
            if not any(prefix in inner for prefix in _INPUT_PREFIXES):
                continue
            needle = match.group(0).splitlines()[0]
            line = locate_in_run(step, needle)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    workflow_path=workflow.path,
                    line=line or 0,
                    job_name=job_name,
                    step_index=step_index,
                    snippet=f"${{{{ {inner} }}}}",
                    message=(
                        "A workflow input is interpolated into a run: script "
                        "and can lead to shell command injection."
                    ),
                    confidence="high",
                )
            )
        return findings
