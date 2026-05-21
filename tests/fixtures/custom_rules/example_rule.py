"""Example custom rule, used by the BYOR (--rules-dir) tests.

It demonstrates the contract: subclass Rule, set the class attributes, and
implement check(). A real organisation might enforce an internal policy here.
"""

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_steps
from actionaudit.rules.base import Rule


class ForbidEchoRule(Rule):
    """Example policy: this organisation forbids `echo` in run steps."""

    rule_id = "custom-no-echo"
    name = "Custom: echo command is forbidden"
    severity = Severity.LOW
    category = OwaspCategory.FLOW_CONTROL
    description = "An example custom rule loaded via --rules-dir."
    remediation = "Remove the echo command from the run step."
    references = []

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        for job_name, step_index, step in iter_steps(workflow):
            run = step.get("run")
            if isinstance(run, str) and "echo" in run:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        workflow_path=workflow.path,
                        line=0,
                        job_name=job_name,
                        step_index=step_index,
                        message="echo is forbidden by organisation policy.",
                    )
                )
        return findings
