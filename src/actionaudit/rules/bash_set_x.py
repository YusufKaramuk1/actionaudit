"""Rule: shell debug tracing (set -x) that can leak secrets into build logs."""

import re
from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_steps, locate_in_run
from actionaudit.rules.base import Rule

# `set -x`, `set -ex`, `set -eux` -- enables command tracing.
# `set +x` (which disables tracing) is intentionally not matched.
_SET_X = re.compile(r"\bset\s+-[a-z]*x\b")


class BashSetXRule(Rule):
    """Detect shell command tracing enabled inside run: steps."""

    rule_id = "bash-with-set-x"
    name = "Shell debug tracing enabled in run: block"
    severity = Severity.LOW
    category = OwaspCategory.LOGGING
    description = (
        "A run: step enables shell command tracing (set -x). With tracing on, "
        "the shell echoes every command -- including expanded secret values "
        "passed as arguments or environment variables -- into the build log, "
        "which may be visible to anyone with read access to the repository."
    )
    remediation = (
        "Remove set -x from the step, or scope tracing tightly: enable it only "
        "where needed and run set +x again before any command that handles a "
        "secret."
    )
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        for job_name, step_index, step in iter_steps(workflow):
            findings.extend(
                self._check_step(workflow, job_name, step_index, step)
            )
        return findings

    def _check_step(
        self, workflow: WorkflowFile, job_name: str, step_index: int, step: Any
    ) -> list[Finding]:
        run = step.get("run")
        if not isinstance(run, str):
            return []

        findings: list[Finding] = []
        for line in run.splitlines():
            match = _SET_X.search(line)
            if match is None:
                continue
            absolute_line = locate_in_run(step, match.group(0))
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    workflow_path=workflow.path,
                    line=absolute_line or 0,
                    job_name=job_name,
                    step_index=step_index,
                    snippet=match.group(0).strip(),
                    message=(
                        "Shell command tracing is enabled; expanded secret "
                        "values can be echoed into the build log."
                    ),
                    confidence="medium",
                )
            )
        return findings
