"""Rule: untrusted input flows through env into a run step (lite taint analysis)."""

import re
from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_jobs, locate_in_run, value_position
from actionaudit.rules.base import Rule
from actionaudit.rules.expression_injection import UNTRUSTED_CONTEXTS

# Shell variable references: $VAR or ${VAR}.
_SHELL_VAR = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)


def _value_carries_untrusted(value: Any) -> bool:
    """True if a YAML scalar references any untrusted context expression."""
    return isinstance(value, str) and any(ctx in value for ctx in UNTRUSTED_CONTEXTS)


def _tainted_names(env_block: Any) -> set[str]:
    """Return env-var names whose value pulls from an untrusted context."""
    if not isinstance(env_block, dict):
        return set()
    return {
        str(name)
        for name, value in env_block.items()
        if _value_carries_untrusted(value)
    }


def _shell_vars_used(run: str) -> set[str]:
    """Return the names of all shell variables referenced in ``run``."""
    return {match.group(1) or match.group(2) for match in _SHELL_VAR.finditer(run)}


class TaintPropagationViaEnvRule(Rule):
    """An env var carries untrusted input and a run step references it.

    This is a lightweight one-hop taint analysis: it follows untrusted data
    through workflow-, job-, and step-level ``env`` blocks into shell
    variables consumed by a ``run:`` script, catching injections that direct
    pattern matching misses.
    """

    rule_id = "taint-propagation-via-env"
    name = "Untrusted input reaches a run step through env"
    severity = Severity.MEDIUM
    category = OwaspCategory.PPE
    description = (
        "An env variable -- declared at workflow, job, or step level -- holds "
        "a value pulled from an untrusted context (github.event.pull_request.* "
        "and friends), and a later run step in the same job references that "
        "variable in shell. Even when the run step does not interpolate the "
        "raw ${{ ... }} expression directly, the value still reaches the "
        "shell; if it is not safely quoted, attacker-controlled input becomes "
        "attacker-controlled shell."
    )
    remediation = (
        'Treat the variable as untrusted in the shell: quote every use ("$VAR") '
        "and never pass it to bash -c, eval, or an unquoted expansion. "
        "Better, do not feed PR-controlled input into env at all -- look the "
        "value up from a trusted store inside the workflow."
    )
    references = [
        "https://securitylab.github.com/research/github-actions-untrusted-input/",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.is_valid:
            return findings

        workflow_taint = _tainted_names(workflow.parsed.get("env"))

        for job_name, job in iter_jobs(workflow):
            job_taint = workflow_taint | _tainted_names(job.get("env"))
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for step_index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                in_scope = job_taint | _tainted_names(step.get("env"))
                if not in_scope:
                    continue
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                used_tainted = in_scope & _shell_vars_used(run)
                if not used_tainted:
                    continue

                var = sorted(used_tainted)[0]
                line = (
                    locate_in_run(step, f"${var}")
                    or locate_in_run(step, "${" + var + "}")
                    or 0
                )
                if line == 0:
                    position = value_position(step, "run")
                    line = position[0] if position else 0

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        workflow_path=workflow.path,
                        line=line,
                        job_name=job_name,
                        step_index=step_index,
                        snippet=f"${var} (carries untrusted input)",
                        message=(
                            f"Env var '{var}' carries untrusted input and is "
                            "referenced in this run script."
                        ),
                        confidence="medium",
                    )
                )
        return findings
