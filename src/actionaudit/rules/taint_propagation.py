"""Rule: untrusted input flows through env into a run step (lite taint analysis)."""

import re
from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_jobs, locate_in_run, value_position
from actionaudit.rules.base import Rule
from actionaudit.rules.expression_injection import UNTRUSTED_CONTEXTS

# Workflow inputs are operator/caller-controlled free text -- also untrusted.
_INPUT_CONTEXTS = ("inputs.", "github.event.inputs.")

# Commands that re-parse their argument as code; quoting does not make them safe.
_EVAL_CONTEXT = re.compile(r"\b(?:eval|bash\s+-c|sh\s+-c|python\s+-c|node\s+-e)\b")


def _value_carries_untrusted(value: Any) -> bool:
    """True if a YAML scalar references an untrusted context or a workflow input."""
    if not isinstance(value, str):
        return False
    return any(ctx in value for ctx in UNTRUSTED_CONTEXTS) or any(
        ctx in value for ctx in _INPUT_CONTEXTS
    )


def _tainted_names(env_block: Any) -> set[str]:
    """Return env-var names whose value pulls from an untrusted context/input."""
    if not isinstance(env_block, dict):
        return set()
    return {
        str(name)
        for name, value in env_block.items()
        if _value_carries_untrusted(value)
    }


def _dangerous_use_line(run: str, var: str) -> str | None:
    """Return the source line where ``var`` is used dangerously, or None.

    A use is dangerous when the variable is referenced unquoted (subject to
    word splitting / globbing) or anywhere inside an eval-style command (where
    even a quoted value is re-parsed as code). A purely double-quoted use
    outside an eval sink -- e.g. ``echo "title: $VAR"`` -- is considered safe.
    """
    eval_context = _EVAL_CONTEXT.search(run) is not None
    pattern = re.compile(r"\$\{" + re.escape(var) + r"\}|\$" + re.escape(var) + r"\b")
    for line in run.splitlines():
        for match in pattern.finditer(line):
            quoted = line[: match.start()].count('"') % 2 == 1
            if eval_context or not quoted:
                return line
    return None


class TaintPropagationViaEnvRule(Rule):
    """An env var carries untrusted input and a run step uses it dangerously.

    A lightweight one-hop taint analysis: it follows untrusted data through
    workflow-, job-, and step-level ``env`` blocks into shell variables in a
    ``run:`` script, and only reports a use that is actually risky (unquoted,
    or inside an eval-style command) -- safely quoted uses are not flagged.
    """

    rule_id = "taint-propagation-via-env"
    name = "Untrusted input reaches a run step through env"
    severity = Severity.MEDIUM
    category = OwaspCategory.PPE
    description = (
        "An env variable -- declared at workflow, job, or step level -- holds "
        "a value pulled from an untrusted context (github.event.pull_request.* "
        "and friends) or a workflow input, and a later run step references that "
        "variable in shell either unquoted or inside an eval-style command. "
        "The attacker-controlled value then reaches the shell as code, even "
        "though the raw ${{ ... }} expression never appears in the run block."
    )
    remediation = (
        'Quote every use of the variable ("$VAR") and never pass it to eval, '
        "bash -c, sh -c, or an unquoted expansion. Better, do not feed "
        "PR-controlled input or untrusted workflow inputs into env at all."
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

                for var in sorted(in_scope):
                    line_text = _dangerous_use_line(run, var)
                    if line_text is None:
                        continue
                    line = locate_in_run(step, line_text.strip())
                    if not line:
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
                            snippet=f"${var} (untrusted input used in shell)",
                            message=(
                                f"Env var '{var}' carries untrusted input and is "
                                "used unsafely (unquoted or in an eval) in this "
                                "run script."
                            ),
                            confidence="medium",
                        )
                    )
                    break  # one finding per step is enough
        return findings
