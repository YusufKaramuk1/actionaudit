"""Rule: untrusted GitHub Actions expressions interpolated into run: scripts."""

import re
from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_steps, locate_in_run
from actionaudit.rules.base import Rule

# Matches a ${{ ... }} expression; DOTALL so it can span multiple lines.
_EXPRESSION = re.compile(r"\$\{\{(.+?)\}\}", re.DOTALL)

# Attacker-controllable context fields. If any of these appears inside a
# ${{ ... }} expression in a run: script, an attacker can inject shell code.
# Sourced from GitHub Security Lab's untrusted-input guidance.
UNTRUSTED_CONTEXTS: tuple[str, ...] = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.pages",
    "github.head_ref",
)


class ExpressionInjectionRule(Rule):
    """Detect attacker-controllable expressions used directly in ``run:``."""

    rule_id = "expression-injection-in-run"
    name = "Expression injection in run: block"
    severity = Severity.CRITICAL
    category = OwaspCategory.PPE
    description = (
        "A GitHub Actions expression containing attacker-controllable input "
        "(PR title, issue body, branch name, etc.) is interpolated directly "
        "into a run: shell script. The expression is substituted before the "
        "shell runs, so an attacker can embed shell metacharacters and achieve "
        "arbitrary code execution in the workflow's privileged context."
    )
    remediation = (
        "Pass the value through an environment variable instead of "
        "interpolating it into the script:\n"
        "  - env:\n"
        "      TITLE: ${{ github.event.pull_request.title }}\n"
        '    run: echo "$TITLE"\n'
        "The shell expands $TITLE safely without re-parsing its contents."
    )
    references = [
        "https://securitylab.github.com/research/github-actions-untrusted-input/",
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
        for match in _EXPRESSION.finditer(run):
            inner = match.group(1).strip()
            untrusted = self._first_untrusted(inner)
            if untrusted is None:
                continue
            line = locate_in_run(step, untrusted)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    workflow_path=workflow.path,
                    line=line or 0,
                    column=0,
                    job_name=job_name,
                    step_index=step_index,
                    snippet=f"${{{{ {inner} }}}}",
                    message=(
                        f"Untrusted input '{untrusted}' is interpolated into a "
                        "run: script and can lead to code execution."
                    ),
                    confidence="high",
                )
            )
        return findings

    @staticmethod
    def _first_untrusted(expression: str) -> str | None:
        """Return the first untrusted context found in ``expression``, if any."""
        for context in UNTRUSTED_CONTEXTS:
            if context in expression:
                return context
        return None
