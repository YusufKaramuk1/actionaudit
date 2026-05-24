"""Rule: actions/cache key derived from PR-controlled input."""

from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import iter_steps, value_position
from actionaudit.rules.base import Rule

# Attacker-controllable contexts that should not feed into a cache key.
_PR_CONTROLLED: tuple[str, ...] = (
    "github.head_ref",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.title",
    "github.event.issue.title",
)


def _is_cache(uses: Any) -> bool:
    return isinstance(uses, str) and (
        uses == "actions/cache" or uses.startswith("actions/cache@")
    )


def _tainted_in(value: Any) -> str | None:
    """Return the first PR-controlled context referenced inside ``value``."""
    if isinstance(value, str):
        for context in _PR_CONTROLLED:
            if context in value:
                return context
    elif isinstance(value, list):
        for item in value:
            tainted = _tainted_in(item)
            if tainted is not None:
                return tainted
    return None


class CachePoisoningRule(Rule):
    """Detect cache keys derived from inputs an attacker can craft."""

    rule_id = "actions-cache-poisoning-risk"
    name = "actions/cache key derived from PR-controlled input"
    severity = Severity.MEDIUM
    category = OwaspCategory.DEPENDENCY_CHAIN
    description = (
        "An actions/cache key (or restore-keys entry) is built from input a "
        "pull request can control -- the head branch name, PR title, or issue "
        "title. An attacker can craft that input to write into a cache slot "
        "they choose, poisoning later runs that restore from the same key. "
        "Subsequent jobs may then execute the attacker's cached content."
    )
    remediation = (
        "Derive cache keys from trusted inputs only -- the OS, a hash of the "
        "lock file, or the commit SHA. Do not include github.head_ref, PR "
        "titles, issue titles, or other attacker-controllable strings."
    )
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
    ]

    def check(self, workflow: WorkflowFile) -> list[Finding]:
        findings: list[Finding] = []
        if not workflow.is_valid:
            return findings

        for job_name, step_index, step in iter_steps(workflow):
            uses = step.get("uses")
            if not _is_cache(uses):
                continue
            with_block = step.get("with")
            if not isinstance(with_block, dict):
                continue

            tainted = _tainted_in(with_block.get("key"))
            if tainted is None:
                tainted = _tainted_in(with_block.get("restore-keys"))
            if tainted is None:
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
                        f"Cache key references '{tainted}', which an attacker "
                        "can influence -- this allows cache poisoning."
                    ),
                    confidence="high",
                )
            )
        return findings
