"""Repository CI/CD posture metrics, computed from parsed workflows.

Where rules produce *findings* (things that are wrong), posture produces
*counts* (how much of the good practice is already in place) -- the positive
mirror image used for the summary in reports.
"""

import re
from typing import Any

from actionaudit.models import PostureSummary, WorkflowFile
from actionaudit.parser import iter_steps, workflow_triggers

# A pinned action reference is a full 40-character lowercase hex commit SHA.
_FULL_SHA = re.compile(r"[0-9a-f]{40}")

# Owners maintained by GitHub itself -- exempt from the SHA-pinning count.
_TRUSTED_OWNERS = frozenset({"actions", "github"})


def _is_checkout(uses: Any) -> bool:
    return isinstance(uses, str) and (
        uses == "actions/checkout" or uses.startswith("actions/checkout@")
    )


def _persist_credentials_disabled(step: Any) -> bool:
    with_block = step.get("with")
    return (
        isinstance(with_block, dict)
        and with_block.get("persist-credentials") is False
    )


def _count_action(uses: str, summary: PostureSummary) -> None:
    """Count a third-party ``uses:`` reference and whether it is SHA-pinned."""
    if uses.startswith(("./", "docker://")) or "@" not in uses:
        return
    action, _, ref = uses.partition("@")
    if action.split("/", 1)[0] in _TRUSTED_OWNERS:
        return
    summary.total_third_party_uses += 1
    if _FULL_SHA.fullmatch(ref):
        summary.pinned_third_party_uses += 1


def analyze_posture(workflows: list[WorkflowFile]) -> PostureSummary:
    """Compute posture metrics across a list of parsed, valid workflows."""
    summary = PostureSummary()
    for workflow in workflows:
        if not workflow.is_valid:
            continue
        summary.total_workflows += 1
        if "permissions" in workflow.parsed:
            summary.workflows_with_permissions += 1
        if "pull_request_target" in workflow_triggers(workflow):
            summary.pull_request_target_workflows += 1

        for _job_name, _step_index, step in iter_steps(workflow):
            uses = step.get("uses")
            if isinstance(uses, str):
                _count_action(uses, summary)
            if _is_checkout(uses):
                summary.total_checkouts += 1
                if _persist_credentials_disabled(step):
                    summary.checkouts_with_persist_false += 1
    return summary
