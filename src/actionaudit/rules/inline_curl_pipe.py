"""Rule: piping a downloaded script straight into a shell (curl | bash)."""

import re
from typing import Any

from actionaudit.models import Finding, OwaspCategory, Severity, WorkflowFile
from actionaudit.parser import locate_in_run
from actionaudit.rules.base import Rule

# curl/wget ... | [sudo] [ba|z|k]sh  -- a remote script executed unverified.
_CURL_PIPE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b"
)


class InlineCurlPipeRule(Rule):
    """Detect remote scripts piped directly into a shell inside run: steps."""

    rule_id = "inline-curl-pipe-bash"
    name = "Remote script piped directly into a shell"
    severity = Severity.MEDIUM
    category = OwaspCategory.DEPENDENCY_CHAIN
    description = (
        "A run: step downloads a script with curl or wget and pipes it "
        "straight into a shell. The downloaded content is executed without "
        "any integrity check, so whoever controls or compromises the remote "
        "endpoint -- or anyone able to intercept the connection -- gains code "
        "execution on the runner."
    )
    remediation = (
        "Download the script to a file, verify it (checksum or signature), "
        "and only then execute it:\n"
        "  - run: |\n"
        "      curl -fsSL -o install.sh https://example.com/install.sh\n"
        '      echo "<expected-sha256>  install.sh" | sha256sum -c\n'
        "      bash install.sh"
    )
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
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
        for line in run.splitlines():
            match = _CURL_PIPE.search(line)
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
                        "A remote script is piped directly into a shell "
                        "without any integrity check."
                    ),
                    confidence="high",
                )
            )
        return findings
