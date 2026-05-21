"""Scan orchestration: discover workflow files, parse them, run all rules."""

import time
from pathlib import Path

from actionaudit.config import Config, load_config
from actionaudit.models import Finding, ScanReport
from actionaudit.parser import parse_ignore_directives, parse_workflow
from actionaudit.rules import get_all_rules, load_rules_from_dir

_WORKFLOW_EXTENSIONS = (".yml", ".yaml")
_WORKFLOWS_DIR = Path(".github") / "workflows"


def discover_workflows(target: Path) -> list[Path]:
    """Return the workflow files reachable from ``target``.

    - a file               -> that file
    - a ``workflows`` dir   -> ``*.yml`` / ``*.yaml`` directly inside it
    - any other directory   -> ``*.yml`` / ``*.yaml`` under ``.github/workflows``

    Hidden files (leading dot) are skipped.
    """
    if target.is_file():
        return [target]
    if not target.is_dir():
        return []

    search_dir = target
    if target.name != "workflows":
        candidate = target / _WORKFLOWS_DIR
        if candidate.is_dir():
            search_dir = candidate

    found: list[Path] = []
    for ext in _WORKFLOW_EXTENSIONS:
        found.extend(search_dir.glob(f"*{ext}"))
    return sorted(p for p in found if not p.name.startswith("."))


def _is_ignored(finding: Finding, directives: dict[int, set[str]]) -> bool:
    """True if an inline ``# actionaudit: ignore`` directive suppresses this finding.

    A directive applies to its own line and the line immediately below it.
    """
    for line in (finding.line, finding.line - 1):
        ignored = directives.get(line)
        if ignored and ("*" in ignored or finding.rule_id in ignored):
            return True
    return False


def scan(
    target: Path,
    config: Config | None = None,
    rules_dir: Path | None = None,
) -> ScanReport:
    """Scan ``target`` and return an aggregated :class:`ScanReport`.

    Configuration is read from the nearest ``pyproject.toml`` unless an explicit
    :class:`Config` is passed. ``rules_dir`` loads extra user-defined rules.
    Never raises on bad input: unreadable or malformed files are recorded in
    ``ScanReport.skipped`` and scanning continues across the rest.
    """
    start = time.perf_counter()
    if config is None:
        config = load_config(target)

    rules = list(get_all_rules())
    if rules_dir is not None:
        rules.extend(load_rules_from_dir(rules_dir))
    rules = [rule for rule in rules if rule.rule_id not in config.disabled_rules]

    findings: list[Finding] = []
    scanned: list[Path] = []
    skipped: list[tuple[Path, str]] = []

    for path in discover_workflows(target):
        workflow = parse_workflow(path)
        if not workflow.is_valid:
            skipped.append((path, workflow.parse_error or "not a valid YAML mapping"))
            continue
        if "jobs" not in workflow.parsed:
            skipped.append((path, "not a GitHub Actions workflow (no jobs:)"))
            continue

        scanned.append(path)
        directives = parse_ignore_directives(workflow.raw_text)
        for rule in rules:
            for finding in rule.check(workflow):
                if _is_ignored(finding, directives):
                    continue
                override = config.severity_overrides.get(finding.rule_id)
                if override is not None:
                    finding.severity = override
                findings.append(finding)

    duration_ms = int((time.perf_counter() - start) * 1000)
    return ScanReport(
        findings=findings,
        scanned_files=scanned,
        skipped=skipped,
        duration_ms=duration_ms,
    )
