"""Tests for configuration loading and its effect on a scan."""

from pathlib import Path

from actionaudit.config import Config, load_config
from actionaudit.models import Severity
from actionaudit.scanner import scan

_PYPROJECT = """\
[tool.actionaudit]
disabled_rules = ["bash-with-set-x"]

[tool.actionaudit.severity]
hardcoded-secret = "critical"
"""


def test_load_config_without_pyproject(tmp_path: Path) -> None:
    config = load_config(tmp_path)
    assert config.disabled_rules == set()
    assert config.severity_overrides == {}


def test_load_config_reads_section(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(_PYPROJECT, encoding="utf-8")
    config = load_config(tmp_path)
    assert "bash-with-set-x" in config.disabled_rules
    assert config.severity_overrides["hardcoded-secret"] is Severity.CRITICAL


def test_load_config_ignores_unknown_severity(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.actionaudit.severity]\nhardcoded-secret = "bogus"\n',
        encoding="utf-8",
    )
    config = load_config(tmp_path)
    assert config.severity_overrides == {}


def test_scan_honours_disabled_rules(fixtures_dir: Path) -> None:
    target = fixtures_dir / "vulnerable" / "expression_injection.yml"
    config = Config(disabled_rules={"expression-injection-in-run"})
    report = scan(target, config=config)
    rule_ids = {f.rule_id for f in report.findings}
    assert "expression-injection-in-run" not in rule_ids


def test_scan_applies_severity_override(fixtures_dir: Path) -> None:
    target = fixtures_dir / "vulnerable" / "hardcoded_secret.yml"
    config = Config(severity_overrides={"hardcoded-secret": Severity.CRITICAL})
    report = scan(target, config=config)
    secret = next(f for f in report.findings if f.rule_id == "hardcoded-secret")
    assert secret.severity is Severity.CRITICAL
