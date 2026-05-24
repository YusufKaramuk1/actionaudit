"""Tests for configuration loading and its effect on a scan."""

from pathlib import Path

from actionaudit.config import Config, load_config, load_config_from_yaml, merge
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


def test_load_config_from_yaml(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "disabled_rules:\n"
        "  - bash-with-set-x\n"
        "severity:\n"
        "  hardcoded-secret: critical\n",
        encoding="utf-8",
    )
    config = load_config_from_yaml(policy)
    assert "bash-with-set-x" in config.disabled_rules
    assert config.severity_overrides["hardcoded-secret"] is Severity.CRITICAL


def test_load_config_from_yaml_malformed_returns_empty(tmp_path: Path) -> None:
    policy = tmp_path / "broken.yaml"
    policy.write_text("[not-valid-yaml\n", encoding="utf-8")
    assert load_config_from_yaml(policy) == Config()


def test_merge_unions_disabled_and_overrides_severity() -> None:
    base = Config(
        disabled_rules={"a"},
        severity_overrides={"x": Severity.MEDIUM, "y": Severity.LOW},
    )
    override = Config(
        disabled_rules={"b"},
        severity_overrides={"y": Severity.HIGH},
    )
    result = merge(base, override)
    assert result.disabled_rules == {"a", "b"}
    assert result.severity_overrides == {"x": Severity.MEDIUM, "y": Severity.HIGH}
