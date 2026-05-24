"""Tests for the built-in --profile presets."""

from actionaudit.models import Severity
from actionaudit.profiles import PROFILES


def test_strict_profile_promotes_low_severity_rules() -> None:
    config = PROFILES["strict"]()
    assert config.severity_overrides.get("bash-with-set-x") is Severity.MEDIUM
    assert (
        config.severity_overrides.get("persist-credentials-default-true")
        is Severity.HIGH
    )


def test_balanced_profile_is_empty() -> None:
    config = PROFILES["balanced"]()
    assert config.disabled_rules == set()
    assert config.severity_overrides == {}


def test_education_profile_mutes_set_x() -> None:
    config = PROFILES["education"]()
    assert "bash-with-set-x" in config.disabled_rules
