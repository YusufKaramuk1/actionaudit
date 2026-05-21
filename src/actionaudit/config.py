"""Configuration loaded from the [tool.actionaudit] table in pyproject.toml."""

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 has no tomllib in the standard library.
    import tomli as tomllib

from actionaudit.models import Severity


@dataclass
class Config:
    """Per-repository ActionAudit configuration.

    An empty Config (the default) changes nothing about a scan.
    """

    disabled_rules: set[str] = field(default_factory=set)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)


def _find_pyproject(start: Path) -> Path | None:
    """Walk up from ``start`` looking for the nearest pyproject.toml."""
    resolved = start.resolve()
    base = resolved if resolved.is_dir() else resolved.parent
    for directory in (base, *base.parents):
        candidate = directory / "pyproject.toml"
        if candidate.is_file():
            return candidate
    return None


def _parse_section(section: dict[str, Any]) -> Config:
    config = Config()

    disabled = section.get("disabled_rules")
    if isinstance(disabled, list):
        config.disabled_rules = {str(rule_id) for rule_id in disabled}

    overrides = section.get("severity")
    if isinstance(overrides, dict):
        for rule_id, value in overrides.items():
            try:
                config.severity_overrides[str(rule_id)] = Severity[str(value).upper()]
            except KeyError:
                continue  # ignore unknown severity names

    return config


def load_config(start: Path) -> Config:
    """Find pyproject.toml at or above ``start`` and read ``[tool.actionaudit]``.

    Returns an empty :class:`Config` when there is no file, no section, or the
    file is malformed -- configuration must never break a scan.
    """
    pyproject = _find_pyproject(start)
    if pyproject is None:
        return Config()
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return Config()

    section = data.get("tool", {}).get("actionaudit", {})
    if not isinstance(section, dict):
        return Config()
    return _parse_section(section)
