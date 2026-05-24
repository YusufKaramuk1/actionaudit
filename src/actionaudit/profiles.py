"""Built-in configuration profiles selected via ``actionaudit scan --profile``.

Profiles are small :class:`Config` presets layered underneath any user
pyproject.toml or ``--policy`` configuration -- the user always has the final
say.
"""

from collections.abc import Callable

from actionaudit.config import Config
from actionaudit.models import Severity


def _strict() -> Config:
    """All rules on; the noisier low/medium rules promoted for a sharper bar."""
    return Config(
        severity_overrides={
            "bash-with-set-x": Severity.MEDIUM,
            "persist-credentials-default-true": Severity.HIGH,
        },
    )


def _balanced() -> Config:
    """Default behaviour -- no overrides, no disabled rules."""
    return Config()


def _education() -> Config:
    """Mute the noisiest LOW rule so the report focuses on teachable findings."""
    return Config(disabled_rules={"bash-with-set-x"})


PROFILES: dict[str, Callable[[], Config]] = {
    "strict": _strict,
    "balanced": _balanced,
    "education": _education,
}
