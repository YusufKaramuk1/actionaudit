"""Security rule registry with automatic discovery.

Adding a built-in rule is just dropping a new module in this package -- no
manual registration. ``get_all_rules`` imports every sibling module and
collects the concrete :class:`Rule` subclasses defined there. ``load_rules_
from_dir`` does the same for an external directory of user-defined rules.
"""

import importlib
import importlib.util
import inspect
import pkgutil
from pathlib import Path

from actionaudit.rules.base import Rule

__all__ = ["Rule", "get_all_rules", "load_rules_from_dir"]


def _collect_rules(module: object) -> list[Rule]:
    """Instantiate every concrete Rule subclass *defined in* ``module``."""
    rules: list[Rule] = []
    module_name = getattr(module, "__name__", None)
    for _name, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, Rule) and obj is not Rule and obj.__module__ == module_name:
            rules.append(obj())
    return rules


def get_all_rules() -> list[Rule]:
    """Discover and instantiate every built-in :class:`Rule` in this package."""
    rules: list[Rule] = []
    for module_info in pkgutil.iter_modules(__path__):
        if module_info.name == "base":
            continue
        module = importlib.import_module(f"{__name__}.{module_info.name}")
        rules.extend(_collect_rules(module))
    return sorted(rules, key=lambda rule: rule.rule_id)


def load_rules_from_dir(directory: Path) -> list[Rule]:
    """Load custom :class:`Rule` subclasses from every ``.py`` file in ``directory``.

    WARNING: this imports and therefore *executes* the Python files it finds.
    Only point it at a directory you trust. Files whose name starts with an
    underscore are skipped.
    """
    rules: list[Rule] = []
    if not directory.is_dir():
        return rules
    for py_file in sorted(directory.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(
            f"actionaudit_custom_{py_file.stem}", py_file
        )
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        rules.extend(_collect_rules(module))
    return sorted(rules, key=lambda rule: rule.rule_id)
