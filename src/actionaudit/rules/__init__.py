"""Security rule registry with automatic discovery.

Adding a new rule is just dropping a new module in this package -- no manual
registration. ``get_all_rules`` imports every sibling module and collects the
concrete :class:`Rule` subclasses defined there.
"""

import importlib
import inspect
import pkgutil

from actionaudit.rules.base import Rule

__all__ = ["Rule", "get_all_rules"]


def get_all_rules() -> list[Rule]:
    """Discover and instantiate every concrete :class:`Rule` in this package."""
    rules: list[Rule] = []
    for module_info in pkgutil.iter_modules(__path__):
        if module_info.name == "base":
            continue
        module = importlib.import_module(f"{__name__}.{module_info.name}")
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, Rule)
                and obj is not Rule
                and obj.__module__ == module.__name__
            ):
                rules.append(obj())
    return sorted(rules, key=lambda rule: rule.rule_id)
