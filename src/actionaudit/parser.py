"""YAML parsing and source-location helpers for workflow files."""

from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.scalarstring import FoldedScalarString, LiteralScalarString

from actionaudit.models import WorkflowFile

# A single round-trip loader. typ="rt" preserves line/column metadata (.lc).
_yaml = YAML(typ="rt")

# Files larger than this are almost certainly not workflows; skip them.
MAX_FILE_SIZE = 5 * 1024 * 1024


def parse_workflow(path: Path) -> WorkflowFile:
    """Read and parse a workflow file. Never raises.

    Any read, decode, or YAML error is captured in ``WorkflowFile.parse_error``
    so the scanner can keep going across the rest of the files.
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return WorkflowFile(path, raw_text="", parse_error="file is not valid UTF-8")
    except OSError as exc:
        return WorkflowFile(path, raw_text="", parse_error=f"cannot read file: {exc}")

    if len(raw_text) > MAX_FILE_SIZE:
        return WorkflowFile(path, raw_text, parse_error="file too large to scan (>5 MB)")

    try:
        parsed = _yaml.load(raw_text)
    except YAMLError as exc:
        detail = str(exc).strip()
        first_line = detail.splitlines()[0] if detail else "unknown error"
        return WorkflowFile(path, raw_text, parse_error=f"invalid YAML: {first_line}")

    return WorkflowFile(path, raw_text, parsed=parsed)


def value_position(node: Any, key: Any) -> tuple[int, int] | None:
    """Return the ``(line, column)`` of a mapping value for ``key``.

    Line is 1-indexed; column is 0-indexed (ruamel's native column).
    Returns ``None`` when position metadata is unavailable.
    """
    lc = getattr(node, "lc", None)
    if lc is None or not hasattr(lc, "data"):
        return None
    entry = lc.data.get(key)
    if entry is None:
        return None
    # entry = [key_line, key_col, value_line, value_col], all 0-indexed.
    value_line, value_col = entry[2], entry[3]
    return value_line + 1, value_col


def locate_in_run(step: Any, needle: str) -> int | None:
    """Find ``needle`` inside a step's ``run:`` script.

    Returns the absolute 1-indexed line number in the source file, handling
    both single-line (``run: echo ...``) and block scalars (``run: |``).
    Returns ``None`` if there is no ``run:`` key or ``needle`` is not found.

    For block scalars ruamel reports the value line as the ``|`` indicator
    line, with the actual content starting on the next line -- hence the
    ``+2`` offset (``+1`` for 1-indexing, ``+1`` to step past the indicator).
    """
    lc = getattr(step, "lc", None)
    if lc is None or not hasattr(lc, "data") or "run" not in lc.data:
        return None

    run_value = step.get("run")
    if run_value is None:
        return None

    value_line = lc.data["run"][2]  # 0-indexed
    is_block = isinstance(run_value, (LiteralScalarString, FoldedScalarString))

    for offset, content_line in enumerate(str(run_value).splitlines()):
        if needle in content_line:
            if is_block:
                return value_line + 2 + offset
            return value_line + 1 + offset
    return None
