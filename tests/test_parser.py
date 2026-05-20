"""Tests for the workflow parser and source-location helpers."""

from pathlib import Path

from actionaudit.parser import locate_in_run, parse_workflow, value_position


def test_parses_valid_workflow(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "sample_workflow.yml")
    assert wf.is_valid
    assert wf.parse_error is None
    assert wf.parsed["name"] == "Sample Workflow"


def test_broken_yaml_does_not_raise(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "broken.yml")
    assert not wf.is_valid
    assert wf.parse_error is not None
    assert "invalid YAML" in wf.parse_error


def test_missing_file_does_not_raise(tmp_path: Path) -> None:
    wf = parse_workflow(tmp_path / "does_not_exist.yml")
    assert not wf.is_valid
    assert wf.parse_error is not None


def test_locate_single_line_run(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "sample_workflow.yml")
    step = wf.parsed["jobs"]["build"]["steps"][0]
    # `run: echo "hello world"` is on line 9 of the fixture.
    assert locate_in_run(step, "hello world") == 9


def test_locate_in_multiline_block(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "sample_workflow.yml")
    step = wf.parsed["jobs"]["build"]["steps"][1]
    # First content line of the `run: |` block is line 12.
    assert locate_in_run(step, "first line") == 12
    # The expression injection sits on line 13.
    assert locate_in_run(step, "${{ github.event.pull_request.title }}") == 13
    # Last content line is line 14.
    assert locate_in_run(step, "third line") == 14


def test_locate_returns_none_when_not_found(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "sample_workflow.yml")
    step = wf.parsed["jobs"]["build"]["steps"][1]
    assert locate_in_run(step, "nonexistent-needle") is None


def test_value_position_of_run_key(fixtures_dir: Path) -> None:
    wf = parse_workflow(fixtures_dir / "sample_workflow.yml")
    step = wf.parsed["jobs"]["build"]["steps"][0]
    pos = value_position(step, "run")
    assert pos is not None
    line, _col = pos
    # `run:` value on the single-line step is on line 9.
    assert line == 9
