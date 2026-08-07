import json
from pathlib import Path

from licenselens.diff_report import diff_scans, render_diff_markdown, write_diff_report


def _scan(findings, scanned_at="2026-01-01T00:00:00+00:00"):
    return {"scanned_at": scanned_at, "findings": findings}


def _finding(check_id, status, confidence="high"):
    return {"check_id": check_id, "status": status, "confidence": confidence}


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_diff_scans_categorizes_changes(tmp_path: Path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    _write(
        old,
        _scan([_finding("a", "gap"), _finding("b", "gap"), _finding("c", "ok")]),
    )
    _write(
        new,
        _scan([_finding("a", "ok"), _finding("b", "gap"), _finding("d", "gap")]),
    )

    diff = diff_scans(old, new)
    assert diff["new_gaps"] == ["d"]
    assert diff["resolved"] == ["a"]
    assert diff["unchanged"] == ["b"]
    assert any(r["check_id"] == "c" for r in diff["rows"])
    by_id = {r["check_id"]: r for r in diff["rows"]}
    assert by_id["c"]["old_status"] == "ok"
    assert by_id["c"]["new_status"] is None
    assert len(diff["rows"]) == 4


def test_diff_scans_tracks_confidence_changes(tmp_path: Path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    _write(
        old,
        _scan([_finding("a", "gap", confidence="high")]),
    )
    _write(
        new,
        _scan([_finding("a", "gap", confidence="low")]),
    )
    diff = diff_scans(old, new)
    assert diff["confidence_changes"] == [{"check_id": "a", "old": "high", "new": "low"}]


def test_diff_scans_marks_improvement(tmp_path: Path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    _write(old, _scan([_finding("a", "partial")]))
    _write(new, _scan([_finding("a", "ok")]))
    diff = diff_scans(old, new)
    assert diff["improved"] == ["a"]


def test_write_diff_report_markdown(tmp_path: Path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    _write(old, _scan([_finding("a", "gap")]))
    _write(new, _scan([_finding("a", "ok")]))

    out = write_diff_report(old, new, tmp_path / "diff.md")
    text = out.read_text(encoding="utf-8")
    assert "# Security License Lens — scan diff" in text
    assert "Resolved gaps: 1" in text
    assert "`a`" in text


def test_write_diff_report_json(tmp_path: Path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    _write(old, _scan([_finding("a", "gap")]))
    _write(new, _scan([_finding("a", "gap")]))

    out = write_diff_report(old, new, tmp_path / "diff.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["new_gaps"] == []
    assert data["rows"][0]["check_id"] == "a"


def test_render_diff_markdown_handles_empty(tmp_path: Path):
    old = tmp_path / "x.json"
    new = tmp_path / "y.json"
    old.write_text("{}", encoding="utf-8")
    new.write_text("{}", encoding="utf-8")
    diff = diff_scans(old, new)
    assert "New gaps: 0" in render_diff_markdown(diff)
