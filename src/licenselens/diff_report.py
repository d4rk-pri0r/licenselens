"""Compare two scan JSON artifacts by check_id."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def diff_scans(old_path: Path, new_path: Path) -> dict[str, Any]:
    old = _load(old_path)
    new = _load(new_path)
    old_map = {f["check_id"]: f for f in old.get("findings") or [] if f.get("check_id")}
    new_map = {f["check_id"]: f for f in new.get("findings") or [] if f.get("check_id")}
    ids = sorted(set(old_map) | set(new_map))

    new_gaps: list[str] = []
    resolved: list[str] = []
    worsened: list[str] = []
    improved: list[str] = []
    unchanged: list[str] = []
    confidence_changes: list[dict[str, str]] = []
    rows: list[dict[str, Any]] = []

    # Mirrors engine.runner._STATUS_PRIORITY ordering (worse = lower number).
    rank = {
        "gap": 0,
        "partial": 1,
        "skipped": 2,
        "error": 3,
        "ok": 4,
        "not_licensed": 5,
    }

    for cid in ids:
        o = old_map.get(cid)
        n = new_map.get(cid)
        os_ = (o or {}).get("status")
        ns_ = (n or {}).get("status")
        oc = (o or {}).get("confidence")
        nc = (n or {}).get("confidence")
        row = {
            "check_id": cid,
            "old_status": os_,
            "new_status": ns_,
            "old_confidence": oc,
            "new_confidence": nc,
        }
        rows.append(row)
        if os_ == ns_:
            unchanged.append(cid)
        elif ns_ == "gap" and os_ != "gap":
            new_gaps.append(cid)
        elif os_ == "gap" and ns_ in {"ok", "partial", "not_licensed"}:
            resolved.append(cid)
        elif os_ and ns_ and rank.get(ns_, 9) < rank.get(os_, 9):
            worsened.append(cid)
        elif os_ and ns_ and rank.get(ns_, 9) > rank.get(os_, 9):
            improved.append(cid)
        if oc and nc and oc != nc:
            confidence_changes.append({"check_id": cid, "old": str(oc), "new": str(nc)})

    return {
        "old_file": str(old_path),
        "new_file": str(new_path),
        "old_scanned_at": old.get("scanned_at"),
        "new_scanned_at": new.get("scanned_at"),
        "new_gaps": new_gaps,
        "resolved": resolved,
        "worsened": worsened,
        "improved": improved,
        "unchanged": unchanged,
        "confidence_changes": confidence_changes,
        "rows": rows,
    }


def render_diff_markdown(diff: dict[str, Any]) -> str:
    lines = [
        "# Security License Lens — scan diff",
        "",
        f"- **Old:** `{diff.get('old_file')}` ({diff.get('old_scanned_at')})",
        f"- **New:** `{diff.get('new_file')}` ({diff.get('new_scanned_at')})",
        "",
        "## Summary",
        "",
        f"- New gaps: {len(diff.get('new_gaps') or [])}",
        f"- Resolved gaps: {len(diff.get('resolved') or [])}",
        f"- Improved: {len(diff.get('improved') or [])}",
        f"- Worsened: {len(diff.get('worsened') or [])}",
        f"- Unchanged: {len(diff.get('unchanged') or [])}",
        "",
    ]
    for title, key in (
        ("New gaps", "new_gaps"),
        ("Resolved", "resolved"),
        ("Improved", "improved"),
        ("Worsened", "worsened"),
    ):
        items = diff.get(key) or []
        if not items:
            continue
        lines.append(f"## {title}")
        lines.append("")
        for cid in items:
            lines.append(f"- `{cid}`")
        lines.append("")

    lines.extend(["## All checks", "", "| Check | Old | New | Confidence |", "|---|---|---|---|"])
    for row in diff.get("rows") or []:
        conf = ""
        if row.get("old_confidence") or row.get("new_confidence"):
            conf = f"{row.get('old_confidence') or '—'} → {row.get('new_confidence') or '—'}"
        lines.append(
            f"| `{row['check_id']}` | {row.get('old_status') or '—'} | "
            f"{row.get('new_status') or '—'} | {conf or '—'} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_diff_report(old_path: Path, new_path: Path, output: Path) -> Path:
    diff = diff_scans(old_path, new_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix.lower() == ".json":
        output.write_text(json.dumps(diff, indent=2) + "\n", encoding="utf-8")
    else:
        output.write_text(render_diff_markdown(diff), encoding="utf-8")
    return output
