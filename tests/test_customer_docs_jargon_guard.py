"""K15: customer-facing docs must be free of internal jargon and raw enums.

Scans README.md and the top-level docs/ pages (the generated ``docs/reference/``
catalog is technical by design and excluded) for creator-knowledge leakage:
the "assessment profile" term, raw underscore enum values (``dry_run`` /
``device_code``), raw evaluation-mode meta labels ("Evaluation: <mode>"),
zero-GUID placeholders, and DMARC report-tag jargon. Any hit fails CI, so
internal vocabulary can never silently return to the customer surface.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "internal term 'assessment profile'",
        re.compile(r"\bassessment\s+profiles?\b", re.IGNORECASE),
    ),
    ("raw enum value 'dry_run'", re.compile(r"\bdry_run\b")),
    ("raw enum value 'device_code'", re.compile(r"\bdevice_code\b")),
    (
        "raw evaluation-mode meta label",
        re.compile(r"\bEvaluation\s*:\s*[A-Za-z_]+"),
    ),
    ("zero-GUID placeholder", re.compile(r"00000000-0000-0000-0000-")),
    (
        "DMARC report-tag jargon 'rua'/'ruf'",
        re.compile(r"\b(rua|ruf)\b", re.IGNORECASE),
    ),
)


def _customer_docs() -> list[Path]:
    docs_root = ROOT / "docs"
    return [
        ROOT / "README.md",
        *(path for path in sorted(docs_root.glob("*.md")) if path.is_file()),
    ]


def _jargon_hits(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8")
    hits: list[tuple[int, str]] = []
    for label, pattern in FORBIDDEN_PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            hits.append((line, label))
    return sorted(hits)


def test_customer_facing_docs_are_free_of_internal_jargon():
    hits = [
        (path.relative_to(ROOT).as_posix(), line, label)
        for path in _customer_docs()
        for line, label in _jargon_hits(path)
    ]
    assert not hits, "customer-facing docs carry internal jargon:\n" + "\n".join(
        f"  {path}:{line}: {label}" for path, line, label in hits
    )


def test_customer_doc_scan_covers_readme_and_all_top_level_docs():
    docs = _customer_docs()
    assert ROOT / "README.md" in docs
    assert ROOT / "docs" / "cli.md" in docs
    assert ROOT / "docs" / "getting-started.md" in docs
    assert len(docs) >= 15
