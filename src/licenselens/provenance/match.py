"""Token variant matching against text and path components."""

from __future__ import annotations

from pathlib import Path

from licenselens.provenance.token import TokenPolicy


def text_matches(policy: TokenPolicy, text: str) -> list[tuple[int, int, str]]:
    """Return (start, end, matched_text) spans for every policy hit in ``text``."""
    hits: list[tuple[int, int, str]] = []
    for pattern in policy.patterns:
        for match in pattern.finditer(text):
            hits.append((match.start(), match.end(), match.group(0)))
    if policy.canonical:
        compact_map: list[int] = []
        compact_chars: list[str] = []
        for index, char in enumerate(text):
            if char in "-_ \t\r\n":
                continue
            compact_map.append(index)
            compact_chars.append(char.casefold())
        compact = "".join(compact_chars)
        needle = policy.canonical
        start_at = 0
        while True:
            found = compact.find(needle, start_at)
            if found < 0:
                break
            end = found + len(needle) - 1
            orig_start = compact_map[found]
            orig_end = compact_map[end] + 1
            hits.append((orig_start, orig_end, text[orig_start:orig_end]))
            start_at = found + 1
    hits.sort(key=lambda item: (item[0], item[1]))
    return _dedupe_spans(hits)


def _dedupe_spans(hits: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    if not hits:
        return []
    out: list[tuple[int, int, str]] = []
    last_start = last_end = -1
    for start, end, matched in hits:
        if start == last_start and end == last_end:
            continue
        out.append((start, end, matched))
        last_start, last_end = start, end
    return out


def path_component_matches(policy: TokenPolicy, relative_path: str) -> list[str]:
    """Return path segments that match the prohibited token variants."""
    bad: list[str] = []
    for part in Path(relative_path).parts:
        if part in {".", "..", "/"}:
            continue
        if text_matches(policy, part):
            bad.append(part)
    return bad
