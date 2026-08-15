"""Derive the sole allowed comparison-table token from README.md at runtime.

The prohibited competitor codename is never embedded in source, tests, or
config. It is located structurally from the README comparison table row whose
repository link points at the ``github.com/silverhack/`` org (with a CSPM /
CIS-style structural fallback used only for synthetic fixtures).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import urlparse

# Pinned digest of the sole allowed production README comparison-table row
# (normalized: strip + UTF-8). Does not encode the token itself.
EXPECTED_ALLOWED_ROW_SHA256: Final = (
    "fc855e4b8cf8a837085b8d9f690d68971573b62018a208ded919e2795b315c43"
)

_SILVERHACK_HOST: Final = "github.com"
_SILVERHACK_ORG: Final = "silverhack"
_LINK_RE: Final = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")
_TABLE_HEADER_RE: Final = re.compile(r"^\|\s*Tool\s*\|", re.IGNORECASE)
_TABLE_SEP_RE: Final = re.compile(r"^\|\s*-+")
_CSPM_MARKERS: Final = ("CSPM", "CIS-style")


@dataclass(frozen=True, slots=True)
class TokenPolicyError(Exception):
    """Policy README could not yield a valid allowed-row token."""

    reason: str

    def __str__(self) -> str:
        return f"provenance token policy error: {self.reason}"


@dataclass(frozen=True, slots=True)
class AllowedRow:
    """One structurally located comparison-table row and its derived token."""

    display_name: str
    url: str
    url_basename: str
    line_text: str
    line_index: int
    byte_start: int
    byte_end: int
    row_sha256: str
    matches_expected_digest: bool

    @property
    def token(self) -> str:
        return self.display_name.strip()


@dataclass(frozen=True, slots=True)
class TokenPolicy:
    """Runtime-derived matching policy for one scan root."""

    token: str
    token_lower: str
    canonical: str
    patterns: tuple[re.Pattern[str], ...]
    allowed_row: AllowedRow
    policy_readme: Path
    readme_relative: str


def normalize_token(value: str) -> str:
    """Lowercase and strip hyphen/underscore/whitespace separators."""
    return re.sub(r"[-_\s]+", "", value.casefold())


def _url_basename(url: str) -> str:
    path = urlparse(url).path.rstrip("/")
    return path.rsplit("/", 1)[-1] if path else ""


def _is_silverhack_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").casefold()
    if host != _SILVERHACK_HOST:
        return False
    parts = [part for part in parsed.path.split("/") if part]
    return bool(parts) and parts[0].casefold() == _SILVERHACK_ORG


def _row_digest(line: str) -> str:
    return hashlib.sha256(line.strip().encode("utf-8")).hexdigest()


def _build_patterns(token: str) -> tuple[re.Pattern[str], ...]:
    """Case-insensitive exact token plus separator-flexible variants."""
    raw = token.strip()
    if not raw:
        raise TokenPolicyError("derived token is empty")

    patterns: list[re.Pattern[str]] = [
        re.compile(re.escape(raw), re.IGNORECASE),
    ]

    # Split on existing separators and on letter↔digit boundaries.
    pieces = re.findall(r"[A-Za-z]+|\d+|[^\W\d_]+", raw, flags=re.UNICODE)
    if len(pieces) >= 2:
        flex = r"[-_\s]*".join(re.escape(part) for part in pieces)
        patterns.append(re.compile(flex, re.IGNORECASE))

    # Canonical form (no separators) as a last-resort content probe.
    canonical = normalize_token(raw)
    if canonical and canonical.casefold() != raw.casefold():
        patterns.append(re.compile(re.escape(canonical), re.IGNORECASE))

    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique: list[re.Pattern[str]] = []
    for pattern in patterns:
        key = pattern.pattern
        if key in seen:
            continue
        seen.add(key)
        unique.append(pattern)
    return tuple(unique)


def _select_row(
    lines: list[str],
    *,
    prefer_silverhack: bool,
) -> tuple[int, str, re.Match[str]] | None:
    in_table = False
    fallback: tuple[int, str, re.Match[str]] | None = None
    for index, line in enumerate(lines):
        if _TABLE_HEADER_RE.match(line):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            break
        if _TABLE_SEP_RE.match(line):
            continue
        match = _LINK_RE.search(line)
        if match is None:
            continue
        url = match.group(2).strip()
        if prefer_silverhack and _is_silverhack_url(url):
            return index, line, match
        if any(marker in line for marker in _CSPM_MARKERS):
            fallback = (index, line, match)
    return fallback


def _line_byte_span(text: str, line_index: int) -> tuple[int, int]:
    """Return UTF-8 byte ``[start, end)`` of line *content* at ``line_index``.

    Uses the original text's line endings (LF, CRLF, or CR) so allowed-row
    ranges stay aligned with match offsets on Windows checkouts that rewrite
    newlines. ``end`` excludes the trailing line-break bytes.
    """
    with_ends = text.splitlines(keepends=True)
    if line_index < 0 or line_index >= len(with_ends):
        raise TokenPolicyError(f"comparison row line index {line_index} out of range")
    prefix = "".join(with_ends[:line_index])
    content = with_ends[line_index].rstrip("\r\n")
    byte_start = len(prefix.encode("utf-8"))
    byte_end = byte_start + len(content.encode("utf-8"))
    return byte_start, byte_end


def parse_allowed_row(readme_text: str, *, require_expected_digest: bool = False) -> AllowedRow:
    """Locate the sole allowed comparison-table row inside README text."""
    lines = readme_text.splitlines()
    selected = _select_row(lines, prefer_silverhack=True)
    if selected is None:
        raise TokenPolicyError(
            "README comparison table row with silverhack org link (or CSPM marker) not found"
        )
    line_index, line, match = selected
    display = match.group(1).strip()
    url = match.group(2).strip()
    basename = _url_basename(url)
    if not display:
        raise TokenPolicyError("comparison row display name is empty")
    if normalize_token(display) != normalize_token(basename):
        raise TokenPolicyError(
            "comparison row display name and URL basename do not normalize equal"
        )

    byte_start, byte_end = _line_byte_span(readme_text, line_index)
    digest = _row_digest(line)
    matches = digest == EXPECTED_ALLOWED_ROW_SHA256
    if require_expected_digest and not matches:
        raise TokenPolicyError(f"allowed row sha256 {digest} does not match pinned expected digest")
    return AllowedRow(
        display_name=display,
        url=url,
        url_basename=basename,
        line_text=line,
        line_index=line_index,
        byte_start=byte_start,
        byte_end=byte_end,
        row_sha256=digest,
        matches_expected_digest=matches,
    )


def resolve_policy_readme(root: Path, explicit: Path | None = None) -> Path:
    """Resolve the README used for token derivation."""
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if not path.is_file():
            raise TokenPolicyError(f"policy readme not found: {path}")
        return path

    candidates = [
        root / "README.md",
        Path.cwd() / "README.md",
    ]
    # Walk parents of the scan root (synthetic fixtures often lack a README).
    for parent in root.resolve().parents:
        candidates.append(parent / "README.md")

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if not resolved.is_file():
            continue
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            parse_allowed_row(text)
        except TokenPolicyError:
            continue
        return resolved
    raise TokenPolicyError("no README.md with a valid comparison-table row found")


def load_token_policy(
    root: Path,
    *,
    policy_readme: Path | None = None,
    require_expected_digest: bool = False,
) -> TokenPolicy:
    """Load runtime token policy for ``root``."""
    readme_path = resolve_policy_readme(root, policy_readme)
    text = readme_path.read_text(encoding="utf-8")
    allowed = parse_allowed_row(text, require_expected_digest=require_expected_digest)
    token = allowed.token
    return TokenPolicy(
        token=token,
        token_lower=token.casefold(),
        canonical=normalize_token(token),
        patterns=_build_patterns(token),
        allowed_row=allowed,
        policy_readme=readme_path,
        readme_relative=_relpath(readme_path, root),
    )


def _relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name
