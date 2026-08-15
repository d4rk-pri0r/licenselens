"""Working-tree provenance scan (tracked, untracked, ignored)."""

from __future__ import annotations

import os
from pathlib import Path

from licenselens.provenance.archive_scan import (
    is_archive_path,
    scan_archive_file,
    scan_bytes_for_token,
)
from licenselens.provenance.match import path_component_matches, text_matches
from licenselens.provenance.models import ScanMode, Violation, ViolationKind
from licenselens.provenance.token import TokenPolicy, TokenPolicyError, parse_allowed_row

# Skip heavy/irrelevant trees that are not product content.
_SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        "node_modules",
        ".eggs",
    }
)


def iter_workspace_paths(root: Path) -> list[Path]:
    """Return every file/symlink under root, including ignored paths."""
    results: list[Path] = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        # Prune skip dirs in-place.
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in _SKIP_DIR_NAMES and not name.endswith(".egg-info")
        )
        for name in sorted(dirnames):
            path = current / name
            results.append(path)
        for name in sorted(filenames):
            results.append(current / name)
    return results


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _scan_readme_text(
    policy: TokenPolicy,
    text: str,
    *,
    relative: str,
    mode: ScanMode,
) -> list[Violation]:
    violations: list[Violation] = []
    # Prefer ranges derived from this file's own allowed row when present.
    try:
        local = parse_allowed_row(text)
        allow_start, allow_end = local.byte_start, local.byte_end
    except TokenPolicyError:
        allow_start = policy.allowed_row.byte_start
        allow_end = policy.allowed_row.byte_end
        # Only apply policy-readme ranges when this is the policy file itself.
        if relative.replace("\\", "/") != policy.readme_relative:
            allow_start = allow_end = -1

    for start, end, matched in text_matches(policy, text):
        if allow_start >= 0 and start >= allow_start and end <= allow_end:
            continue
        violations.append(
            Violation(
                kind=ViolationKind.CONTENT,
                path=relative,
                detail=f"token variant outside allowed README row at offset {start}",
                mode=mode,
                offset=start,
                snippet_hex=matched.encode("utf-8", errors="replace")[:24].hex(),
            )
        )
    return violations


def scan_workspace_tree(root: Path, policy: TokenPolicy) -> tuple[list[Violation], int]:
    """Scan the full working tree under root. Returns (violations, path_count)."""
    mode = ScanMode.WORKSPACE
    root = root.resolve()
    violations: list[Violation] = []
    paths = iter_workspace_paths(root)
    scanned = 0

    for path in paths:
        relative = _relative(path, root)
        scanned += 1

        # Path components (every segment).
        for part in path_component_matches(policy, relative):
            violations.append(
                Violation(
                    kind=ViolationKind.PATH,
                    path=relative,
                    detail=f"path component matches token: {part}",
                    mode=mode,
                )
            )

        if path.is_symlink():
            try:
                target = os.readlink(path)
            except OSError as exc:
                violations.append(
                    Violation(
                        kind=ViolationKind.UNREADABLE,
                        path=relative,
                        detail=f"unreadable symlink: {exc.__class__.__name__}",
                        mode=mode,
                    )
                )
                continue
            # Broken symlink is a fail-closed violation.
            if not path.exists():
                violations.append(
                    Violation(
                        kind=ViolationKind.UNREADABLE,
                        path=relative,
                        detail="broken symlink",
                        mode=mode,
                    )
                )
            for start, _end, matched in text_matches(policy, target):
                violations.append(
                    Violation(
                        kind=ViolationKind.SYMLINK_TARGET,
                        path=relative,
                        detail=f"symlink target matches token at offset {start}",
                        mode=mode,
                        offset=start,
                        snippet_hex=matched.encode("utf-8", errors="replace")[:24].hex(),
                    )
                )
            continue

        if path.is_dir():
            continue

        if not path.is_file():
            violations.append(
                Violation(
                    kind=ViolationKind.UNREADABLE,
                    path=relative,
                    detail="unreadable special file",
                    mode=mode,
                )
            )
            continue

        if is_archive_path(path):
            violations.extend(
                scan_archive_file(policy, path, relative=relative, mode=mode)
            )
            continue

        try:
            data = path.read_bytes()
        except OSError as exc:
            violations.append(
                Violation(
                    kind=ViolationKind.UNREADABLE,
                    path=relative,
                    detail=f"unreadable file: {exc.__class__.__name__}",
                    mode=mode,
                )
            )
            continue

        if path.name.casefold() == "readme.md":
            text = data.decode("utf-8", errors="replace")
            violations.extend(
                _scan_readme_text(policy, text, relative=relative, mode=mode)
            )
            continue

        violations.extend(
            scan_bytes_for_token(
                policy,
                data,
                path=relative,
                mode=mode,
                kind=ViolationKind.CONTENT,
            )
        )

    def _sort_key(v: Violation) -> tuple[str, str, str, int]:
        offset = v.offset if v.offset is not None else -1
        return (v.kind.value, v.path, v.member or "", offset)

    violations.sort(key=_sort_key)
    return violations, scanned
