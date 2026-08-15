"""Low-level git helpers and metadata surface scanning."""

from __future__ import annotations

import subprocess
from pathlib import Path

from licenselens.provenance.archive_scan import (
    is_archive_path,
    scan_archive_bytes,
    scan_bytes_for_token,
)
from licenselens.provenance.match import path_component_matches, text_matches
from licenselens.provenance.models import ScanMode, Violation, ViolationKind
from licenselens.provenance.token import TokenPolicy, TokenPolicyError, parse_allowed_row


class GitScanError(Exception):
    """Git subprocess failure that should surface as a policy/scan error."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def run_git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a git command in ``root`` and optionally require exit 0."""
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise GitScanError(
            f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result


def find_git_dir(root: Path) -> Path | None:
    """Return the .git directory for root, or None if not a git work tree."""
    try:
        result = run_git(root, "rev-parse", "--git-dir")
    except GitScanError:
        return None
    git_dir = Path(result.stdout.strip())
    if not git_dir.is_absolute():
        git_dir = (root / git_dir).resolve()
    return git_dir if git_dir.exists() else None


def cat_file_blob(root: Path, obj_id: str) -> bytes | None:
    """Return blob bytes or None if unreadable."""
    data = subprocess.run(
        ["git", "cat-file", "blob", obj_id],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if data.returncode != 0:
        return None
    return data.stdout


def cat_file_text(root: Path, obj_id: str) -> str | None:
    """Return pretty-printed object text or None if unreadable."""
    data = subprocess.run(
        ["git", "cat-file", "-p", obj_id],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if data.returncode != 0:
        return None
    return data.stdout


def zip_magic(data: bytes) -> bool:
    return data[:2] == b"PK"


def tar_magic(data: bytes) -> bool:
    if len(data) >= 265 and data[257:262] == b"ustar":
        return True
    return data[:2] in {b"\x1f\x8b", b"BZ", b"\xfd7"}


def scan_text_field(
    policy: TokenPolicy,
    text: str,
    *,
    path: str,
    mode: ScanMode,
    kind: ViolationKind,
    object_id: str | None = None,
) -> list[Violation]:
    """Scan a free-text git metadata field for token variants."""
    violations: list[Violation] = []
    for start, _end, matched in text_matches(policy, text):
        violations.append(
            Violation(
                kind=kind,
                path=path,
                detail=f"token variant in git metadata at offset {start}",
                mode=mode,
                object_id=object_id,
                offset=start,
                snippet_hex=matched.encode("utf-8", errors="replace")[:24].hex(),
            )
        )
    return violations


def scan_blob(
    policy: TokenPolicy,
    data: bytes,
    *,
    path: str,
    mode: ScanMode,
    object_id: str,
) -> list[Violation]:
    """Scan one blob's path components and payload."""
    violations: list[Violation] = []
    if not path.startswith("object:"):
        for part in path_component_matches(policy, path):
            violations.append(
                Violation(
                    kind=ViolationKind.PATH,
                    path=path,
                    detail=f"git tree path component matches token: {part}",
                    mode=mode,
                    object_id=object_id,
                )
            )
    name = Path(path).name
    if is_archive_path(Path(name)) or zip_magic(data) or tar_magic(data):
        violations.extend(
            scan_archive_bytes(
                policy,
                data,
                path=path,
                mode=mode,
                object_id=object_id,
            )
        )
        return violations
    if _blob_looks_like_readme(data):
        return scan_readme_blob(policy, data, path=path, mode=mode, object_id=object_id)
    violations.extend(
        scan_bytes_for_token(
            policy,
            data,
            path=path,
            mode=mode,
            object_id=object_id,
            kind=ViolationKind.GIT_OBJECT,
        )
    )
    return violations


def _blob_looks_like_readme(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    try:
        parse_allowed_row(text)
    except TokenPolicyError:
        return False
    return True


def is_policy_readme_path(path: str, policy: TokenPolicy) -> bool:
    return Path(path).name.casefold() == "readme.md"


def scan_readme_blob(
    policy: TokenPolicy,
    data: bytes,
    *,
    path: str,
    mode: ScanMode,
    object_id: str,
) -> list[Violation]:
    """Scan a README blob, permitting only its own allowed comparison row."""
    text = data.decode("utf-8", errors="replace")
    violations: list[Violation] = []
    allowed = policy.allowed_row
    for start, end, matched in text_matches(policy, text):
        if start >= allowed.byte_start and end <= allowed.byte_end:
            continue
        try:
            local = parse_allowed_row(text)
            if start >= local.byte_start and end <= local.byte_end:
                continue
        except TokenPolicyError:
            pass
        violations.append(
            Violation(
                kind=ViolationKind.GIT_OBJECT,
                path=path,
                detail=f"token variant outside allowed README row at offset {start}",
                mode=mode,
                object_id=object_id,
                offset=start,
                snippet_hex=matched.encode("utf-8", errors="replace")[:24].hex(),
            )
        )
    return violations


def scan_refs_and_meta(root: Path, policy: TokenPolicy, mode: ScanMode) -> list[Violation]:
    """Scan refs, stash, reflog, and notes for token variants."""
    violations: list[Violation] = []
    refs = run_git(root, "for-each-ref", "--format=%(refname) %(objectname)").stdout
    violations.extend(
        scan_text_field(
            policy,
            refs,
            path="refs",
            mode=mode,
            kind=ViolationKind.GIT_METADATA,
        )
    )
    stash = run_git(root, "stash", "list", check=False)
    if stash.returncode == 0 and stash.stdout.strip():
        violations.extend(
            scan_text_field(
                policy,
                stash.stdout,
                path="stash",
                mode=mode,
                kind=ViolationKind.GIT_METADATA,
            )
        )
    reflog = run_git(root, "reflog", "--all", check=False)
    if reflog.returncode == 0 and reflog.stdout.strip():
        violations.extend(
            scan_text_field(
                policy,
                reflog.stdout,
                path="reflog",
                mode=mode,
                kind=ViolationKind.GIT_METADATA,
            )
        )
    notes = run_git(root, "notes", "list", check=False)
    if notes.returncode == 0:
        for line in notes.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            note_obj = parts[0]
            body = cat_file_text(root, note_obj)
            if body is None:
                continue
            violations.extend(
                scan_text_field(
                    policy,
                    body,
                    path=f"notes:{note_obj}",
                    mode=mode,
                    kind=ViolationKind.GIT_METADATA,
                    object_id=note_obj,
                )
            )
    return violations


def dedupe_violations(violations: list[Violation]) -> list[Violation]:
    """Stable de-duplication and sort for git scan findings."""
    seen: set[tuple[str, str, str | None, str | None, int | None]] = set()
    out: list[Violation] = []
    for item in violations:
        key = (item.kind.value, item.path, item.member, item.object_id, item.offset)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    out.sort(
        key=lambda v: (
            v.mode.value,
            v.kind.value,
            v.path,
            v.member or "",
            v.offset if v.offset is not None else -1,
        )
    )
    return out
