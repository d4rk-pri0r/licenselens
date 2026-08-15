"""Low-level git helpers and metadata surface scanning."""

from __future__ import annotations

import subprocess
from collections.abc import Iterable, Sequence
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


def cat_file_batch(root: Path, object_ids: Sequence[str] | Iterable[str]) -> dict[str, bytes]:
    """Read many git objects in one ``git cat-file --batch`` subprocess.

    Returns a mapping of object id -> raw bytes for objects that were present and
    well-formed. Missing, ambiguous, or malformed entries are omitted rather than
    failing the whole batch.
    """
    unique_ids = list(dict.fromkeys(object_ids))
    if not unique_ids:
        return {}

    payload = "".join(f"{oid}\n" for oid in unique_ids).encode("ascii")
    result = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=root,
        check=False,
        input=payload,
        capture_output=True,
    )
    if result.returncode != 0 and not result.stdout:
        return {}
    return _parse_cat_file_batch(result.stdout)


def cat_file_batch_types(root: Path, object_ids: Sequence[str] | Iterable[str]) -> dict[str, str]:
    """Return object id -> type via one ``git cat-file --batch-check`` call."""
    unique_ids = list(dict.fromkeys(object_ids))
    if not unique_ids:
        return {}

    payload = "".join(f"{oid}\n" for oid in unique_ids)
    result = subprocess.run(
        ["git", "cat-file", "--batch-check"],
        cwd=root,
        check=False,
        input=payload,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 and not result.stdout:
        return {}

    types: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        oid, status = parts[0], parts[1]
        if status in {"missing", "ambiguous"}:
            continue
        types[oid] = status
    return types


def _parse_cat_file_batch(data: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    index = 0
    length = len(data)
    while index < length:
        newline = data.find(b"\n", index)
        if newline < 0:
            break
        header = data[index:newline].decode("ascii", errors="replace")
        index = newline + 1
        parts = header.split()
        if len(parts) == 2 and parts[1] in {"missing", "ambiguous"}:
            continue
        if len(parts) < 3:
            continue
        oid = parts[0]
        try:
            size = int(parts[2])
        except ValueError:
            continue
        if size < 0 or index + size > length:
            break
        content = data[index : index + size]
        index += size
        if index < length and data[index : index + 1] == b"\n":
            index += 1
        out[oid] = content
    return out


def parse_raw_tree_names(data: bytes, *, hash_size: int) -> list[str]:
    names: list[str] = []
    index = 0
    length = len(data)
    while index < length:
        space = data.find(b" ", index)
        if space < 0:
            break
        nul = data.find(b"\0", space + 1)
        if nul < 0:
            break
        name = data[space + 1 : nul].decode("utf-8", errors="replace")
        names.append(name)
        index = nul + 1 + hash_size
        if index > length:
            break
    return names


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
        b_start = len(text[:start].encode("utf-8"))
        b_end = len(text[:end].encode("utf-8"))
        if b_start >= allowed.byte_start and b_end <= allowed.byte_end:
            continue
        try:
            local = parse_allowed_row(text)
            if b_start >= local.byte_start and b_end <= local.byte_end:
                continue
        except TokenPolicyError:
            pass
        violations.append(
            Violation(
                kind=ViolationKind.GIT_OBJECT,
                path=path,
                detail=f"token variant outside allowed README row at offset {b_start}",
                mode=mode,
                object_id=object_id,
                offset=b_start,
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
