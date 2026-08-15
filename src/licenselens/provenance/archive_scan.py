"""Fail-closed archive member and payload scanning."""

from __future__ import annotations

import io
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

from licenselens.provenance.match import path_component_matches, text_matches
from licenselens.provenance.models import ScanMode, Violation, ViolationKind
from licenselens.provenance.token import TokenPolicy

ARCHIVE_SUFFIXES: frozenset[str] = frozenset(
    {
        ".zip",
        ".whl",
        ".egg",
        ".jar",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".dist-info",  # not an archive; ignored by is_archive_path
    }
)

_ZIP_SUFFIXES: frozenset[str] = frozenset({".zip", ".whl", ".egg", ".jar"})
_TAR_SUFFIXES: frozenset[str] = frozenset(
    {".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".gz", ".bz2", ".xz"}
)


def is_archive_path(path: Path) -> bool:
    name = path.name.casefold()
    if name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return True
    return path.suffix.casefold() in _ZIP_SUFFIXES or path.suffix.casefold() in {
        ".tar",
        ".tgz",
        ".tbz2",
        ".txz",
        ".gz",
        ".bz2",
        ".xz",
    }


def _snippet_hex(data: bytes, offset: int, length: int = 24) -> str:
    end = min(len(data), offset + length)
    return data[offset:end].hex()


def scan_bytes_for_token(
    policy: TokenPolicy,
    data: bytes,
    *,
    path: str,
    mode: ScanMode,
    object_id: str | None = None,
    member: str | None = None,
    kind: ViolationKind = ViolationKind.CONTENT,
) -> list[Violation]:
    """Scan raw bytes via UTF-8 (replace) and lossy latin-1 views."""
    violations: list[Violation] = []
    views: list[tuple[str, str]] = [
        ("utf-8", data.decode("utf-8", errors="replace")),
        ("latin-1", data.decode("latin-1", errors="replace")),
    ]
    seen_offsets: set[int] = set()
    for _label, text in views:
        for start, _end, matched in text_matches(policy, text):
            if start in seen_offsets:
                continue
            seen_offsets.add(start)
            # Prefer binary kind when NULs present or non-text ratio is high.
            use_kind = kind
            if b"\x00" in data and kind == ViolationKind.CONTENT:
                use_kind = ViolationKind.BINARY
            snippet = matched.encode("utf-8", errors="replace")
            violations.append(
                Violation(
                    kind=use_kind,
                    path=path,
                    detail=f"token variant match at offset {start}",
                    mode=mode,
                    object_id=object_id,
                    member=member,
                    offset=start,
                    snippet_hex=snippet[:24].hex(),
                )
            )
    return violations


def _zip_members(path: Path) -> Iterator[tuple[str, bytes]]:
    with zipfile.ZipFile(path) as zf:
        # Test integrity first — truncated/corrupt central directories raise.
        bad = zf.testzip()
        if bad is not None:
            raise zipfile.BadZipFile(f"corrupt member: {bad}")
        for info in zf.infolist():
            if info.is_dir():
                yield info.filename, b""
                continue
            yield info.filename, zf.read(info)


def _tar_members(path: Path) -> Iterator[tuple[str, bytes]]:
    with tarfile.open(path, mode="r:*") as tf:
        for member in tf.getmembers():
            name = member.name
            if not member.isfile():
                yield name, b""
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                yield name, b""
                continue
            with extracted:
                yield name, extracted.read()


def iter_archive_members(path: Path) -> Iterator[tuple[str, bytes]]:
    """Yield (member_name, payload) or raise for malformed archives."""
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    if suffix in _ZIP_SUFFIXES or name.endswith(".whl"):
        yield from _zip_members(path)
        return
    # tar and compressed tars
    yield from _tar_members(path)


def scan_archive_file(
    policy: TokenPolicy,
    path: Path,
    *,
    relative: str,
    mode: ScanMode,
) -> list[Violation]:
    """Scan one archive path fail-closed."""
    violations: list[Violation] = []
    try:
        members = list(iter_archive_members(path))
    except (zipfile.BadZipFile, tarfile.TarError, tarfile.ReadError, OSError, EOFError) as exc:
        violations.append(
            Violation(
                kind=ViolationKind.MALFORMED_ARCHIVE,
                path=relative,
                detail=f"malformed or unreadable archive: {exc.__class__.__name__}",
                mode=mode,
            )
        )
        return violations

    for member_name, payload in members:
        for part in path_component_matches(policy, member_name):
            violations.append(
                Violation(
                    kind=ViolationKind.ARCHIVE_MEMBER,
                    path=relative,
                    detail=f"archive member path component matches token: {part}",
                    mode=mode,
                    member=member_name,
                )
            )
        if payload:
            violations.extend(
                scan_bytes_for_token(
                    policy,
                    payload,
                    path=relative,
                    mode=mode,
                    member=member_name,
                    kind=ViolationKind.ARCHIVE_CONTENT,
                )
            )
    return violations


def scan_archive_bytes(
    policy: TokenPolicy,
    data: bytes,
    *,
    path: str,
    mode: ScanMode,
    object_id: str | None = None,
) -> list[Violation]:
    """Scan archive bytes from a git blob or in-memory artifact."""
    violations: list[Violation] = []
    bio = io.BytesIO(data)
    try:
        if zipfile.is_zipfile(bio):
            bio.seek(0)
            with zipfile.ZipFile(bio) as zf:
                bad = zf.testzip()
                if bad is not None:
                    raise zipfile.BadZipFile(f"corrupt member: {bad}")
                members = []
                for info in zf.infolist():
                    payload = b"" if info.is_dir() else zf.read(info)
                    members.append((info.filename, payload))
        else:
            bio.seek(0)
            with tarfile.open(fileobj=bio, mode="r:*") as tf:
                members = []
                for member in tf.getmembers():
                    if member.isfile():
                        extracted = tf.extractfile(member)
                        payload = extracted.read() if extracted is not None else b""
                    else:
                        payload = b""
                    members.append((member.name, payload))
    except (zipfile.BadZipFile, tarfile.TarError, tarfile.ReadError, OSError, EOFError) as exc:
        return [
            Violation(
                kind=ViolationKind.MALFORMED_ARCHIVE,
                path=path,
                detail=f"malformed or unreadable archive: {exc.__class__.__name__}",
                mode=mode,
                object_id=object_id,
            )
        ]

    for member_name, payload in members:
        for part in path_component_matches(policy, member_name):
            violations.append(
                Violation(
                    kind=ViolationKind.ARCHIVE_MEMBER,
                    path=path,
                    detail=f"archive member path component matches token: {part}",
                    mode=mode,
                    object_id=object_id,
                    member=member_name,
                )
            )
        if payload:
            violations.extend(
                scan_bytes_for_token(
                    policy,
                    payload,
                    path=path,
                    mode=mode,
                    object_id=object_id,
                    member=member_name,
                    kind=ViolationKind.ARCHIVE_CONTENT,
                )
            )
    return violations
