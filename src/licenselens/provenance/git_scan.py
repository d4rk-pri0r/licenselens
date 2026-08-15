"""Git reachable history and all-object provenance scanning."""

from __future__ import annotations

import subprocess
from pathlib import Path

from licenselens.provenance.git_ops import (
    cat_file_batch,
    cat_file_batch_types,
    dedupe_violations,
    find_git_dir,
    is_policy_readme_path,
    parse_raw_tree_names,
    run_git,
    scan_blob,
    scan_readme_blob,
    scan_refs_and_meta,
    scan_text_field,
)
from licenselens.provenance.match import path_component_matches
from licenselens.provenance.models import ScanMode, Violation, ViolationKind
from licenselens.provenance.token import TokenPolicy

_COMMIT_LOG_FORMAT = "%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x00%x00"


def scan_git_reachable(root: Path, policy: TokenPolicy) -> list[Violation]:
    """Scan every reachable commit/tree/blob path plus refs metadata."""
    mode = ScanMode.GIT_REACHABLE
    if find_git_dir(root) is None:
        return [
            Violation(
                kind=ViolationKind.UNREADABLE,
                path=".git",
                detail="not a git repository",
                mode=mode,
            )
        ]

    violations: list[Violation] = []
    violations.extend(scan_refs_and_meta(root, policy, mode))
    violations.extend(_scan_reachable_commits(root, policy, mode))
    violations.extend(_scan_reachable_blobs(root, policy, mode))
    return dedupe_violations(violations)


def scan_git_all_objects(root: Path, policy: TokenPolicy) -> list[Violation]:
    """Scan every local object including unreachable loose/packed blobs."""
    mode = ScanMode.GIT_ALL_OBJECTS
    if find_git_dir(root) is None:
        return [
            Violation(
                kind=ViolationKind.UNREADABLE,
                path=".git",
                detail="not a git repository",
                mode=mode,
            )
        ]

    violations: list[Violation] = []
    violations.extend(scan_refs_and_meta(root, policy, mode))

    listing = subprocess.run(
        ["git", "cat-file", "--batch-check", "--batch-all-objects"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if listing.returncode != 0:
        return [
            Violation(
                kind=ViolationKind.UNREADABLE,
                path=".git",
                detail="git cat-file --batch-all-objects failed",
                mode=mode,
            )
        ]

    blob_ids: list[str] = []
    commit_ids: list[str] = []
    tag_ids: list[str] = []
    tree_ids: list[str] = []
    for line in listing.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        obj_id, obj_type = parts[0], parts[1]
        match obj_type:
            case "blob":
                blob_ids.append(obj_id)
            case "commit":
                commit_ids.append(obj_id)
            case "tag":
                tag_ids.append(obj_id)
            case "tree":
                tree_ids.append(obj_id)
            case _:
                continue

    blob_data = cat_file_batch(root, blob_ids)
    text_ids = commit_ids + tag_ids + tree_ids
    text_data = cat_file_batch(root, text_ids)

    for obj_id in blob_ids:
        violations.extend(_scan_all_blob_data(policy, mode, obj_id, blob_data.get(obj_id)))

    for obj_id in commit_ids:
        raw = text_data.get(obj_id)
        if raw is None:
            continue
        text = raw.decode("utf-8", errors="replace")
        violations.extend(
            scan_text_field(
                policy,
                text,
                path=f"commit:{obj_id}",
                mode=mode,
                kind=ViolationKind.GIT_MESSAGE,
                object_id=obj_id,
            )
        )

    for obj_id in tag_ids:
        raw = text_data.get(obj_id)
        if raw is None:
            continue
        text = raw.decode("utf-8", errors="replace")
        violations.extend(
            scan_text_field(
                policy,
                text,
                path=f"tag:{obj_id}",
                mode=mode,
                kind=ViolationKind.GIT_METADATA,
                object_id=obj_id,
            )
        )

    hash_size = _hash_size_from_oids(blob_ids, commit_ids, tag_ids, tree_ids)
    for obj_id in tree_ids:
        raw = text_data.get(obj_id)
        if raw is None:
            continue
        violations.extend(_scan_all_tree_raw(policy, mode, obj_id, raw, hash_size=hash_size))

    return dedupe_violations(violations)


def _scan_reachable_commits(root: Path, policy: TokenPolicy, mode: ScanMode) -> list[Violation]:
    log = run_git(root, "log", "--all", f"--format={_COMMIT_LOG_FORMAT}", check=False)
    if log.returncode != 0 or not log.stdout.strip():
        return []

    violations: list[Violation] = []
    for record in log.stdout.split("\0\0"):
        record = record.strip("\n\0")
        if not record:
            continue
        parts = record.split("\0")
        if len(parts) < 6:
            continue
        commit = parts[0]
        meta = "\n".join(parts[:6])
        violations.extend(
            scan_text_field(
                policy,
                meta,
                path=f"commit:{commit}",
                mode=mode,
                kind=ViolationKind.GIT_MESSAGE,
                object_id=commit,
            )
        )
    return violations


def _scan_reachable_blobs(root: Path, policy: TokenPolicy, mode: ScanMode) -> list[Violation]:
    listing = run_git(root, "rev-list", "--objects", "--all", check=False)
    if listing.returncode != 0:
        return []

    oid_paths: dict[str, list[str]] = {}
    for line in listing.stdout.splitlines():
        if not line.strip():
            continue
        if " " not in line:
            continue
        obj_id, path = line.split(" ", 1)
        paths = oid_paths.setdefault(obj_id, [])
        if path not in paths:
            paths.append(path)

    if not oid_paths:
        return []

    type_map = cat_file_batch_types(root, oid_paths.keys())
    blob_ids = [oid for oid, obj_type in type_map.items() if obj_type == "blob"]
    blob_data = cat_file_batch(root, blob_ids)

    violations: list[Violation] = []
    for obj_id, paths in oid_paths.items():
        obj_type = type_map.get(obj_id)
        for path in paths:
            for part in path_component_matches(policy, path):
                violations.append(
                    Violation(
                        kind=ViolationKind.PATH,
                        path=path,
                        detail=f"reachable tree path component matches token: {part}",
                        mode=mode,
                        object_id=obj_id,
                    )
                )
            if obj_type != "blob":
                continue
            blob = blob_data.get(obj_id)
            if blob is None:
                violations.append(
                    Violation(
                        kind=ViolationKind.UNREADABLE,
                        path=path,
                        detail=f"unable to read blob {obj_id}",
                        mode=mode,
                        object_id=obj_id,
                    )
                )
                continue
            if is_policy_readme_path(path, policy):
                violations.extend(
                    scan_readme_blob(policy, blob, path=path, mode=mode, object_id=obj_id)
                )
            else:
                violations.extend(scan_blob(policy, blob, path=path, mode=mode, object_id=obj_id))
    return violations


def _scan_all_blob_data(
    policy: TokenPolicy,
    mode: ScanMode,
    obj_id: str,
    data: bytes | None,
) -> list[Violation]:
    if data is None:
        return [
            Violation(
                kind=ViolationKind.UNREADABLE,
                path=f"object:{obj_id}",
                detail="unable to read blob",
                mode=mode,
                object_id=obj_id,
            )
        ]
    return scan_blob(
        policy,
        data,
        path=f"object:{obj_id}",
        mode=mode,
        object_id=obj_id,
    )


def _scan_all_tree_raw(
    policy: TokenPolicy,
    mode: ScanMode,
    obj_id: str,
    data: bytes,
    *,
    hash_size: int,
) -> list[Violation]:
    violations: list[Violation] = []
    for name in parse_raw_tree_names(data, hash_size=hash_size):
        for part in path_component_matches(policy, name):
            violations.append(
                Violation(
                    kind=ViolationKind.PATH,
                    path=f"tree:{obj_id}/{name}",
                    detail=f"tree entry matches token: {part}",
                    mode=mode,
                    object_id=obj_id,
                )
            )
    return violations


def _hash_size_from_oids(*groups: list[str]) -> int:
    for group in groups:
        for oid in group:
            if len(oid) == 64:
                return 32
            if len(oid) == 40:
                return 20
    return 20
