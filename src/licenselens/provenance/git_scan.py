"""Git reachable history and all-object provenance scanning."""

from __future__ import annotations

import subprocess
from pathlib import Path

from licenselens.provenance.git_ops import (
    cat_file_blob,
    cat_file_text,
    dedupe_violations,
    find_git_dir,
    is_policy_readme_path,
    run_git,
    scan_blob,
    scan_readme_blob,
    scan_refs_and_meta,
    scan_text_field,
)
from licenselens.provenance.match import path_component_matches
from licenselens.provenance.models import ScanMode, Violation, ViolationKind
from licenselens.provenance.token import TokenPolicy


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

    commits = run_git(root, "rev-list", "--all").stdout.splitlines()
    for commit in commits:
        meta = run_git(
            root,
            "show",
            "-s",
            "--format=%H%n%an%n%ae%n%cn%n%ce%n%B",
            commit,
        ).stdout
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
        ls = run_git(root, "ls-tree", "-r", "-z", commit).stdout
        for record in ls.split("\0"):
            if not record.strip():
                continue
            try:
                meta_part, path = record.split("\t", 1)
            except ValueError:
                continue
            parts = meta_part.split()
            if len(parts) < 3:
                continue
            obj_type, obj_id = parts[1], parts[2]
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
            blob = cat_file_blob(root, obj_id)
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
                    scan_readme_blob(
                        policy, blob, path=path, mode=mode, object_id=obj_id
                    )
                )
            else:
                violations.extend(
                    scan_blob(policy, blob, path=path, mode=mode, object_id=obj_id)
                )
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

    for line in listing.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        obj_id, obj_type = parts[0], parts[1]
        match obj_type:
            case "blob":
                violations.extend(_scan_all_blob(root, policy, mode, obj_id))
            case "commit" | "tag":
                violations.extend(_scan_all_commit_or_tag(root, policy, mode, obj_id, obj_type))
            case "tree":
                violations.extend(_scan_all_tree(root, policy, mode, obj_id))
            case _:
                continue
    return dedupe_violations(violations)


def _scan_all_blob(
    root: Path, policy: TokenPolicy, mode: ScanMode, obj_id: str
) -> list[Violation]:
    data = cat_file_blob(root, obj_id)
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


def _scan_all_commit_or_tag(
    root: Path,
    policy: TokenPolicy,
    mode: ScanMode,
    obj_id: str,
    obj_type: str,
) -> list[Violation]:
    text = cat_file_text(root, obj_id)
    if text is None:
        return []
    kind = (
        ViolationKind.GIT_MESSAGE if obj_type == "commit" else ViolationKind.GIT_METADATA
    )
    return scan_text_field(
        policy,
        text,
        path=f"{obj_type}:{obj_id}",
        mode=mode,
        kind=kind,
        object_id=obj_id,
    )


def _scan_all_tree(
    root: Path, policy: TokenPolicy, mode: ScanMode, obj_id: str
) -> list[Violation]:
    text = cat_file_text(root, obj_id)
    if text is None:
        return []
    violations: list[Violation] = []
    for tree_line in text.splitlines():
        if "\t" not in tree_line:
            continue
        _meta, name = tree_line.split("\t", 1)
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
