"""Orchestrate provenance policy scans across workspace, git, and artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from licenselens.provenance.archive_scan import is_archive_path, scan_archive_file
from licenselens.provenance.git_scan import scan_git_all_objects, scan_git_reachable
from licenselens.provenance.models import (
    JSON_SEPARATORS,
    ScanMode,
    ScanResult,
    Violation,
    ViolationKind,
)
from licenselens.provenance.token import TokenPolicy, TokenPolicyError, load_token_policy
from licenselens.provenance.workspace import scan_workspace_tree


def _result(
    *,
    mode: ScanMode,
    root: Path,
    policy: TokenPolicy | None,
    violations: list[Violation],
    scanned_paths: int = 0,
) -> ScanResult:
    ordered = sorted(
        violations,
        key=lambda v: (
            v.mode.value,
            v.kind.value,
            v.path,
            v.member or "",
            v.object_id or "",
            v.offset if v.offset is not None else -1,
            v.detail,
        ),
    )
    status = "clean" if not ordered else "violations"
    return ScanResult(
        status=status,
        mode=mode,
        root=root.as_posix(),
        violations=tuple(ordered),
        allowed_row_sha256=policy.allowed_row.row_sha256 if policy else None,
        policy_readme=policy.policy_readme.as_posix() if policy else None,
        scanned_paths=scanned_paths,
    )


def _load_policy(
    root: Path,
    *,
    policy_readme: Path | None,
    require_expected_digest: bool,
    mode: ScanMode,
) -> tuple[TokenPolicy | None, list[Violation]]:
    try:
        policy = load_token_policy(
            root,
            policy_readme=policy_readme,
            require_expected_digest=require_expected_digest,
        )
    except TokenPolicyError as exc:
        return None, [
            Violation(
                kind=ViolationKind.POLICY,
                path="README.md",
                detail=str(exc),
                mode=mode,
            )
        ]
    return policy, []


def scan_workspace(
    root: Path | str,
    *,
    policy_readme: Path | str | None = None,
    require_expected_digest: bool = False,
) -> ScanResult:
    """Scan a working tree (tracked + untracked + ignored files).

    This is the primary API used by RED contracts and library callers.
    """
    root_path = Path(root).expanduser().resolve()
    readme = Path(policy_readme).expanduser().resolve() if policy_readme else None
    policy, early = _load_policy(
        root_path,
        policy_readme=readme,
        require_expected_digest=require_expected_digest,
        mode=ScanMode.WORKSPACE,
    )
    if policy is None:
        return _result(
            mode=ScanMode.WORKSPACE,
            root=root_path,
            policy=None,
            violations=early,
        )
    violations, scanned = scan_workspace_tree(root_path, policy)
    return _result(
        mode=ScanMode.WORKSPACE,
        root=root_path,
        policy=policy,
        violations=violations,
        scanned_paths=scanned,
    )


def scan_git_reachable_mode(
    root: Path | str,
    *,
    policy_readme: Path | str | None = None,
    require_expected_digest: bool = False,
) -> ScanResult:
    """Scan every reachable git commit/tree/blob and ref metadata."""
    root_path = Path(root).expanduser().resolve()
    readme = Path(policy_readme).expanduser().resolve() if policy_readme else None
    policy, early = _load_policy(
        root_path,
        policy_readme=readme,
        require_expected_digest=require_expected_digest,
        mode=ScanMode.GIT_REACHABLE,
    )
    if policy is None:
        return _result(
            mode=ScanMode.GIT_REACHABLE,
            root=root_path,
            policy=None,
            violations=early,
        )
    violations = scan_git_reachable(root_path, policy)
    return _result(
        mode=ScanMode.GIT_REACHABLE,
        root=root_path,
        policy=policy,
        violations=violations,
        scanned_paths=len(violations),
    )


def scan_git_all_objects_mode(
    root: Path | str,
    *,
    policy_readme: Path | str | None = None,
    require_expected_digest: bool = False,
) -> ScanResult:
    """Scan all local git objects including unreachable ones."""
    root_path = Path(root).expanduser().resolve()
    readme = Path(policy_readme).expanduser().resolve() if policy_readme else None
    policy, early = _load_policy(
        root_path,
        policy_readme=readme,
        require_expected_digest=require_expected_digest,
        mode=ScanMode.GIT_ALL_OBJECTS,
    )
    if policy is None:
        return _result(
            mode=ScanMode.GIT_ALL_OBJECTS,
            root=root_path,
            policy=None,
            violations=early,
        )
    violations = scan_git_all_objects(root_path, policy)
    return _result(
        mode=ScanMode.GIT_ALL_OBJECTS,
        root=root_path,
        policy=policy,
        violations=violations,
        scanned_paths=len(violations),
    )


def scan_artifacts(
    root: Path | str,
    *,
    policy_readme: Path | str | None = None,
    require_expected_digest: bool = False,
) -> ScanResult:
    """Scan wheel/sdist/zip/tar artifacts under root (recursive)."""
    root_path = Path(root).expanduser().resolve()
    readme = Path(policy_readme).expanduser().resolve() if policy_readme else None
    mode = ScanMode.ARTIFACTS
    policy, early = _load_policy(
        root_path,
        policy_readme=readme,
        require_expected_digest=require_expected_digest,
        mode=mode,
    )
    if policy is None:
        return _result(mode=mode, root=root_path, policy=None, violations=early)

    violations: list[Violation] = []
    scanned = 0
    for path in sorted(root_path.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if not is_archive_path(path):
            continue
        scanned += 1
        try:
            relative = path.resolve().relative_to(root_path).as_posix()
        except ValueError:
            relative = path.name
        violations.extend(scan_archive_file(policy, path, relative=relative, mode=mode))
    return _result(
        mode=mode,
        root=root_path,
        policy=policy,
        violations=violations,
        scanned_paths=scanned,
    )


def run_scan(
    root: Path | str,
    *,
    mode: ScanMode | str = ScanMode.WORKSPACE,
    policy_readme: Path | str | None = None,
    require_expected_digest: bool = False,
) -> ScanResult:
    """Dispatch a scan by mode name."""
    resolved = ScanMode(mode) if not isinstance(mode, ScanMode) else mode
    match resolved:
        case ScanMode.WORKSPACE:
            return scan_workspace(
                root,
                policy_readme=policy_readme,
                require_expected_digest=require_expected_digest,
            )
        case ScanMode.GIT_REACHABLE:
            return scan_git_reachable_mode(
                root,
                policy_readme=policy_readme,
                require_expected_digest=require_expected_digest,
            )
        case ScanMode.GIT_ALL_OBJECTS:
            return scan_git_all_objects_mode(
                root,
                policy_readme=policy_readme,
                require_expected_digest=require_expected_digest,
            )
        case ScanMode.ARTIFACTS:
            return scan_artifacts(
                root,
                policy_readme=policy_readme,
                require_expected_digest=require_expected_digest,
            )
        case unreachable:
            from typing import assert_never

            assert_never(unreachable)


# Aliases expected by flexible RED contract loaders.
scan = scan_workspace
main_scan = scan_workspace


def result_to_json(result: ScanResult) -> str:
    """Deterministic JSON: sorted keys, compact separators, no timestamps."""
    return json.dumps(result.to_dict(), sort_keys=True, separators=JSON_SEPARATORS) + "\n"
