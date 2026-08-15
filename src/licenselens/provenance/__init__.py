"""Fail-closed repository and Git provenance policy scanner."""

from __future__ import annotations

from licenselens.provenance.models import ScanMode, ScanResult, Violation, ViolationKind
from licenselens.provenance.scanner import (
    main_scan,
    result_to_json,
    run_scan,
    scan,
    scan_artifacts,
    scan_git_all_objects_mode,
    scan_git_reachable_mode,
    scan_workspace,
)
from licenselens.provenance.token import (
    EXPECTED_ALLOWED_ROW_SHA256,
    AllowedRow,
    TokenPolicy,
    TokenPolicyError,
    load_token_policy,
    parse_allowed_row,
)

__all__ = [
    "EXPECTED_ALLOWED_ROW_SHA256",
    "AllowedRow",
    "ScanMode",
    "ScanResult",
    "TokenPolicy",
    "TokenPolicyError",
    "Violation",
    "ViolationKind",
    "load_token_policy",
    "main_scan",
    "parse_allowed_row",
    "result_to_json",
    "run_scan",
    "scan",
    "scan_artifacts",
    "scan_git_all_objects_mode",
    "scan_git_reachable_mode",
    "scan_workspace",
]
