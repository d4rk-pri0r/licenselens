"""RED contract: release receipt schema rejects bad proof (todo 18 gate)."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

CANDIDATE_MODULES = (
    "licenselens.release_receipts",
    "licenselens.receipts",
)
CANDIDATE_SCRIPTS = (
    ROOT / "scripts" / "release" / "validate_receipts.py",
    ROOT / "scripts" / "release" / "validate_receipt.py",
    ROOT / "scripts" / "validate_release_receipts.py",
)


def _load_receipt_validator() -> Any:
    for name in CANDIDATE_MODULES:
        try:
            return importlib.import_module(name)
        except ImportError:
            continue

    for script in CANDIDATE_SCRIPTS:
        if not script.is_file():
            continue
        mod_name = f"receipt_validator_{script.stem}"
        spec = importlib.util.spec_from_file_location(mod_name, script)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = module
        spec.loader.exec_module(module)
        return module

    # Direct import of the expected package surface — RED signature is ImportError.
    return importlib.import_module("licenselens.release_receipts")


def _validate_api(module: Any) -> Any:
    for name in (
        "validate_receipt",
        "validate_receipts",
        "validate",
        "check_receipt",
    ):
        func = getattr(module, name, None)
        if callable(func):
            return func
    raise AssertionError(
        "receipt validator must expose validate_receipt/validate_receipts callable"
    )


def _problems(result: Any) -> list[str]:
    if result is None:
        return []
    if isinstance(result, list):
        return [str(item) for item in result]
    if isinstance(result, dict):
        for key in ("problems", "errors", "violations", "findings"):
            value = result.get(key)
            if isinstance(value, list):
                return [str(item) for item in value]
        if result.get("ok") is False or result.get("valid") is False:
            return [str(result)]
        return []
    if result is False:
        return ["invalid"]
    problems = getattr(result, "problems", None) or getattr(result, "errors", None)
    if problems is not None:
        return [str(item) for item in problems]
    if getattr(result, "ok", None) is False or getattr(result, "valid", None) is False:
        return [str(result)]
    return []


def test_release_receipt_validator_rejects_wrong_sha_config_only_and_missing_artifacts() -> None:
    """Receipt schema must reject wrong SHA, config-only proof, and missing artifacts."""
    module = _load_receipt_validator()
    validate = _validate_api(module)

    final_sha = "a" * 40
    wrong_sha_receipt = {
        "kind": "ci",
        "commit_sha": "b" * 40,
        "expected_commit_sha": final_sha,
        "run_url": "https://example.invalid/run/1",
        "run_id": "1",
        "conclusion": "success",
        "artifacts": {
            "licenselens-0.0.0-py3-none-any.whl": {"sha256": "c" * 64},
        },
    }
    wrong = _problems(validate(wrong_sha_receipt, expected_commit_sha=final_sha))
    assert wrong, "receipt validator must reject wrong commit SHA"

    config_only = {
        "kind": "pages",
        "commit_sha": final_sha,
        "conclusion": "success",
        "proof": "workflow_configured",
        "artifacts": {},
    }
    config_problems = _problems(validate(config_only, expected_commit_sha=final_sha))
    assert config_problems, "receipt validator must reject config-only proof"

    missing_artifacts = {
        "kind": "release",
        "commit_sha": final_sha,
        "run_url": "https://example.invalid/run/2",
        "run_id": "2",
        "conclusion": "success",
        "artifacts": {},
    }
    missing = _problems(validate(missing_artifacts, expected_commit_sha=final_sha))
    assert missing, "receipt validator must reject missing artifacts"
