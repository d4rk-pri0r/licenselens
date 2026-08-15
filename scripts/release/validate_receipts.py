"""CLI: validate release trust receipts (Todo 18).

Usage::

    python scripts/release/validate_receipts.py path/to/receipt.json \\
        --expected-commit-sha <sha>

    python scripts/release/validate_receipts.py path/to/receipts-dir \\
        --expected-commit-sha <sha> --require-kinds release,sbom,attestation

Exit 0 when every receipt is schema-valid; exit 1 on any problem. Prints a
JSON summary on stdout so CI can capture the verdict as an artifact.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from licenselens.release_receipts import (  # noqa: E402
    validate_receipt,
    validate_receipts,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate release trust receipts.")
    parser.add_argument(
        "path",
        type=Path,
        help="receipt JSON file or directory of receipt JSON files",
    )
    parser.add_argument(
        "--expected-commit-sha",
        default=None,
        help="immutable final commit SHA every receipt must bind",
    )
    parser.add_argument(
        "--require-kinds",
        default="",
        help="comma-separated receipt kinds that must be present",
    )
    parser.add_argument(
        "--require-success",
        action="store_true",
        help="require conclusion in {success,passed,pass,ok}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit JSON summary on stdout (default: human + JSON)",
    )
    args = parser.parse_args(argv)

    kinds = tuple(k.strip() for k in args.require_kinds.split(",") if k.strip())
    target = args.path
    if target.is_dir() or (kinds and target.is_file()):
        result = validate_receipts(
            target,
            expected_commit_sha=args.expected_commit_sha,
            require_kinds=kinds or None,
            require_success=args.require_success,
        )
    else:
        result = validate_receipt(
            target,
            expected_commit_sha=args.expected_commit_sha,
            require_success=args.require_success,
        )

    payload = result.to_dict()
    print(json.dumps(payload, indent=2))
    if result.ok:
        print("RECEIPT_VALID", file=sys.stderr)
        return 0
    print("RECEIPT_REJECTED", file=sys.stderr)
    for problem in result.problems:
        print(f"  - {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
