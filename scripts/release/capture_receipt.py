"""CLI: capture a release trust receipt for one proof surface (Todo 18).

Usage::

    python scripts/release/capture_receipt.py \\
        --kind release \\
        --commit-sha "$GITHUB_SHA" \\
        --run-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" \\
        --run-id "$GITHUB_RUN_ID" \\
        --conclusion success \\
        --artifacts-dir release-bundle \\
        --output dist-receipts/release.json

The receipt binds run identity, the immutable commit SHA, and every artifact
hash under ``--artifacts-dir`` (or an explicit ``--artifact name=sha256`` list).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from licenselens.release_receipts import (  # noqa: E402
    RECEIPT_KINDS,
    make_receipt,
    validate_receipt,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture a release trust receipt.")
    parser.add_argument("--kind", required=True, choices=RECEIPT_KINDS)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--conclusion", default="success")
    parser.add_argument(
        "--expected-commit-sha",
        default=None,
        help="optional expected final SHA (defaults to --commit-sha)",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="directory of files to hash into the receipt",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="NAME=SHA256",
        help="explicit artifact binding (repeatable)",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="write even if the receipt fails schema validation",
    )
    args = parser.parse_args(argv)

    artifacts: dict[str, dict[str, str]] = {}
    if args.artifacts_dir is not None:
        from licenselens.release_receipts import build_artifact_map

        artifacts.update(build_artifact_map(args.artifacts_dir))
    for item in args.artifact:
        if "=" not in item:
            print(f"invalid --artifact {item!r} (want NAME=SHA256)", file=sys.stderr)
            return 2
        name, digest = item.split("=", 1)
        artifacts[name.strip()] = {"sha256": digest.strip().lower()}

    receipt = make_receipt(
        kind=args.kind,
        commit_sha=args.commit_sha,
        run_url=args.run_url,
        run_id=args.run_id,
        conclusion=args.conclusion,
        artifacts=artifacts,
        expected_commit_sha=args.expected_commit_sha or args.commit_sha,
    )

    result = validate_receipt(
        receipt,
        expected_commit_sha=args.expected_commit_sha or args.commit_sha,
    )
    if not result.ok and not args.no_validate:
        print("RECEIPT_CAPTURE_REJECTED", file=sys.stderr)
        for problem in result.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
