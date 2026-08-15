"""Release gate: require attestation + SBOM subjects before production promote.

Usage::

    python scripts/release/verify_attestation.py \\
        --bundle release-bundle \\
        --receipts dist-receipts \\
        --require-kinds sbom,attestation,signing,release

Fails closed when required receipts are missing, when the release receipt's
SHA256SUMS does not cover the bundle, or when signing/attestation kinds are
absent under a required policy. Config-only placeholders never pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from licenselens.release_receipts import (  # noqa: E402
    validate_receipts,
    verify_sha256sums,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Require attestation/SBOM/signing receipts before promote."
    )
    parser.add_argument("--bundle", type=Path, default=Path("release-bundle"))
    parser.add_argument("--receipts", type=Path, default=Path("dist-receipts"))
    parser.add_argument(
        "--expected-commit-sha",
        default=None,
        help="immutable final commit SHA receipts must bind",
    )
    parser.add_argument(
        "--require-kinds",
        default="sbom,attestation,signing,release",
        help="comma-separated receipt kinds required for promote",
    )
    args = parser.parse_args(argv)

    problems: list[str] = []

    if not args.bundle.is_dir():
        problems.append(f"missing release bundle: {args.bundle}")
    else:
        problems.extend(verify_sha256sums(args.bundle))

    kinds = tuple(k.strip() for k in args.require_kinds.split(",") if k.strip())
    if not args.receipts.exists():
        problems.append(f"missing receipts directory: {args.receipts}")
    else:
        result = validate_receipts(
            args.receipts,
            expected_commit_sha=args.expected_commit_sha,
            require_kinds=kinds or None,
            require_success=True,
        )
        problems.extend(result.problems)

    # signing-status.json inside the bundle must claim signed=true when signing required
    if "signing" in kinds and args.bundle.is_dir():
        status_path = args.bundle / "signing-status.json"
        if status_path.is_file():
            try:
                status = json.loads(status_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                problems.append("signing-status.json is malformed")
            else:
                if not bool(status.get("signed")):
                    problems.append(
                        "signing required but signing-status.json reports signed=false"
                    )
        else:
            # receipt kind may still prove signing; marker absence is a soft signal
            pass

    payload = {"ok": not problems, "problems": problems}
    print(json.dumps(payload, indent=2))
    if problems:
        print("ATTESTATION_GATE_REJECTED", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    print("ATTESTATION_GATE_OK", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
