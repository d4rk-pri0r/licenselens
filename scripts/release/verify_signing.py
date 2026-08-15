"""Release gate: enforce the Windows signing policy before production promotion.

Usage::

    python scripts/release/verify_signing.py --policy required --assets <dir>

Scans ``<dir>`` for the release assets (the signed-or-unsigned Windows ZIP plus
the ``signing-status.json`` marker emitted by the ``sign-windows`` job) and
enforces the policy:

  * ``required``  — fail unless a signed Windows artifact is present,
  * ``optional``  — allow unsigned (labeled test-only) but report it,
  * ``off``       — no check.

Exit 0 when the policy is satisfied, 2 when a required signature is missing.
This runs in the ``promote`` job so an unsigned Windows artifact can never enter
the production release channel when signing is required.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(REPO_ROOT / "src"))

from licenselens.release_guard import signing_gate  # noqa: E402


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Enforce the Windows signing policy.")
    parser.add_argument(
        "--policy",
        choices=("required", "optional", "off"),
        default="required",
        help="signing policy for the release channel (default: required)",
    )
    parser.add_argument(
        "--assets",
        type=Path,
        default=Path("release-assets"),
        help="directory holding the release assets (default: release-assets)",
    )
    args = parser.parse_args(argv)

    ok, message = signing_gate(args.policy, args.assets)
    if not ok:
        print(f"REJECT: {message}", file=sys.stderr)
        return 2
    print(f"signing gate ({args.policy}): {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
