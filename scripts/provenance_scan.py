#!/usr/bin/env python3
"""CLI entrypoint for the fail-closed provenance policy scanner.

Modes:
  --workspace         working tree (tracked + untracked + ignored)
  --git-reachable     every reachable commit/tree/blob + refs metadata
  --git-all-objects   unreachable loose/packed objects too
  --artifacts         wheel/sdist/zip/tar members + binary strings

JSON output is deterministic (sorted keys, no timestamps). Binary payloads are
never emitted raw — only offsets and short hex snippets.

Run:
  uv run python scripts/provenance_scan.py --workspace --root . --json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as a script without install when src/ is on PYTHONPATH (pytest)
# or when invoked via `uv run` from the repo root.
_REPO = Path(__file__).resolve().parent.parent
_SRC = _REPO / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from licenselens.provenance.models import ScanMode  # noqa: E402
from licenselens.provenance.scanner import (  # noqa: E402
    main_scan,
    result_to_json,
    run_scan,
    scan,
    scan_workspace,
)

# Alias retained for importers that expect run_scan_api.
run_scan_api = run_scan

__all__ = [
    "main",
    "main_scan",
    "run_scan_api",
    "scan",
    "scan_workspace",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provenance_scan",
        description="Fail-closed repository + Git provenance policy scanner",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--workspace", action="store_true", help="scan working tree")
    mode.add_argument(
        "--git-reachable",
        action="store_true",
        help="scan reachable commits/trees/blobs and refs",
    )
    mode.add_argument(
        "--git-all-objects",
        action="store_true",
        help="scan all local git objects including unreachable",
    )
    mode.add_argument(
        "--artifacts",
        action="store_true",
        help="scan wheel/sdist/zip/tar artifacts under root",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="scan root (default: cwd); recorded once in JSON output",
    )
    parser.add_argument(
        "--policy-readme",
        type=Path,
        default=None,
        help="README.md used to derive the allowed comparison-table token",
    )
    parser.add_argument(
        "--require-expected-digest",
        action="store_true",
        help="require the allowed row SHA-256 to match the pinned production digest",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit deterministic JSON (default when stdout is not a TTY)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write JSON to this path in addition to stdout",
    )
    return parser


def _selected_mode(args: argparse.Namespace) -> ScanMode:
    if args.workspace:
        return ScanMode.WORKSPACE
    if args.git_reachable:
        return ScanMode.GIT_REACHABLE
    if args.git_all_objects:
        return ScanMode.GIT_ALL_OBJECTS
    if args.artifacts:
        return ScanMode.ARTIFACTS
    raise AssertionError("no scan mode selected")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    mode = _selected_mode(args)
    result = run_scan(
        args.root,
        mode=mode,
        policy_readme=args.policy_readme,
        require_expected_digest=args.require_expected_digest,
    )
    payload = result_to_json(result)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    sys.stdout.write(payload)
    if sys.stderr.isatty() and not args.json:
        sys.stderr.write(
            f"provenance {mode.value}: status={result.status} "
            f"violations={len(result.violations)} scanned={result.scanned_paths}\n"
        )
    return 0 if result.status == "clean" else 1


if __name__ == "__main__":
    raise SystemExit(main())
