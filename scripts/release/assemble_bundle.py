"""Assemble the final release bundle and bind SHA256SUMS to every promoted file.

Usage::

    python scripts/release/assemble_bundle.py \\
        --out release-bundle \\
        --dist dist \\
        --windows release-assets \\
        --sbom sboms \\
        --sample sample \\
        --notes RELEASE_NOTES.md \\
        --receipts-out dist-receipts \\
        --commit-sha "$GITHUB_SHA" \\
        --run-url "..." --run-id "..."

Copies every promoted artifact into ``--out`` (no rebuild), writes the final
``SHA256SUMS`` covering the complete set, verifies the manifest, and emits a
``release`` receipt. Production promotion must consume this bundle only.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from licenselens.release_receipts import (  # noqa: E402
    build_artifact_map,
    make_receipt,
    sha256_file,
    validate_receipt,
    verify_sha256sums,
    write_sha256sums,
)

# Promoted surfaces that must appear in the final bundle (by filename pattern).
REQUIRED_PATTERNS: tuple[tuple[str, str], ...] = (
    ("wheel", "*.whl"),
    ("sdist", "*.tar.gz"),
    ("license_inventory", "license-inventory.json"),
    ("windows_zip", "licenselens-windows-x64-*.zip"),
    ("sbom_spdx", "sbom.spdx.json"),
    ("sbom_cdx", "sbom.cyclonedx.json"),
    ("sample_html", "security-license-lens-report.html"),
    ("release_notes", "RELEASE_NOTES.md"),
)


def _copy_tree_files(src: Path, dest: Path, *, prefix: str = "") -> list[Path]:
    copied: list[Path] = []
    if not src.exists():
        return copied
    if src.is_file():
        target = dest / (prefix + src.name if prefix else src.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        copied.append(target)
        return copied
    for path in sorted(p for p in src.rglob("*") if p.is_file()):
        rel = path.relative_to(src).as_posix()
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        copied.append(target)
    return copied


def _has_match(root: Path, pattern: str) -> bool:
    if "*" in pattern or "?" in pattern or "[" in pattern:
        return any(root.glob(pattern)) or any(root.rglob(pattern))
    return (root / pattern).is_file() or any(root.rglob(pattern))


def assemble(
    *,
    out: Path,
    dist: Path | None,
    windows: Path | None,
    sbom: Path | None,
    sample: Path | None,
    notes: Path | None,
    extra: list[Path],
) -> list[str]:
    """Populate ``out`` with every promoted artifact. Returns problem strings."""
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    if dist is not None:
        # wheel/sdist/inventory only — drop any intermediate SHA256SUMS
        for path in sorted(dist.rglob("*")):
            if not path.is_file():
                continue
            if path.name == "SHA256SUMS":
                continue
            rel = path.relative_to(dist).as_posix()
            target = out / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)

    if windows is not None:
        for path in sorted(windows.rglob("*")):
            if not path.is_file():
                continue
            # Promote the signed ZIP + signing-status marker; skip nested trees.
            if path.suffix == ".zip" or path.name == "signing-status.json":
                target = out / path.name
                shutil.copy2(path, target)

    if sbom is not None:
        for name in ("sbom.spdx.json", "sbom.cyclonedx.json"):
            src = sbom / name
            if src.is_file():
                shutil.copy2(src, out / name)
            else:
                # allow nested download layout
                matches = list(sbom.rglob(name))
                if matches:
                    shutil.copy2(matches[0], out / name)

    if sample is not None:
        sample_dest = out / "sample-report"
        _copy_tree_files(sample, sample_dest)

    if notes is not None and notes.is_file():
        shutil.copy2(notes, out / "RELEASE_NOTES.md")

    for path in extra:
        _copy_tree_files(path, out)

    problems: list[str] = []
    for label, pattern in REQUIRED_PATTERNS:
        if not _has_match(out, pattern):
            # sample html lives under sample-report/
            if label == "sample_html" and _has_match(out, "**/security-license-lens-report.html"):
                continue
            if label == "windows_zip" and _has_match(out, "licenselens-windows-x64-*.zip"):
                continue
            problems.append(f"missing required promoted artifact ({label}): {pattern}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assemble final release bundle + SHA256SUMS.")
    parser.add_argument("--out", type=Path, default=Path("release-bundle"))
    parser.add_argument("--dist", type=Path, default=None)
    parser.add_argument("--windows", type=Path, default=None)
    parser.add_argument("--sbom", type=Path, default=None)
    parser.add_argument("--sample", type=Path, default=None)
    parser.add_argument("--notes", type=Path, default=None)
    parser.add_argument(
        "--extra",
        type=Path,
        action="append",
        default=[],
        help="extra file or directory to include (repeatable)",
    )
    parser.add_argument("--receipts-out", type=Path, default=Path("dist-receipts"))
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--run-url", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--conclusion", default="success")
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="do not fail when a required promoted surface is absent (dry-run only)",
    )
    args = parser.parse_args(argv)

    problems = assemble(
        out=args.out,
        dist=args.dist,
        windows=args.windows,
        sbom=args.sbom,
        sample=args.sample,
        notes=args.notes,
        extra=list(args.extra),
    )
    if problems and not args.allow_missing:
        print("ASSEMBLE_REJECTED", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"WARN: {problem}", file=sys.stderr)

    manifest = write_sha256sums(args.out)
    verify_problems = verify_sha256sums(args.out, manifest)
    if verify_problems:
        print("SHA256SUMS_REJECTED", file=sys.stderr)
        for problem in verify_problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    artifact_map = build_artifact_map(args.out)
    summary = {
        "bundle": str(args.out),
        "artifact_count": len(artifact_map),
        "sha256sums": sha256_file(manifest),
        "artifacts": artifact_map,
        "assemble_warnings": problems,
    }
    brief = {k: summary[k] for k in ("bundle", "artifact_count", "sha256sums")}
    print(json.dumps({"ok": True, **brief}, indent=2))

    if args.commit_sha and args.run_url and args.run_id:
        args.receipts_out.mkdir(parents=True, exist_ok=True)
        receipt = make_receipt(
            kind="release",
            commit_sha=args.commit_sha,
            run_url=args.run_url,
            run_id=args.run_id,
            conclusion=args.conclusion,
            artifacts=artifact_map,
            expected_commit_sha=args.commit_sha,
        )
        result = validate_receipt(receipt, expected_commit_sha=args.commit_sha)
        receipt_path = args.receipts_out / "release.json"
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        if not result.ok:
            print("RELEASE_RECEIPT_REJECTED", file=sys.stderr)
            for problem in result.problems:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print(f"wrote receipt {receipt_path}")

    print(f"assembled {len(artifact_map)} artifacts -> {args.out} (SHA256SUMS verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
