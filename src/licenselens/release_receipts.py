"""Release trust receipt schema (Todo 18).

Each receipt binds a hosted or local proof surface to an immutable commit SHA
and the exact artifact bytes it claims. Config-only claims ("workflow is
configured") are never enough: a receipt must name real artifacts with
SHA-256 digests, a run URL/ID, and a terminal conclusion.

Kinds covered: ci, windows, pages, signing, sbom, attestation, release,
live-lab. The promote path requires a complete ``release`` receipt whose
artifact set matches the final SHA256SUMS of every promoted file.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

RECEIPT_KINDS: Final = (
    "ci",
    "windows",
    "pages",
    "signing",
    "sbom",
    "attestation",
    "release",
    "live-lab",
)

#: Kinds that must carry at least one named artifact with a sha256 digest.
ARTIFACT_REQUIRED_KINDS: Final = frozenset(
    {
        "ci",
        "windows",
        "signing",
        "sbom",
        "attestation",
        "release",
        "live-lab",
    }
)

#: Config-only proof tokens that never satisfy the schema.
CONFIG_ONLY_PROOFS: Final = frozenset(
    {
        "workflow_configured",
        "configured",
        "config-only",
        "config_only",
        "placeholder",
    }
)

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SUCCESS_CONCLUSIONS: Final = frozenset({"success", "passed", "pass", "ok"})


@dataclass(frozen=True, slots=True)
class ReceiptValidation:
    """Result of validating one receipt (or a bundle of receipts)."""

    ok: bool
    problems: list[str] = field(default_factory=list)
    kind: str | None = None
    commit_sha: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "valid": self.ok,
            "problems": list(self.problems),
            "kind": self.kind,
            "commit_sha": self.commit_sha,
        }


def _as_mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _normalize_sha(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    digest = value.strip().lower()
    return digest or None


def _artifact_entries(artifacts: Any) -> list[tuple[str, str]]:
    """Return ``(name, sha256)`` pairs; empty list when artifacts are unusable."""
    if not isinstance(artifacts, Mapping) or not artifacts:
        return []
    entries: list[tuple[str, str]] = []
    for name, meta in artifacts.items():
        if not isinstance(name, str) or not name.strip():
            continue
        digest: str | None = None
        if isinstance(meta, Mapping):
            digest = _normalize_sha(meta.get("sha256") or meta.get("digest"))
        elif isinstance(meta, str):
            digest = _normalize_sha(meta)
        if digest is None:
            continue
        entries.append((name, digest))
    return entries


def validate_receipt(
    receipt: Mapping[str, Any] | dict[str, Any] | Path,
    *,
    expected_commit_sha: str | None = None,
    require_artifacts: bool | None = None,
    require_success: bool = False,
) -> ReceiptValidation:
    """Validate one trust receipt against the Todo 18 schema.

    Rejects wrong commit SHA, config-only proof tokens, missing run identity,
    empty/malformed artifact maps, and (when required) non-success conclusions.
    """
    problems: list[str] = []
    data: Mapping[str, Any] | None

    if isinstance(receipt, Path):
        if not receipt.is_file():
            return ReceiptValidation(ok=False, problems=[f"missing receipt file: {receipt}"])
        try:
            loaded = json.loads(receipt.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return ReceiptValidation(
                ok=False, problems=[f"malformed receipt JSON {receipt}: {exc}"]
            )
        data = _as_mapping(loaded)
        if data is None:
            return ReceiptValidation(
                ok=False, problems=[f"receipt must be a JSON object: {receipt}"]
            )
    else:
        data = _as_mapping(receipt)
        if data is None:
            return ReceiptValidation(ok=False, problems=["receipt must be a mapping"])

    kind = data.get("kind")
    kind_s = kind if isinstance(kind, str) else None
    if kind_s not in RECEIPT_KINDS:
        problems.append(f"unknown or missing receipt kind: {kind!r}")

    commit_sha = _normalize_sha(data.get("commit_sha"))
    if commit_sha is None or not _SHA1_RE.fullmatch(commit_sha):
        problems.append("commit_sha must be a 40-char lowercase hex git SHA")
        commit_sha = commit_sha or None

    expected = _normalize_sha(expected_commit_sha) or _normalize_sha(
        data.get("expected_commit_sha")
    )
    if expected is not None:
        if not _SHA1_RE.fullmatch(expected):
            problems.append("expected_commit_sha must be a 40-char lowercase hex git SHA")
        elif commit_sha is not None and commit_sha != expected:
            problems.append(f"commit_sha mismatch: receipt={commit_sha} expected={expected}")

    proof = data.get("proof")
    if isinstance(proof, str) and proof.strip().lower() in CONFIG_ONLY_PROOFS:
        problems.append(f"config-only proof is not verifiable: {proof!r}")

    run_url = data.get("run_url")
    run_id = data.get("run_id")
    if not (isinstance(run_url, str) and run_url.strip()):
        problems.append("missing run_url")
    if run_id is None or (isinstance(run_id, str) and not run_id.strip()):
        problems.append("missing run_id")

    conclusion = data.get("conclusion")
    if not (isinstance(conclusion, str) and conclusion.strip()):
        problems.append("missing conclusion")
    elif require_success and conclusion.strip().lower() not in SUCCESS_CONCLUSIONS:
        problems.append(f"conclusion is not success: {conclusion!r}")

    entries = _artifact_entries(data.get("artifacts"))
    must_have_artifacts = (
        require_artifacts
        if require_artifacts is not None
        else (kind_s in ARTIFACT_REQUIRED_KINDS if kind_s else True)
    )
    # pages may ship a deployment URL as its sole artifact, but empty is never OK
    # when the kind is in ARTIFACT_REQUIRED_KINDS or when proof is config-only.
    if kind_s == "pages" and not entries:
        must_have_artifacts = True
    if must_have_artifacts and not entries:
        problems.append("missing artifacts (receipt must bind named files + sha256)")
    for name, digest in entries:
        if not _SHA256_RE.fullmatch(digest):
            problems.append(f"artifact {name!r}: sha256 must be 64-char lowercase hex")

    # release receipts must cover the final checksum manifest itself
    if kind_s == "release" and entries:
        names = {name for name, _ in entries}
        if "SHA256SUMS" not in names:
            problems.append("release receipt must include SHA256SUMS artifact")

    return ReceiptValidation(
        ok=not problems,
        problems=problems,
        kind=kind_s,
        commit_sha=commit_sha,
    )


def validate_receipts(
    receipts: list[Mapping[str, Any] | dict[str, Any] | Path] | Path,
    *,
    expected_commit_sha: str | None = None,
    require_kinds: tuple[str, ...] | list[str] | None = None,
    require_success: bool = False,
) -> ReceiptValidation:
    """Validate many receipts; optionally require a full kind set."""
    problems: list[str] = []
    items: list[Mapping[str, Any] | dict[str, Any] | Path]

    if isinstance(receipts, Path):
        if receipts.is_dir():
            files = sorted(p for p in receipts.rglob("*.json") if p.is_file())
            if not files:
                return ReceiptValidation(ok=False, problems=[f"no receipt JSON under {receipts}"])
            items = list(files)
        elif receipts.is_file():
            items = [receipts]
        else:
            return ReceiptValidation(ok=False, problems=[f"missing receipts path: {receipts}"])
    else:
        items = list(receipts)

    kinds_seen: set[str] = set()
    for item in items:
        result = validate_receipt(
            item,
            expected_commit_sha=expected_commit_sha,
            require_success=require_success,
        )
        problems.extend(result.problems)
        if result.kind:
            kinds_seen.add(result.kind)

    if require_kinds:
        for kind in require_kinds:
            if kind not in kinds_seen:
                problems.append(f"missing required receipt kind '{kind}'")

    return ReceiptValidation(ok=not problems, problems=problems)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_artifact_map(root: Path) -> dict[str, dict[str, str]]:
    """Hash every regular file under ``root`` (relative POSIX paths as keys)."""
    artifacts: dict[str, dict[str, str]] = {}
    if not root.is_dir():
        return artifacts
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        artifacts[rel] = {"sha256": sha256_file(path)}
    return artifacts


def write_sha256sums(root: Path, output: Path | None = None) -> Path:
    """Write a GNU-style SHA256SUMS covering every file under ``root``."""
    target = output or (root / "SHA256SUMS")
    lines: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path.resolve() == target.resolve():
            continue
        rel = path.relative_to(root).as_posix()
        lines.append(f"{sha256_file(path)}  {rel}")
    target.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return target


def verify_sha256sums(root: Path, manifest: Path | None = None) -> list[str]:
    """Recompute digests and compare to SHA256SUMS; return problem strings."""
    path = manifest or (root / "SHA256SUMS")
    if not path.is_file():
        return [f"missing SHA256SUMS: {path}"]
    problems: list[str] = []
    seen: set[str] = set()
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        parts = text.split(None, 1)
        if len(parts) != 2:
            problems.append(f"SHA256SUMS:{line_no}: malformed line")
            continue
        digest, name = parts[0].lower(), parts[1].lstrip("*").strip()
        seen.add(name)
        target = root / name
        if not target.is_file():
            problems.append(f"SHA256SUMS missing file: {name}")
            continue
        actual = sha256_file(target)
        if actual != digest:
            problems.append(f"SHA256SUMS mismatch: {name}")
    # every promoted file (except the manifest itself) must appear
    for file_path in sorted(p for p in root.rglob("*") if p.is_file()):
        if file_path.resolve() == path.resolve():
            continue
        rel = file_path.relative_to(root).as_posix()
        if rel not in seen:
            problems.append(f"promoted file not in SHA256SUMS: {rel}")
    return problems


def make_receipt(
    *,
    kind: str,
    commit_sha: str,
    run_url: str,
    run_id: str | int,
    conclusion: str,
    artifacts: Mapping[str, Mapping[str, str]] | Mapping[str, str] | Path,
    expected_commit_sha: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a schema-shaped receipt dict (does not validate)."""
    if isinstance(artifacts, Path):
        art_map = build_artifact_map(artifacts)
    else:
        art_map = {}
        for name, meta in artifacts.items():
            if isinstance(meta, Mapping):
                digest = _normalize_sha(meta.get("sha256") or meta.get("digest"))
            else:
                digest = _normalize_sha(meta)
            if digest is None:
                continue
            art_map[str(name)] = {"sha256": digest}

    payload: dict[str, Any] = {
        "kind": kind,
        "commit_sha": commit_sha.lower(),
        "run_url": run_url,
        "run_id": str(run_id),
        "conclusion": conclusion,
        "artifacts": art_map,
    }
    if expected_commit_sha:
        payload["expected_commit_sha"] = expected_commit_sha.lower()
    if extra:
        for key, value in extra.items():
            if key not in payload:
                payload[key] = value
    return payload


# Aliases accepted by the RED contract loader.
validate = validate_receipt
check_receipt = validate_receipt
