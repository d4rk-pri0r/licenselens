#!/usr/bin/env python3
"""Master release gate for Todo 36 (maturity-and-check-expansion close).

One reproducible, fail-closed runner that executes every Linux/macOS-runnable
quality command from the plan's "Required commands" list, verifies the two-way
determinism of the generated reference docs and sample report, inspects the
offline report bundle for network traffic, runs the coverage validator, scans
built and generated artifacts for secrets / host absolute paths / source
leakage, and exercises the old and new CLI workflows against a freshly built,
installed wheel. The Windows PyInstaller exe and any live-tenant execution are
recorded as explicit ``deferred`` entries with a rationale rather than silently
skipped, so the ledger never hides a gap.

Fail-closed contract:
  * every step must exit within its allowed exit-code set,
  * every ``required_outputs`` path must exist afterwards,
  * every ``required_markers`` substring must appear in stdout,
  * any violation marks the step ``FAIL`` and the whole gate exits non-zero,
  * any ``deferred`` step is treated like failure in exit aggregation (nonzero).

The ledger is written as JSON (``release-gate.json``) and a human summary
(``release-gate.txt``) under the evidence directory, plus the same to ``dist/``
so the record ships with the artifacts.

Run:  uv run python scripts/release_gate.py [--out <dir>] [--skip-browser]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
DEFAULT_OUT: Final = REPO_ROOT / ".omo/evidence/maturity-and-check-expansion"
DEFAULT_CONFORMANCE: Final = (
    REPO_ROOT / ".omo/evidence/licenselens-plan-conformance-and-provenance-audit/conformance.json"
)
DEFAULT_PROVENANCE_RECEIPT: Final = REPO_ROOT / "dist" / "provenance-receipts"

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Step:
    id: str
    title: str
    argv: tuple[str, ...]
    allow_codes: tuple[int, ...] = (0,)
    required_outputs: tuple[str, ...] = ()
    required_markers: tuple[str, ...] = ()
    cwd: str | None = None
    timeout: int = 600


@dataclass(slots=True)
class StepResult:
    id: str
    title: str
    status: str  # pass | fail | deferred
    exit_code: int | None
    duration_ms: int
    summary: str
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "summary": self.summary,
            "note": self.note,
        }


# ---------------------------------------------------------------------------
# Scanning helpers (secrets / absolute paths / source leakage)
# ---------------------------------------------------------------------------

# Secret-shaped VALUES (apply to every file, including source). Bare names such
# as ``client_secret``/``access_token`` are legitimate vocabulary in this domain
# (env-var names, auth modes, the lab matrix's redaction self-check list), so the
# scan only flags actual value payloads: a JWT, a PEM private key, or a hardcoded
# assignment of the client-secret env var to a concrete value.
SECRET_VALUE_PATTERNS: Final = (
    re.compile(r"AZURE_CLIENT_SECRET\s*=\s*['\"]?[A-Za-z0-9._~+\-/]{8,}['\"]?"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    # JWT-shaped blobs (base64url.base64url.base64url)
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
)

# Host filesystem paths that would leak the build machine or break portability.
# Azure ARM resource ids (/subscriptions/...) and Log Analytics workspace paths
# (/workspaces/) are explicitly NOT host paths, so no ``/workspace`` pattern.
ABSOLUTE_PATH_PATTERNS: Final = (
    re.compile(r"/Users/[A-Za-z0-9_.-]+"),
    re.compile(r"/home/[A-Za-z0-9_.-]+"),
    re.compile(r"/private/tmp"),
    re.compile(r"/var/folders"),
    re.compile(r"/tmp/[A-Za-z0-9_.-]+"),
    re.compile(r"[A-Z]:\\Users\\"),
    re.compile(r"\\\\wsl"),
)

# Paths that must never appear inside a binary wheel.
WHEEL_LEAKAGE_NAMES: Final = (
    "tests/",
    ".git",
    ".env",
    "scripts/",
    "packaging/",
    "__pycache__",
    ".pytest_cache",
    ".coverage",
    "openspec/",
    ".omo/",
    ".playwright-mcp/",
    ".venv",
    ".ruff_cache",
)

# Build/scratch/secret state that must never ship in a source distribution.
# Legitimate source-dist content (tests/, scripts/, packaging/, .github/,
# .env.example) is intentionally NOT listed here.
SDIST_LEAKAGE_NAMES: Final = (
    "__pycache__",
    ".pytest_cache",
    ".coverage",
    ".venv",
    ".ruff_cache",
    ".omo/",
    ".opencode/",
    ".playwright-mcp/",
    "openspec/",
    ".debug-journal",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _find_hits(text: str, patterns: tuple[re.Pattern[str], ...]) -> list[str]:
    hits: list[str] = []
    for pattern in patterns:
        for match in pattern.findall(text):
            hits.append(match if isinstance(match, str) else str(match))
    return hits


def scan_text(text: str, label: str) -> list[str]:
    """Return secret-value/absolute-path problems in ``text`` for ``label``."""
    problems: list[str] = []
    for hit in _find_hits(text, SECRET_VALUE_PATTERNS):
        problems.append(f"secret_value:{label}:{hit}")
    for hit in _find_hits(text, ABSOLUTE_PATH_PATTERNS):
        problems.append(f"absolute_path:{label}:{hit}")
    return problems


def scan_wheel(wheel: Path) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(wheel) as zf:
        for name in zf.namelist():
            if any(leak in name for leak in WHEEL_LEAKAGE_NAMES):
                problems.append(f"source_leakage:wheel:{name}")
            if name.endswith((".py", ".md", ".json", ".yaml", ".html", ".js", ".css", ".ps1")):
                problems.extend(scan_text(zf.read(name).decode("utf-8", "replace"), name))
    return problems


def scan_sdist(sdist: Path) -> list[str]:
    # A source distribution legitimately contains tests/, scripts/, and fixture
    # data (JWTs, temp paths), so it is scanned only for scratch/secret *state*
    # that must never ship — not for the text of its own test fixtures.
    problems: list[str] = []
    with tarfile.open(sdist) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if any(leak in member.name for leak in SDIST_LEAKAGE_NAMES):
                problems.append(f"source_leakage:sdist:{member.name}")
    return problems


def scan_tree(root: Path, suffixes: tuple[str, ...]) -> list[str]:
    problems: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in suffixes:
            problems.extend(
                scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))
            )
    return problems


def stray_artifact_problems(root: Path = REPO_ROOT) -> list[str]:
    """Flag stray literal-backslash/NUL paths (cross-platform test detritus)."""
    problems: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        if ".venv" in path.parts or ".git" in path.parts or ".omo" in path.parts:
            continue
        if "\\" in path.name or "\x00" in path.name:
            problems.append(f"stray_backslash_path:{path}")
    return problems


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------


def run_capture(
    argv: list[str] | tuple[str, ...],
    *,
    cwd: str | None = None,
    timeout: int = 600,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        cwd=cwd or str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _tail(text: str, limit: int = 1200) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[-limit:]


def run_step(step: Step) -> StepResult:
    start = time.monotonic()
    try:
        proc = run_capture(step.argv, cwd=step.cwd, timeout=step.timeout)
    except subprocess.TimeoutExpired as exc:
        return StepResult(step.id, step.title, "fail", None, 0, "", f"timeout: {exc}")
    except OSError as exc:
        return StepResult(step.id, step.title, "fail", None, 0, "", f"spawn failed: {exc}")

    duration_ms = int((time.monotonic() - start) * 1000)
    output = (proc.stdout or "") + (proc.stderr or "")
    problems: list[str] = []

    if proc.returncode not in step.allow_codes:
        problems.append(f"exit {proc.returncode} not in {step.allow_codes}")
    for rel in step.required_outputs:
        target = (Path(step.cwd) if step.cwd else REPO_ROOT) / rel
        if not target.exists():
            problems.append(f"missing required output: {rel}")
    for marker in step.required_markers:
        if marker not in output:
            problems.append(f"missing required marker: {marker!r}")

    if problems:
        return StepResult(
            step.id,
            step.title,
            "fail",
            proc.returncode,
            duration_ms,
            _tail(output),
            "; ".join(problems),
        )
    return StepResult(step.id, step.title, "pass", proc.returncode, duration_ms, _tail(output))


def deferred_result(step_id: str, title: str, note: str) -> StepResult:
    return StepResult(step_id, title, "deferred", None, 0, "", note)


def gate_exit_code(results: list[StepResult]) -> int:
    """Aggregate step statuses into the process exit code (fail-closed).

    Deferred steps count as failure: a gap recorded in the ledger must not
    yield a green gate exit. Only an all-pass result returns 0.
    """
    if any(r.status in ("fail", "deferred") for r in results):
        return 1
    return 0


# ---------------------------------------------------------------------------
# Compound (in-process) checks
# ---------------------------------------------------------------------------


def check_reference_docs_determinism() -> StepResult:
    """Generate reference docs twice into temp roots; require byte-identical output."""
    start = time.monotonic()
    with tempfile.TemporaryDirectory() as tmp:
        a = Path(tmp) / "a"
        b = Path(tmp) / "b"
        gen = ["uv", "run", "python", "scripts/generate_reference_docs.py", "--root"]
        first = run_capture([*gen, str(a)])
        second = run_capture([*gen, str(b)])
        if first.returncode != 0 or second.returncode != 0:
            return StepResult(
                "reference-docs-determinism",
                "Reference docs regenerate twice -> byte-identical",
                "fail",
                first.returncode,
                0,
                _tail((first.stdout or "") + (first.stderr or "")),
                "generator returned non-zero",
            )
        a_files = {p.relative_to(a).as_posix(): _sha256(p) for p in a.rglob("*") if p.is_file()}
        b_files = {p.relative_to(b).as_posix(): _sha256(p) for p in b.rglob("*") if p.is_file()}
        diffs = sorted(set(a_files) ^ set(b_files)) + [
            rel for rel in a_files if a_files[rel] != b_files.get(rel)
        ]
        duration_ms = int((time.monotonic() - start) * 1000)
        if diffs:
            return StepResult(
                "reference-docs-determinism",
                "Reference docs regenerate twice -> byte-identical",
                "fail",
                0,
                duration_ms,
                "",
                f"{len(diffs)} diverged file(s): {diffs[:10]}",
            )
        note = f"{len(a_files)} files identical across two generations"
        return StepResult(
            "reference-docs-determinism",
            "Reference docs regenerate twice -> byte-identical",
            "pass",
            0,
            duration_ms,
            f"{len(a_files)} generated files, two runs byte-identical",
            note,
        )


def check_reference_docs_freshness() -> StepResult:
    start = time.monotonic()
    proc = run_capture(["uv", "run", "python", "scripts/generate_reference_docs.py", "--check"])
    duration_ms = int((time.monotonic() - start) * 1000)
    ok = proc.returncode == 0
    return StepResult(
        "reference-docs-freshness",
        "Reference docs + sample fresh (--check, no drift)",
        "pass" if ok else "fail",
        proc.returncode,
        duration_ms,
        _tail((proc.stdout or "") + (proc.stderr or "")),
    )


def check_report_assets_determinism() -> StepResult:
    """Regenerate the committed sample reports twice; require identical hashes."""
    start = time.monotonic()
    samples = (
        "examples/sample-report/security-license-lens-report.html",
        "examples/sample-report/security-license-lens-report.json",
        "examples/sample-report/security-license-lens-report.md",
    )

    def hashes() -> dict[str, str]:
        proc = run_capture(["uv", "run", "python", "scripts/regenerate_report_assets.py"])
        if proc.returncode != 0:
            raise RuntimeError(_tail((proc.stdout or "") + (proc.stderr or "")))
        return {rel: _sha256(REPO_ROOT / rel) for rel in samples}

    try:
        first = hashes()
        second = hashes()
    except RuntimeError as exc:
        return StepResult(
            "report-assets-determinism",
            "Sample report regenerates twice -> identical",
            "fail",
            0,
            0,
            "",
            f"regenerate failed: {exc}",
        )
    duration_ms = int((time.monotonic() - start) * 1000)
    for rel in samples:
        if first[rel] != second[rel]:
            return StepResult(
                "report-assets-determinism",
                "Sample report regenerates twice -> identical",
                "fail",
                0,
                duration_ms,
                "",
                f"diverged: {rel}",
            )
    return StepResult(
        "report-assets-determinism",
        "Sample report regenerates twice -> identical",
        "pass",
        0,
        duration_ms,
        "; ".join(f"{rel}: {first[rel][:16]}…" for rel in samples),
    )


def check_secret_and_path_scan() -> StepResult:
    """Scan dist + generated artifacts for secrets and host absolute paths."""
    start = time.monotonic()
    problems: list[str] = []

    for wheel in sorted((REPO_ROOT / "dist").glob("*.whl")):
        problems.extend(scan_wheel(wheel))
    for sdist in sorted((REPO_ROOT / "dist").glob("*.tar.gz")):
        problems.extend(scan_sdist(sdist))

    problems.extend(scan_tree(REPO_ROOT / "docs" / "reference", (".md", ".json")))
    problems.extend(scan_tree(REPO_ROOT / "examples" / "sample-report", (".json", ".html", ".md")))
    problems.extend(scan_tree(REPO_ROOT / "dist", (".json", ".md")))

    duration_ms = int((time.monotonic() - start) * 1000)
    if problems:
        return StepResult(
            "secret-path-scan",
            "Secrets + host absolute paths absent from artifacts",
            "fail",
            0,
            duration_ms,
            "",
            f"{len(problems)} hit(s): {problems[:10]}",
        )
    return StepResult(
        "secret-path-scan",
        "Secrets + host absolute paths absent from artifacts",
        "pass",
        0,
        duration_ms,
        "no secrets, no host absolute paths in wheel/sdist/sample/reference",
    )


def check_source_leakage() -> StepResult:
    """Confirm wheel/sdist contain only the package and its data, nothing else."""
    start = time.monotonic()
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from licenselens.release_guard import version_from_pyproject

    allowed_sdist_roots = {"licenselens", f"licenselens-{version_from_pyproject(REPO_ROOT)}"}
    problems: list[str] = []
    for wheel in sorted((REPO_ROOT / "dist").glob("*.whl")):
        with zipfile.ZipFile(wheel) as zf:
            names = zf.namelist()
        # A wheel's only allowed top-level entries are the package and the
        # <name>-<version>.dist-info metadata directory.
        real_outside = [
            n for n in names if not n.startswith("licenselens/") and ".dist-info/" not in n
        ]
        if real_outside:
            problems.append(f"unexpected_top_level:{wheel.name}:{real_outside[:5]}")
    for sdist in sorted((REPO_ROOT / "dist").glob("*.tar.gz")):
        with tarfile.open(sdist) as tf:
            root_dirs = {m.name.split("/")[0] for m in tf.getmembers() if "/" in m.name}
        if root_dirs - allowed_sdist_roots:
            problems.append(f"unexpected_sdist_root:{sdist.name}:{sorted(root_dirs)}")
    duration_ms = int((time.monotonic() - start) * 1000)
    if problems:
        return StepResult(
            "source-leakage",
            "Wheel/sdist contain only licenselens package + data",
            "fail",
            0,
            duration_ms,
            "",
            "; ".join(problems),
        )
    return StepResult(
        "source-leakage",
        "Wheel/sdist contain only licenselens package + data",
        "pass",
        0,
        duration_ms,
        "wheel and sdist scoped to licenselens package + dist-info",
    )


def check_stray_artifacts() -> StepResult:
    start = time.monotonic()
    problems = stray_artifact_problems()
    duration_ms = int((time.monotonic() - start) * 1000)
    if problems:
        return StepResult(
            "stray-artifacts",
            "No stray backslash dirs / live-report detritus in the tree",
            "fail",
            0,
            duration_ms,
            "",
            f"{len(problems)} stray artifact(s): {problems[:10]}",
        )
    return StepResult(
        "stray-artifacts",
        "No stray backslash dirs / live-report detritus in the tree",
        "pass",
        0,
        duration_ms,
        "clean",
    )


def check_checksums() -> StepResult:
    """Compute SHA-256 for every dist artifact and verify a self-consistent manifest."""
    start = time.monotonic()
    manifest_path = REPO_ROOT / "dist" / "SHA256SUMS"
    artifacts = sorted((REPO_ROOT / "dist").glob("*"))
    # The manifest is the record, not a hashed artifact: including it would
    # always mismatch (its content changes the moment the manifest is written).
    artifacts = [a for a in artifacts if a.is_file() and a.name != manifest_path.name]
    if not artifacts:
        return StepResult(
            "checksums", "Release checksums match", "fail", 0, 0, "", "no dist artifacts"
        )
    lines = [f"{_sha256(a)}  {a.name}" for a in artifacts]
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    problems: list[str] = []
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        target = REPO_ROOT / "dist" / name
        if not target.is_file() or _sha256(target) != digest:
            problems.append(f"checksum_mismatch:{name}")
    duration_ms = int((time.monotonic() - start) * 1000)
    if problems:
        return StepResult(
            "checksums", "Release checksums match", "fail", 0, duration_ms, "", "; ".join(problems)
        )
    return StepResult(
        "checksums",
        "Release checksums match",
        "pass",
        0,
        duration_ms,
        f"{len(artifacts)} artifacts hashed; SHA256SUMS verified",
    )


def check_release_guards() -> StepResult:
    """Run the cross-platform release/CI workflow static guards in-process."""
    start = time.monotonic()
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from licenselens.ci_guard import ci_guards, docs_freshness_guards
    from licenselens.release_guard import (
        release_guards,
        third_party_notices_guards,
        version_consistent,
        version_from_pyproject,
    )
    from licenselens.windows_ci import windows_ci_guards

    problems = (
        release_guards(REPO_ROOT)
        + windows_ci_guards(REPO_ROOT)
        + ci_guards(REPO_ROOT)
        + docs_freshness_guards(REPO_ROOT)
        + third_party_notices_guards(REPO_ROOT)
    )
    version = version_from_pyproject(REPO_ROOT)
    version_ok = version_consistent(REPO_ROOT, f"v{version}")
    duration_ms = int((time.monotonic() - start) * 1000)
    if problems or not version_ok:
        return StepResult(
            "release-guards",
            "Release/CI workflow static guards (SHA pins, permissions, topology)",
            "fail",
            0,
            duration_ms,
            "",
            "; ".join(problems + ([] if version_ok else [f"version tag v{version} inconsistent"])),
        )
    return StepResult(
        "release-guards",
        "Release/CI workflow static guards (SHA pins, permissions, topology)",
        "pass",
        0,
        duration_ms,
        f"release_guards/windows_ci_guards/ci_guards/notices clean; version v{version} consistent",
    )


def check_provenance_receipt(
    receipt: Path | None = None,
    *,
    require_modes: tuple[str, ...] = (),
) -> StepResult:
    """Require a clean provenance JSON receipt (fail closed on missing/unclean)."""
    start = time.monotonic()
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from licenselens.release_guard import provenance_receipt_guards

    target = receipt or DEFAULT_PROVENANCE_RECEIPT
    problems = provenance_receipt_guards(target, require_modes=require_modes or None)
    duration_ms = int((time.monotonic() - start) * 1000)
    if problems:
        return StepResult(
            "provenance-receipt",
            "Provenance JSON receipt is present and clean",
            "fail",
            0,
            duration_ms,
            "",
            "; ".join(problems),
        )
    return StepResult(
        "provenance-receipt",
        "Provenance JSON receipt is present and clean",
        "pass",
        0,
        duration_ms,
        f"clean receipt at {target}",
    )


def check_conformance_freshness(matrix: Path | None = None) -> StepResult:
    """Require conformance matrix with no partial|missing|deferred rows."""
    start = time.monotonic()
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from licenselens.release_guard import conformance_matrix_guards

    target = matrix or DEFAULT_CONFORMANCE
    if not target.is_file():
        duration_ms = int((time.monotonic() - start) * 1000)
        return StepResult(
            "conformance-freshness",
            "Conformance matrix has no partial|missing|deferred rows",
            "fail",
            0,
            duration_ms,
            "",
            f"missing conformance matrix: {target}",
        )
    problems = conformance_matrix_guards(target)
    duration_ms = int((time.monotonic() - start) * 1000)
    if problems:
        return StepResult(
            "conformance-freshness",
            "Conformance matrix has no partial|missing|deferred rows",
            "fail",
            0,
            duration_ms,
            "",
            f"{len(problems)} stale row(s): {problems[:8]}",
        )
    return StepResult(
        "conformance-freshness",
        "Conformance matrix has no partial|missing|deferred rows",
        "pass",
        0,
        duration_ms,
        f"fresh matrix at {target}",
    )


def check_provenance_artifacts() -> StepResult:
    """Scan built wheel/sdist/zip members via the provenance scanner."""
    start = time.monotonic()
    proc = run_capture(
        [
            "uv",
            "run",
            "python",
            "scripts/provenance_scan.py",
            "--artifacts",
            "--root",
            str(REPO_ROOT / "dist"),
            "--json",
        ],
        timeout=600,
    )
    duration_ms = int((time.monotonic() - start) * 1000)
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        return StepResult(
            "provenance-artifacts",
            "Artifact-member provenance scan is clean",
            "fail",
            proc.returncode,
            duration_ms,
            _tail(output),
            f"provenance --artifacts exit {proc.returncode}",
        )
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return StepResult(
            "provenance-artifacts",
            "Artifact-member provenance scan is clean",
            "fail",
            proc.returncode,
            duration_ms,
            _tail(output),
            "provenance --artifacts emitted non-JSON",
        )
    if payload.get("status") != "clean":
        return StepResult(
            "provenance-artifacts",
            "Artifact-member provenance scan is clean",
            "fail",
            proc.returncode,
            duration_ms,
            _tail(output),
            f"status={payload.get('status')!r} violations={payload.get('violation_count')}",
        )
    return StepResult(
        "provenance-artifacts",
        "Artifact-member provenance scan is clean",
        "pass",
        0,
        duration_ms,
        f"artifacts clean; scanned={payload.get('scanned_paths', 0)}",
    )


def validate_receipts_bundle(
    receipts: Path,
    *,
    require_modes: tuple[str, ...] = (),
    conformance: Path | None = None,
    gate_ledger: Path | None = None,
    fail_on_deferred: bool = True,
) -> list[str]:
    """Validate provenance receipts (+ optional conformance/ledger) fail-closed."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from licenselens.release_guard import (
        conformance_matrix_guards,
        gate_ledger_guards,
        provenance_receipt_guards,
    )

    problems = provenance_receipt_guards(receipts, require_modes=require_modes or None)
    if conformance is not None:
        problems.extend(conformance_matrix_guards(conformance))
    if gate_ledger is not None:
        problems.extend(gate_ledger_guards(gate_ledger, fail_on_deferred=fail_on_deferred))
    return problems


def check_release_scripts() -> StepResult:
    """Exercise the three scripts/release/* gates end-to-end."""
    start = time.monotonic()
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from licenselens.release_guard import version_from_pyproject

    version = version_from_pyproject(REPO_ROOT)
    checks: list[tuple[str, tuple[str, ...], int]] = [
        (
            f"verify_version v{version}",
            ("uv", "run", "python", "scripts/release/verify_version.py", f"v{version}"),
            0,
        ),
        (
            "verify_signing optional+unsigned",
            (
                "uv",
                "run",
                "python",
                "scripts/release/verify_signing.py",
                "--policy",
                "optional",
                "--assets",
                str(REPO_ROOT / "dist"),
            ),
            0,
        ),
        (
            "license_inventory",
            (
                "uv",
                "run",
                "python",
                "scripts/release/license_inventory.py",
                "--output",
                str(REPO_ROOT / "dist" / "license-inventory.json"),
            ),
            0,
        ),
    ]
    problems: list[str] = []
    outputs: list[str] = []
    for name, argv, want in checks:
        proc = run_capture(argv)
        outputs.append(f"{name} -> exit {proc.returncode}")
        if proc.returncode != want:
            problems.append(f"{name}: exit {proc.returncode} != {want}")
    duration_ms = int((time.monotonic() - start) * 1000)
    if problems:
        return StepResult(
            "release-scripts",
            "Release gate CLIs (version/signing/license inventory)",
            "fail",
            0,
            duration_ms,
            "\n".join(outputs),
            "; ".join(problems),
        )
    return StepResult(
        "release-scripts",
        "Release gate CLIs (version/signing/license inventory)",
        "pass",
        0,
        duration_ms,
        "\n".join(outputs),
    )


def check_wheel_smoke() -> StepResult:
    """Install the freshly built wheel into a clean venv and run CLI workflows."""
    start = time.monotonic()
    wheels = sorted((REPO_ROOT / "dist").glob("*.whl"))
    if not wheels:
        return StepResult(
            "wheel-smoke", "Installed-wheel CLI smoke", "fail", 0, 0, "", "no wheel in dist/"
        )
    with tempfile.TemporaryDirectory() as tmp:
        venv = Path(tmp) / "venv"
        run_capture(["uv", "venv", str(venv)], timeout=120)
        venv_python = venv / "bin" / "python"
        run_capture(
            ["uv", "pip", "install", "--quiet", "--python", str(venv_python), str(wheels[-1])],
            timeout=300,
        )
        cli = venv / "bin" / "licenselens"
        reports = Path(tmp) / "reports"

        invocations: list[tuple[str, tuple[int, ...]]] = [
            ("version", ("version",), (0,)),
            ("checks", ("checks",), (0,)),
            ("diff --help", ("diff", "--help"), (0,)),
            ("batch --help", ("batch", "--help"), (0,)),
            ("discover-workspace --help", ("discover-workspace", "--help"), (0,)),
            ("doctor --dry-run", ("doctor",), (0,)),
            ("scan dry-run", ("scan", "-o", str(reports)), (0, 1)),
            (
                "scan --profile full --report-archive",
                ("scan", "--profile", "full", "--report-archive", "-o", str(reports / "full")),
                (0, 1),
            ),
        ]
        problems: list[str] = []
        outputs: list[str] = []
        for name, args, allow in invocations:
            proc = run_capture([str(cli), *args], timeout=300)
            outputs.append(f"{name} -> exit {proc.returncode}")
            if proc.returncode not in allow:
                problems.append(f"{name}: exit {proc.returncode}")
        entry = reports / "security-license-lens-report.html"
        if not entry.is_file():
            problems.append("missing report entry security-license-lens-report.html")
        archive = reports / "full" / "security-license-lens-report.zip"
        if not archive.is_file():
            problems.append("missing report archive (--report-archive)")

    duration_ms = int((time.monotonic() - start) * 1000)
    if problems:
        return StepResult(
            "wheel-smoke",
            "Installed-wheel CLI smoke",
            "fail",
            0,
            duration_ms,
            "\n".join(outputs),
            "; ".join(problems),
        )
    return StepResult(
        "wheel-smoke",
        "Installed-wheel CLI smoke",
        "pass",
        0,
        duration_ms,
        "\n".join(outputs),
    )


# ---------------------------------------------------------------------------
# Pester steps
# ---------------------------------------------------------------------------

PESTER_WRAPPER: Final = (
    "$r = Invoke-Pester -Path '{path}' -Output Detailed -PassThru; "
    "if ($r.FailedCount -gt 0) {{ Write-Host ('PESTER_FAILED=' + $r.FailedCount); exit 1 }}; "
    "Write-Host ('PESTER_OK passed=' + $r.PassedCount + ' skipped=' + $r.SkippedCount); exit 0"
)


def pester_step(step_id: str, title: str, path: str) -> Step:
    return Step(
        step_id,
        title,
        (
            "pwsh",
            "-NoProfile",
            "-Command",
            PESTER_WRAPPER.format(path=path),
        ),
        allow_codes=(0,),
        required_markers=("PESTER_OK",),
        timeout=300,
    )


# ---------------------------------------------------------------------------
# Step list
# ---------------------------------------------------------------------------


def build_steps(skip_browser: bool) -> list[Step]:
    steps: list[Step] = [
        Step("ruff-check", "Ruff lint", ("uv", "run", "ruff", "check", "src", "tests")),
        Step(
            "ruff-format",
            "Ruff format check",
            ("uv", "run", "ruff", "format", "--check", "src", "tests"),
        ),
        Step(
            "pytest-coverage",
            "Pytest with coverage floor (72%)",
            (
                "uv",
                "run",
                "pytest",
                "-m",
                "not browser",
                "--cov=licenselens",
                "--cov-report=term-missing",
                "--cov-fail-under=72",
                "-q",
            ),
            timeout=900,
        ),
        Step("pytest-full", "Full pytest suite", ("uv", "run", "pytest", "-q"), timeout=900),
    ]
    if not skip_browser:
        steps.append(
            Step(
                "pytest-browser",
                "Playwright Chromium report suite",
                (
                    "uv",
                    "run",
                    "pytest",
                    "tests/test_report_browser.py",
                    "tests/test_report_hardening_browser.py",
                    "--browser",
                    "chromium",
                    "-q",
                ),
                timeout=900,
            )
        )
    steps += [
        Step(
            "coverage-manifest",
            "SCuBA coverage manifest validator",
            (
                "uv",
                "run",
                "python",
                "scripts/validate_coverage_manifest.py",
                "catalog/coverage/scuba-2026-08.yaml",
            ),
        ),
        Step(
            "mkdocs-strict",
            "MkDocs build --strict",
            ("uv", "run", "mkdocs", "build", "--strict"),
            required_markers=("Documentation built",),
            timeout=300,
        ),
        Step("codespell", "Codespell (docs)", ("uv", "run", "codespell", "docs", "mkdocs.yml")),
        Step(
            "lychee",
            "External link check (lychee)",
            ("lychee", "--no-progress", "--max-concurrency", "8", "docs/"),
            timeout=600,
        ),
        Step(
            "package-build",
            "Build wheel + sdist",
            ("uv", "run", "python", "-m", "build"),
            timeout=600,
        ),
        pester_step(
            "pester-collectors",
            "Pester: PowerShell bridge module",
            "powershell/LicenseLens.Collectors/tests/LicenseLens.Collectors.Tests.ps1",
        ),
        pester_step(
            "pester-installer",
            "Pester: per-user installer lifecycle",
            "packaging/windows/tests/Installer.Tests.ps1",
        ),
    ]
    return steps


def run_negative(out: Path) -> int:
    """Demonstrate the gate's fail-closed rejection of adversarial fixtures.

    Each scenario below is an actual (malformed / stale / dirty / misleading /
    tampered / secret / external-network) input that the gate must reject; the
    ledger records the command, the expected rejection, and the observed outcome.
    """
    out.mkdir(parents=True, exist_ok=True)
    entries: list[dict] = []

    def record(name: str, command: str, expected: str, outcome: str, verdict: str) -> None:
        entries.append(
            {
                "scenario": name,
                "command": command,
                "expected_rejection": expected,
                "observed": outcome,
                "verdict": verdict,
            }
        )
        print(f"[{verdict}] {name}: {outcome}")

    # 1) malformed input — a step whose binary does not exist fails closed.
    r = run_step(Step("neg-malformed-binary", "x", ("/definitely/not/a/binary",), allow_codes=(0,)))
    record(
        "malformed_input",
        "run_step(Step(argv=('/definitely/not/a/binary',)))",
        "status 'fail' (spawn failed), no traceback",
        f"status={r.status!r} note={r.note!r}",
        "REJECTED" if r.status == "fail" else "NOT-REJECTED",
    )

    # 2) misleading success output — exit 0 without the required artifact fails.
    with tempfile.TemporaryDirectory() as tmp:
        missing = Path(tmp) / "nope.html"
        r = run_step(
            Step(
                "neg-misleading",
                "x",
                (sys.executable, "-c", "print('looks fine')"),
                required_outputs=(str(missing),),
            )
        )
    record(
        "misleading_success_output",
        "run_step(exit-0 command with required_outputs=nonexistent)",
        "status 'fail' (missing required output)",
        f"status={r.status!r} note={r.note!r}",
        "REJECTED" if r.status == "fail" else "NOT-REJECTED",
    )

    # 3) stale state — a hand-edited generated file fails the freshness check.
    with tempfile.TemporaryDirectory() as tmp:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "generate_reference_docs", REPO_ROOT / "scripts" / "generate_reference_docs.py"
        )
        gen = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules["generate_reference_docs"] = gen
        spec.loader.exec_module(gen)
        generation = gen.build_generation()
        target = Path(tmp) / "docs" / "reference" / "checks.md"
        target.parent.mkdir(parents=True)
        target.write_text("// tampered by hand\n", encoding="utf-8")
        problems = gen.check_generation(generation, root=Path(tmp))
        stale_problem = [p for p in problems if p.startswith("generated_file_drift")]
    record(
        "stale_state",
        "generate_reference_docs.check_generation() against a tampered generated file",
        "generated_file_drift reported",
        f"{len(stale_problem)} drift problem(s) detected",
        "REJECTED" if stale_problem else "NOT-REJECTED",
    )

    # 4) dirty worktree — a literal-backslash directory is flagged.
    with tempfile.TemporaryDirectory() as tmp:
        stray = Path(tmp) / "\\private\\tmp\\Pester_x\\LicenseLens"
        stray.mkdir(parents=True, exist_ok=True)
        problems = stray_artifact_problems(Path(tmp))
    record(
        "dirty_worktree",
        "stray_artifact_problems() over a tree containing a literal-backslash dir",
        "stray_backslash_path reported",
        f"{len(problems)} stray path(s) detected",
        "REJECTED" if problems else "NOT-REJECTED",
    )

    # 5) tampered artifact — a corrupted wheel entry is flagged by the leak scan.
    with tempfile.TemporaryDirectory() as tmp:
        wheel = Path(tmp) / "tampered.whl"
        with zipfile.ZipFile(wheel, "w") as zf:
            zf.writestr("licenselens/__init__.py", "x = 1")
            zf.writestr("tests/leaked.py", "x = 1")
        problems = scan_wheel(wheel)
    record(
        "tampered_artifact",
        "scan_wheel() over a wheel containing a 'tests/' entry",
        "source_leakage reported",
        f"{len(problems)} leakage problem(s) detected",
        "REJECTED" if problems else "NOT-REJECTED",
    )

    # 6) secret fixture — a hardcoded secret value is flagged.
    problems = scan_text('AZURE_CLIENT_SECRET="hunter2secretvalue"\n', "leak.txt")
    record(
        "secret_fixture",
        "scan_text() over a hardcoded AZURE_CLIENT_SECRET value",
        "secret_value reported",
        f"{len(problems)} secret problem(s) detected",
        "REJECTED" if problems else "NOT-REJECTED",
    )

    # 7) external network — the report hardening test rejects any http(s) request.
    ext = run_capture(
        [
            "uv",
            "run",
            "pytest",
            "tests/test_report_hardening_browser.py::test_negative_external_request_is_blocked",
            "tests/test_report_hardening_browser.py::test_negative_eval_is_blocked_by_csp",
            "--browser",
            "chromium",
            "-q",
        ],
        timeout=300,
    )
    record(
        "external_network",
        "pytest test_report_hardening_browser.py::test_negative_external_request_is_blocked "
        "::test_negative_eval_is_blocked_by_csp",
        "exit 0 (external request / eval rejected by CSP)",
        f"exit {ext.returncode}: {_tail(ext.stdout or ext.stderr or '')}",
        "REJECTED" if ext.returncode == 0 else "NOT-REJECTED",
    )

    # 8) unit contract — the fail-closed unit suite passes.
    unit = run_capture(["uv", "run", "pytest", "tests/test_release_gate.py", "-q"], timeout=300)
    record(
        "fail_closed_unit_contract",
        "pytest tests/test_release_gate.py -q",
        "exit 0 (11 fail-closed contract tests)",
        f"exit {unit.returncode}: {_tail(unit.stdout or unit.stderr or '')}",
        "PASS" if unit.returncode == 0 else "FAIL",
    )

    all_rejected = all(e["verdict"] in ("REJECTED", "PASS") for e in entries)
    payload = {"generator": "scripts/release_gate.py --negative", "scenarios": entries}
    (out / "release-gate-negative.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    (out / "release-gate-negative.txt").write_text(
        _render_negative_ledger(entries), encoding="utf-8"
    )
    print(f"negative ledger -> {out / 'release-gate-negative.txt'}")
    return 0 if all_rejected else 1


def _render_negative_ledger(entries: list[dict]) -> str:
    lines = [
        "# Todo 36 — Release gate negative (fail-closed) ledger",
        "",
        f"Generator: scripts/release_gate.py --negative · Host: {os.uname().sysname}",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        "",
        "Each fixture is an adversarial input the gate must reject. `REJECTED`",
        "means the gate failed closed exactly as required.",
        "",
        "| Scenario | Expected rejection | Observed | Verdict |",
        "|----------|--------------------|----------|---------|",
    ]
    for e in entries:
        lines.append(
            f"| {e['scenario']} | {e['expected_rejection']} | {e['observed']} | {e['verdict']} |"
        )
    lines += [
        "",
        "## Commands",
        "",
    ]
    for e in entries:
        lines.append(f"- `{e['command']}`")
    lines.append("")
    return "\n".join(lines)


def run_validate_receipts(
    receipts: Path,
    *,
    require_modes: tuple[str, ...] = (),
    conformance: Path | None = None,
    gate_ledger: Path | None = None,
    fail_on_deferred: bool = True,
) -> int:
    problems = validate_receipts_bundle(
        receipts,
        require_modes=require_modes,
        conformance=conformance,
        gate_ledger=gate_ledger,
        fail_on_deferred=fail_on_deferred,
    )
    if problems:
        print("PROVENANCE_RECEIPT_REJECTED")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("PROVENANCE_RECEIPT_CLEAN")
    if require_modes:
        print(f"required_modes={','.join(require_modes)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Master LicenseLens release gate (Todo 36).")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--skip-browser", action="store_true")
    parser.add_argument(
        "--negative",
        action="store_true",
        help="run the fail-closed negative fixture ledger instead of the happy gate",
    )
    parser.add_argument(
        "--validate-receipts",
        type=Path,
        default=None,
        help="validate a provenance receipt file/dir (and optional conformance/ledger)",
    )
    parser.add_argument(
        "--require-modes",
        default="",
        help="comma-separated provenance modes required under --validate-receipts",
    )
    parser.add_argument(
        "--conformance",
        type=Path,
        default=None,
        help="conformance matrix JSON to require fresh (no partial|missing|deferred)",
    )
    parser.add_argument(
        "--gate-ledger",
        type=Path,
        default=None,
        help="release-gate.json ledger to validate (deferred steps fail when set)",
    )
    parser.add_argument(
        "--allow-deferred-ledger",
        action="store_true",
        help="with --gate-ledger, do not fail on deferred steps (default: fail)",
    )
    parser.add_argument(
        "--provenance-receipt",
        type=Path,
        default=None,
        help="when running the full gate, require this clean provenance receipt",
    )
    parser.add_argument(
        "--skip-conformance",
        action="store_true",
        help="skip conformance-matrix freshness (default: require when matrix exists)",
    )
    args = parser.parse_args(argv)

    if args.negative:
        return run_negative(args.out)

    if args.validate_receipts is not None:
        modes = tuple(m.strip() for m in args.require_modes.split(",") if m.strip())
        return run_validate_receipts(
            args.validate_receipts,
            require_modes=modes,
            conformance=args.conformance,
            gate_ledger=args.gate_ledger,
            fail_on_deferred=not args.allow_deferred_ledger,
        )

    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    results: list[StepResult] = []

    # 1) subprocess + Pester steps
    for step in build_steps(args.skip_browser):
        results.append(run_step(step))

    # 2) in-process compound checks (ordered after build)
    compound_checks = (
        check_release_guards,
        check_release_scripts,
        check_reference_docs_determinism,
        check_reference_docs_freshness,
        check_report_assets_determinism,
        check_wheel_smoke,
        check_checksums,
        check_secret_and_path_scan,
        check_source_leakage,
        check_stray_artifacts,
        check_provenance_artifacts,
    )
    for check in compound_checks:
        try:
            results.append(check())
        except Exception as exc:  # noqa: BLE001 - fail-closed, never traceback
            results.append(
                StepResult(
                    check.__name__,
                    "compound check",
                    "fail",
                    None,
                    0,
                    "",
                    f"unhandled exception: {exc}",
                )
            )

    if args.provenance_receipt is not None:
        results.append(check_provenance_receipt(args.provenance_receipt))

    if args.conformance is not None and not args.skip_conformance:
        results.append(check_conformance_freshness(args.conformance))

    results.append(
        deferred_result(
            "windows-exe-build",
            "Windows x64 PyInstaller one-folder ZIP (smoke + report open)",
            "PyInstaller is not a cross-compiler; the exe/ZIP is built on Windows CI "
            "(windows-ci.yml pyinstaller + binary-smoke jobs) only. Frozen-artifact "
            "contract is locked cross-platform by tests/test_windows_packaging.py.",
        )
    )
    results.append(
        deferred_result(
            "live-tenant",
            "Controlled live-tenant validation",
            "No real Microsoft tenant is touched here; live-lab is dry-run validated "
            "against fake backends (scripts/lab_runner.py) and deferred to the operator "
            "per docs/tenant-provisioning-guide.md.",
        )
    )

    failed = [r for r in results if r.status == "fail"]
    deferred = [r for r in results if r.status == "deferred"]
    for r in results:
        print(f"[{r.status.upper():8}] {r.id}: {r.title}")
        if r.note:
            print(f"            note: {r.note}")
        if r.status == "fail":
            print(f"            {r.summary[:400]}")

    payload = {
        "generator": "scripts/release_gate.py",
        "repo_root": str(REPO_ROOT),
        "steps": [r.to_dict() for r in results],
        "passed": sum(1 for r in results if r.status == "pass"),
        "failed": len(failed),
        "deferred": len(deferred),
    }
    (out / "release-gate.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (out / "release-gate.txt").write_text(_render_ledger(results), encoding="utf-8")

    print(f"\npassed={payload['passed']} failed={payload['failed']} deferred={payload['deferred']}")
    print(f"ledger -> {out / 'release-gate.txt'}")
    return gate_exit_code(results)


def _render_ledger(results: list[StepResult]) -> str:
    lines = [
        "# Todo 36 — Master release gate ledger",
        "",
        f"Generator: scripts/release_gate.py · Host: {platform.system()} ({platform.machine()})",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        "",
        "| Status | Step | Detail |",
        "|--------|------|--------|",
    ]
    for r in results:
        detail = r.note or (r.summary.strip().replace("\n", " ") if r.summary else "")
        lines.append(f"| {r.status} | `{r.id}` | {detail[:200]} |")
    lines += [
        "",
        "## Summary",
        "",
        f"- passed: {sum(1 for r in results if r.status == 'pass')}",
        f"- failed: {sum(1 for r in results if r.status == 'fail')}",
        f"- deferred: {sum(1 for r in results if r.status == 'deferred')}",
        "",
        "The gate is fail-closed: any step whose exit code falls outside its allowed",
        "set, whose required output is absent, or whose required output marker is",
        "missing is marked FAIL. Deferred steps also fail the gate (nonzero exit).",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
