"""Release automation contract (Todo 34).

Cross-platform static guards over the tag-gated release pipeline so the trust
invariants are locked on any host, not just GitHub runners:

  * the workflow triggers only on ``v*`` tags (build once from the release tag),
  * a gated build-once -> checksum/SBOM/attest -> promote topology with the
    promote job hard-failing unless every gate ran,
  * every action is pinned by full commit SHA (no floating tags),
  * least privilege: top-level ``contents: read``; ``id-token: write`` only on
    the attest / sign / promote jobs that actually need OIDC,
  * version consistency is checked (tag == ``pyproject.toml`` version),
  * unsigned Windows artifacts cannot enter the production channel (the
    ``verify_signing.py`` gate runs in ``promote`` and enforces the policy), and
  * a dependency/license inventory is produced and cross-checked against a
    committed ``THIRD_PARTY_NOTICES.md``.

The release workflow itself runs on GitHub-hosted runners and publishes to PyPI
and GitHub Releases; this module only parses/validates it (PyYAML/tomllib) plus
provides the pure helpers the ``scripts/release/*.py`` CLI wrappers call.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Final

import yaml

from licenselens.windows_ci import action_is_pinned

WORKFLOW_FILE: Final = ".github/workflows/publish.yml"
VERIFY_VERSION_SCRIPT: Final = "scripts/release/verify_version.py"
VERIFY_SIGNING_SCRIPT: Final = "scripts/release/verify_signing.py"
VERIFY_ATTESTATION_SCRIPT: Final = "scripts/release/verify_attestation.py"
ASSEMBLE_BUNDLE_SCRIPT: Final = "scripts/release/assemble_bundle.py"
VALIDATE_RECEIPTS_SCRIPT: Final = "scripts/release/validate_receipts.py"
CAPTURE_RECEIPT_SCRIPT: Final = "scripts/release/capture_receipt.py"
LICENSE_INVENTORY_SCRIPT: Final = "scripts/release/license_inventory.py"
PROVENANCE_SCAN_SCRIPT: Final = "scripts/provenance_scan.py"
SIGNING_STATUS_FILE: Final = "signing-status.json"
THIRD_PARTY_NOTICES: Final = "THIRD_PARTY_NOTICES.md"
PROVENANCE_CLEAN_STATUS: Final = "clean"
PROVENANCE_REQUIRED_MODES: Final = ("git-reachable", "artifacts")
FINAL_CHECKSUMS_MARKER: Final = "SHA256SUMS"
RELEASE_BUNDLE_NAME: Final = "release-bundle"

#: Jobs the release pipeline must declare, in build-once -> gate -> promote order.
REQUIRED_JOBS: Final = (
    "build",
    "build-windows",
    "checksums",
    "sbom",
    "attest",
    "sign-windows",
    "promote",
)

#: Permissions that must never be granted write at the workflow top level.
_FORBIDDEN_TOP_LEVEL_WRITE: Final = ("id-token", "attestations", "pages", "packages")

#: Allowed signing policies for the Windows artifact.
SIGNING_POLICIES: Final = ("required", "optional", "off")

_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


# ---------------------------------------------------------------------------
# Small YAML helpers
# ---------------------------------------------------------------------------


def load_workflow(text: str) -> dict:
    """Parse a workflow file, keeping the ``on`` trigger key a string.

    PyYAML resolves the bare ``on`` key to the boolean ``True`` (YAML 1.1), so
    we normalize it back to ``"on"`` here. Every other scalar is left as-is.
    """
    data = yaml.safe_load(text)
    if isinstance(data, dict) and True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def _all_steps(jobs: dict) -> list[tuple[str, dict]]:
    steps: list[tuple[str, dict]] = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []):
            if isinstance(step, dict):
                steps.append((job_name, step))
    return steps


def _run_text(step: dict) -> str:
    run = step.get("run")
    if isinstance(run, str):
        return run
    if isinstance(run, list):
        return "\n".join(str(item) for item in run)
    return ""


def _step_runs(job: dict, needle: str) -> bool:
    for _, step in _all_steps({"job": job}):
        if needle in _run_text(step):
            return True
    return False


def _job_permission(job: dict, key: str) -> str | None:
    perms = job.get("permissions") if isinstance(job, dict) else None
    if not isinstance(perms, dict):
        return None
    return perms.get(key)


def _job_uses(job: dict) -> list[str]:
    return [step.get("uses", "") for _, step in _all_steps({"job": job})]


# ---------------------------------------------------------------------------
# Workflow guards
# ---------------------------------------------------------------------------


def release_guards(repo_root: Path) -> list[str]:
    """Static guards over the release workflow; an empty list means all pass."""
    path = repo_root / WORKFLOW_FILE
    if not path.is_file():
        return [f"missing workflow file: {WORKFLOW_FILE}"]

    text = path.read_text(encoding="utf-8")
    try:
        data = load_workflow(text)
    except yaml.YAMLError as exc:
        return [f"workflow YAML does not parse: {exc}"]
    if not isinstance(data, dict):
        return ["workflow must be a YAML mapping"]

    problems: list[str] = []

    # --- tag-gated only ---------------------------------------------------
    on = data.get("on")
    if not isinstance(on, dict):
        problems.append("workflow: missing 'on' trigger")
    else:
        push = on.get("push") if isinstance(on.get("push"), dict) else {}
        if push.get("tags") != ["v*"]:
            problems.append("workflow: must trigger only on 'v*' tags (build once)")
        if "pull_request" in on:
            problems.append("workflow: must not trigger on pull_request")
        if "branches" in push:
            problems.append("workflow: must not trigger on branch pushes")

    # --- minimal top-level permissions -------------------------------------
    perms = data.get("permissions")
    if not isinstance(perms, dict) or perms.get("contents") != "read":
        problems.append("workflow: top-level 'contents' must be 'read'")
    if isinstance(perms, dict):
        for key in _FORBIDDEN_TOP_LEVEL_WRITE:
            if perms.get(key) == "write":
                problems.append(f"workflow: top-level '{key}' must not be write")

    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return problems + ["workflow: missing jobs mapping"]

    for name in REQUIRED_JOBS:
        if name not in jobs:
            problems.append(f"workflow: missing required job '{name}'")

    # --- SHA-pinned actions everywhere -------------------------------------
    for jname, step in _all_steps(jobs):
        uses = step.get("uses")
        if uses and not action_is_pinned(uses):
            problems.append(f"job '{jname}': unpinned action '{uses}'")

    # --- build: version consistency + license inventory + provenance -------
    build = jobs.get("build", {}) if isinstance(jobs.get("build"), dict) else {}
    if not _step_runs(build, VERIFY_VERSION_SCRIPT):
        problems.append("job 'build': must run the version-consistency guard (verify_version.py)")
    if not _step_runs(build, LICENSE_INVENTORY_SCRIPT):
        problems.append("job 'build': must run the license inventory (license_inventory.py)")
    if not _step_runs(build, PROVENANCE_SCAN_SCRIPT):
        problems.append("job 'build': must run provenance_scan.py")
    if not _step_runs(build, "--git-reachable"):
        problems.append("job 'build': must run provenance_scan --git-reachable")
    if not _step_runs(build, "--artifacts"):
        problems.append("job 'build': must run provenance_scan --artifacts")

    # --- checksums: final SHA256SUMS after ALL promoted artifacts ----------
    checksums = jobs.get("checksums", {}) if isinstance(jobs.get("checksums"), dict) else {}
    checksums_needs = checksums.get("needs") or []
    for upstream in ("build", "build-windows", "sbom", "sign-windows"):
        if upstream not in checksums_needs:
            problems.append(
                f"job 'checksums': needs must include '{upstream}' "
                "(final SHA256SUMS after every promoted artifact is assembled)"
            )
    checksums_runs = "\n".join(
        _run_text(step) for _, step in _all_steps({"checksums": checksums})
    )
    if ASSEMBLE_BUNDLE_SCRIPT not in checksums_runs:
        problems.append(
            f"job 'checksums': must run {ASSEMBLE_BUNDLE_SCRIPT} so final "
            "SHA256SUMS covers every promoted artifact"
        )
    elif FINAL_CHECKSUMS_MARKER not in checksums_runs and "sha256sum" not in checksums_runs:
        problems.append("job 'checksums': must recompute and verify sha256sum (bind bytes)")

    # --- sbom: SPDX + CycloneDX --------------------------------------------
    sbom = jobs.get("sbom", {}) if isinstance(jobs.get("sbom"), dict) else {}
    if not any("sbom" in uses.lower() for uses in _job_uses(sbom)):
        problems.append("job 'sbom': must use a SBOM action (SPDX + CycloneDX)")

    # --- attest: provenance + SBOM attestation -----------------------------
    attest = jobs.get("attest", {}) if isinstance(jobs.get("attest"), dict) else {}
    attest_uses = _job_uses(attest)
    if not any("attest-build-provenance" in u for u in attest_uses):
        problems.append("job 'attest': must use attest-build-provenance")
    if not any("attest-sbom" in u for u in attest_uses):
        problems.append("job 'attest': must use attest-sbom")
    if _job_permission(attest, "id-token") != "write":
        problems.append("job 'attest': must request id-token: write")
    if _job_permission(attest, "attestations") != "write":
        problems.append("job 'attest': must request attestations: write")
    attest_needs = attest.get("needs") or []
    if "checksums" not in attest_needs:
        problems.append(
            "job 'attest': needs must include 'checksums' "
            "(attest subjects from the final assembled bundle)"
        )

    # --- sign-windows: OIDC Microsoft Artifact Signing, config-gated -------
    sign = jobs.get("sign-windows", {}) if isinstance(jobs.get("sign-windows"), dict) else {}
    signing_steps = [
        step
        for _, step in _all_steps({"sign-windows": sign})
        if "trusted-signing-action" in step.get("uses", "")
    ]
    if not signing_steps:
        problems.append(
            "job 'sign-windows': must use Azure/trusted-signing-action "
            "(Microsoft Artifact Signing, OIDC)"
        )
    else:
        for step in signing_steps:
            if not step.get("if"):
                problems.append(
                    "job 'sign-windows': the trusted-signing step must be gated by "
                    "a signing-config condition (so unsigned CI artifacts never sign)"
                )
    if _job_permission(sign, "id-token") != "write":
        problems.append("job 'sign-windows': must request id-token: write (OIDC)")
    if not _step_runs(sign, SIGNING_STATUS_FILE):
        problems.append(
            "job 'sign-windows': must emit a signing-status.json marker "
            "(signed/unsigned) for the promote gate"
        )

    # --- promote: tag-gated, all gates, unsigned-can't-promote -------------
    promote = jobs.get("promote", {}) if isinstance(jobs.get("promote"), dict) else {}
    if "refs/tags" not in str(promote.get("if", "")):
        problems.append(
            "job 'promote': must be tag-gated (if: startsWith(github.ref, 'refs/tags/'))"
        )
    needs = promote.get("needs") or []
    for gate in ("build", "build-windows", "checksums", "sbom", "attest", "sign-windows"):
        if gate not in needs:
            problems.append(f"job 'promote': needs must include '{gate}'")
    if not _step_runs(promote, VERIFY_SIGNING_SCRIPT):
        problems.append(
            "job 'promote': must run the unsigned-can't-promote guard (verify_signing.py)"
        )
    if not _step_runs(promote, VERIFY_ATTESTATION_SCRIPT):
        problems.append(
            "job 'promote': must run the attestation/receipt gate "
            f"({VERIFY_ATTESTATION_SCRIPT})"
        )
    if not (
        _step_runs(promote, VALIDATE_RECEIPTS_SCRIPT)
        or _step_runs(promote, "validate_receipts")
        or _step_runs(promote, VERIFY_ATTESTATION_SCRIPT)
    ):
        problems.append(
            "job 'promote': must validate trust receipts before publish"
        )
    if not (
        _step_runs(promote, "validate-receipts")
        or _step_runs(promote, PROVENANCE_SCAN_SCRIPT)
        or _step_runs(promote, "provenance-receipts")
    ):
        problems.append(
            "job 'promote': must enforce a clean provenance receipt before publish"
        )
    if not (
        _step_runs(promote, FINAL_CHECKSUMS_MARKER)
        or _step_runs(promote, "sha256sum")
        or _step_runs(promote, VERIFY_ATTESTATION_SCRIPT)
    ):
        problems.append(
            "job 'promote': must verify final SHA256SUMS before publish (no rebuild)"
        )
    promote_runs = "\n".join(_run_text(step) for _, step in _all_steps({"promote": promote}))
    if "python -m build" in promote_runs or "pyinstaller" in promote_runs:
        problems.append("job 'promote': must not rebuild artifacts")
    promote_uses = _job_uses(promote)
    if not any("pypi-publish" in u for u in promote_uses):
        problems.append("job 'promote': must publish to PyPI via trusted publishing")
    if not any("action-gh-release" in u for u in promote_uses):
        problems.append("job 'promote': must create the GitHub Release")
    if _job_permission(promote, "id-token") != "write":
        problems.append("job 'promote': must request id-token: write (PyPI trusted publishing)")
    if _job_permission(promote, "contents") != "write":
        problems.append("job 'promote': must request contents: write (GitHub Release)")

    return problems


# ---------------------------------------------------------------------------
# Version consistency
# ---------------------------------------------------------------------------


def version_from_pyproject(repo_root: Path) -> str:
    """Return the ``[project].version`` string from ``pyproject.toml``."""
    data = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    version = data.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("pyproject.toml is missing a [project].version string")
    return version


def normalize_tag(tag: str) -> str:
    """Strip a leading ``v`` from a release tag (``v0.3.0`` -> ``0.3.0``)."""
    return tag[1:] if tag.startswith("v") else tag


def version_consistent(repo_root: Path, tag: str) -> bool:
    """Return True when the release tag and package version agree."""
    if not _TAG_RE.fullmatch(tag):
        return False
    return normalize_tag(tag) == version_from_pyproject(repo_root)


# ---------------------------------------------------------------------------
# Unsigned-can't-promote gate
# ---------------------------------------------------------------------------


def _assets_are_signed(assets_dir: Path) -> bool:
    if not assets_dir.is_dir():
        return False
    signed_zips = [
        z for z in assets_dir.rglob("licenselens-windows-x64-*.zip") if "-test-only" not in z.name
    ]
    for marker in assets_dir.rglob(SIGNING_STATUS_FILE):
        try:
            data = json.loads(marker.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return False
        if bool(data.get("signed")):
            # A marker that claims "signed" is not enough on its own: a signed
            # (non-test-only) artifact must actually be present, otherwise a
            # tampered/misleading marker could promote an unsigned build.
            return bool(signed_zips)
        return False
    # No marker: infer from the artifact names.
    return bool(signed_zips)


def signing_gate(policy: str, assets_dir: Path) -> tuple[bool, str]:
    """Enforce the Windows signing policy; return ``(ok, message)``.

    ``required`` fails when no signed Windows artifact is present; ``optional``
    allows an unsigned (test-only) artifact but reports it; ``off`` disables the
    check entirely.
    """
    if policy not in SIGNING_POLICIES:
        return False, f"unknown signing policy {policy!r} (expected one of {SIGNING_POLICIES})"
    signed = _assets_are_signed(assets_dir)
    if policy == "off":
        return True, "signing disabled (off); unsigned artifacts allowed"
    if signed:
        return True, "signed Windows artifact present"
    if policy == "optional":
        return True, "unsigned Windows artifact allowed (optional; labeled test-only)"
    return False, "signing required but no signed Windows artifact present"


# ---------------------------------------------------------------------------
# Dependency / license inventory
# ---------------------------------------------------------------------------


def direct_dependencies(pyproject_path: Path) -> list[tuple[str, str]]:
    """Return ``(name, specifier)`` for every ``[project].dependencies`` entry."""
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", [])
    result: list[tuple[str, str]] = []
    for dep in deps:
        if not isinstance(dep, str):
            continue
        name = re.split(r"[<>=!~;\[]", dep, maxsplit=1)[0].strip()
        if name:
            result.append((name, dep))
    return result


def third_party_notices_guards(repo_root: Path) -> list[str]:
    """Ensure the committed inventory covers every direct runtime dependency."""
    path = repo_root / THIRD_PARTY_NOTICES
    if not path.is_file():
        return [f"missing file: {THIRD_PARTY_NOTICES}"]
    text = path.read_text(encoding="utf-8")
    problems: list[str] = []
    for name, _spec in direct_dependencies(repo_root / "pyproject.toml"):
        if name not in text:
            problems.append(f"{THIRD_PARTY_NOTICES} is missing dependency '{name}'")
    return problems


# ---------------------------------------------------------------------------
# Provenance receipt validation (fail-closed)
# ---------------------------------------------------------------------------


def _load_json_object(path: Path) -> dict | list | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, (dict, list)) else None


def provenance_receipt_guards(
    receipt: dict | Path,
    *,
    require_modes: tuple[str, ...] | list[str] | None = None,
) -> list[str]:
    required = tuple(require_modes) if require_modes is not None else ()
    problems: list[str] = []

    if isinstance(receipt, Path):
        if not receipt.exists():
            return [f"missing provenance receipt: {receipt}"]
        if receipt.is_dir():
            files = sorted(
                p
                for p in receipt.rglob("*.json")
                if p.is_file() and p.name.startswith("provenance")
            )
            if not files:
                return [f"missing provenance receipt JSON under {receipt}"]
            for path in files:
                problems.extend(
                    provenance_receipt_guards(path, require_modes=required or None)
                )
            if required:
                modes_seen: set[str] = set()
                for path in files:
                    data = _load_json_object(path)
                    if isinstance(data, dict) and isinstance(data.get("mode"), str):
                        modes_seen.add(data["mode"])
                for mode in required:
                    if mode not in modes_seen:
                        problems.append(f"missing required provenance mode '{mode}'")
            return problems
        data = _load_json_object(receipt)
        if data is None:
            return [f"malformed provenance receipt: {receipt}"]
        label = str(receipt)
    else:
        data = receipt
        label = "receipt"

    if not isinstance(data, dict):
        return [f"malformed provenance receipt: {label}"]

    status = data.get("status")
    if status is None:
        problems.append(f"unsigned/missing provenance status: {label}")
    elif status != PROVENANCE_CLEAN_STATUS:
        problems.append(f"unclean provenance receipt status={status!r}: {label}")

    if data.get("signed") is False:
        problems.append(f"unsigned provenance receipt: {label}")

    mode = data.get("mode")
    if required and mode is not None and len(required) == 1 and mode != required[0]:
        problems.append(
            f"provenance mode mismatch: got {mode!r}, want {required[0]!r}: {label}"
        )

    violations = data.get("violations")
    if isinstance(violations, list) and violations:
        problems.append(f"provenance violations present ({len(violations)}): {label}")
    violation_count = data.get("violation_count")
    if isinstance(violation_count, int) and violation_count > 0:
        problems.append(f"provenance violation_count={violation_count}: {label}")

    return problems


def conformance_matrix_guards(matrix: dict | Path) -> list[str]:
    if isinstance(matrix, Path):
        if not matrix.is_file():
            return [f"missing conformance matrix: {matrix}"]
        data = _load_json_object(matrix)
        if not isinstance(data, dict):
            return [f"malformed conformance matrix: {matrix}"]
    else:
        data = matrix

    rows = data.get("criteria")
    if not isinstance(rows, list):
        return ["conformance matrix missing criteria list"]

    problems: list[str] = []
    blocked = ("partial", "missing", "deferred")
    for row in rows:
        if not isinstance(row, dict):
            problems.append("conformance matrix contains a non-object criterion row")
            continue
        status = str(row.get("status") or row.get("state") or "").lower()
        row_id = str(row.get("id") or row.get("criterion") or "?")
        if status in blocked:
            problems.append(f"conformance row {row_id} is {status}")
        verdict = str(row.get("verdict") or "").lower()
        if verdict in blocked:
            problems.append(f"conformance row {row_id} verdict is {verdict}")
    return problems


def gate_ledger_guards(
    ledger: dict | Path,
    *,
    fail_on_deferred: bool = True,
) -> list[str]:
    if isinstance(ledger, Path):
        if not ledger.is_file():
            return [f"missing gate ledger: {ledger}"]
        data = _load_json_object(ledger)
        if not isinstance(data, dict):
            return [f"malformed gate ledger: {ledger}"]
    else:
        data = ledger

    problems: list[str] = []
    steps = data.get("steps")
    if not isinstance(steps, list):
        return ["gate ledger missing steps list"]

    deferred = 0
    failed = 0
    for step in steps:
        if not isinstance(step, dict):
            problems.append("gate ledger contains a non-object step")
            continue
        status = str(step.get("status") or "").lower()
        step_id = str(step.get("id") or "?")
        if status == "fail":
            failed += 1
            problems.append(f"gate step {step_id} failed")
        elif status == "deferred":
            deferred += 1
            if fail_on_deferred:
                problems.append(f"gate step {step_id} is deferred")

    if isinstance(data.get("failed"), int) and data["failed"] > 0 and failed == 0:
        problems.append(f"gate ledger reports failed={data['failed']}")
    if (
        fail_on_deferred
        and isinstance(data.get("deferred"), int)
        and data["deferred"] > 0
        and deferred == 0
    ):
        problems.append(f"gate ledger reports deferred={data['deferred']}")

    return problems