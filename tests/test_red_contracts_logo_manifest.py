"""RED contract: pinned Microsoft workload logo manifest (todo 15 gate)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "assets" / "vendor" / "microsoft-cloud" / "manifest.yaml"
PINNED_UPSTREAM_COMMIT = "fc3a6c9506dc9a6ebdfb4f5891ee486f2717257c"
EXPECTED_ASSET_COUNT = 12
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def _load_manifest() -> dict[str, Any]:
    assert MANIFEST_PATH.is_file(), (
        f"missing vendor logo manifest at {MANIFEST_PATH.as_posix()} "
        "(assets/vendor/microsoft-cloud/manifest.yaml required by todo 15)"
    )
    data = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "logo manifest root must be a mapping"
    return data


def _asset_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("assets", "files", "icons", "entries"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    raise AssertionError("logo manifest must contain an assets/files list of pinned file entries")


def test_logo_manifest_pins_exactly_twelve_allowlisted_assets() -> None:
    data = _load_manifest()
    assets = _asset_entries(data)
    assert len(assets) == EXPECTED_ASSET_COUNT, (
        f"logo manifest must pin exactly {EXPECTED_ASSET_COUNT} assets, got {len(assets)}"
    )

    upstream = (
        data.get("upstream_commit")
        or data.get("source_commit")
        or data.get("commit")
        or (data.get("upstream") or {}).get("commit")
    )
    assert upstream == PINNED_UPSTREAM_COMMIT, (
        f"manifest upstream commit must be {PINNED_UPSTREAM_COMMIT}, got {upstream!r}"
    )

    paths: list[str] = []
    for entry in assets:
        rel = str(entry.get("path") or entry.get("file") or entry.get("name") or "")
        assert rel, f"asset entry missing path: {entry!r}"
        paths.append(rel)
        sha = str(entry.get("sha256") or entry.get("sha256_hex") or entry.get("digest") or "")
        assert SHA256_RE.match(sha), f"asset {rel!r} missing pinned sha256, got {sha!r}"
        entry_commit = entry.get("commit") or entry.get("upstream_commit") or upstream
        assert entry_commit == PINNED_UPSTREAM_COMMIT, (
            f"asset {rel!r} must pin upstream commit {PINNED_UPSTREAM_COMMIT}"
        )
        blob = " ".join(str(v).lower() for v in entry.values())
        assert "unofficial" not in blob, f"asset {rel!r} must not use unofficial variant"
        assert "legacy" not in Path(rel).parts, f"asset path must not use legacy folder: {rel}"

    # On-disk tree under the vendor root must match the allowlist (no extras).
    vendor_root = MANIFEST_PATH.parent
    on_disk = sorted(
        p.relative_to(vendor_root).as_posix()
        for p in vendor_root.rglob("*")
        if p.is_file() and p.name != "manifest.yaml"
    )
    assert len(on_disk) == EXPECTED_ASSET_COUNT, (
        f"vendor tree must contain exactly {EXPECTED_ASSET_COUNT} asset files, got {on_disk}"
    )


def test_logo_manifest_rejects_drift_and_unofficial_variants(tmp_path: Path) -> None:
    """Manifest verifier must fail closed on checksum drift and unofficial names."""
    data = _load_manifest()
    # Prefer an exported validator if present; otherwise enforce inline drift rules.
    validator = None
    for mod_name in (
        "licenselens.assets_manifest",
        "licenselens.vendor_assets",
    ):
        try:
            import importlib

            mod = importlib.import_module(mod_name)
            validator = getattr(mod, "validate_manifest", None) or getattr(
                mod, "verify_assets", None
            )
            if callable(validator):
                break
        except ImportError:
            continue

    assets = _asset_entries(data)
    drifted = dict(assets[0])
    drifted["sha256"] = "0" * 64
    unofficial = {
        "path": "logos/unofficial/legacy-icon.svg",
        "sha256": "a" * 64,
        "commit": PINNED_UPSTREAM_COMMIT,
    }

    if callable(validator):
        drift_problems = validator({**data, "assets": [drifted, *assets[1:]]})
        assert drift_problems, "validator must reject checksum drift"
        unofficial_problems = validator({**data, "assets": [*assets, unofficial]})
        assert unofficial_problems, "validator must reject unofficial/legacy assets"
        return

    # Inline fail-closed checks until a dedicated validator module lands.
    assert drifted.get("sha256") != assets[0].get("sha256"), "drift fixture must differ"
    assert "unofficial" in str(unofficial["path"])
    raise AssertionError(
        "logo manifest drift/unofficial rejection API is not implemented; "
        "validator module required (todo 15)"
    )
