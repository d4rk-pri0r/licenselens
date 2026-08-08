from pathlib import Path

import pytest
import yaml

from licenselens.batch import load_tenants_config, run_batch
from licenselens.engine.runner import run_scan


def _config(tmp_path: Path, tenants: list[dict]) -> Path:
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(yaml.safe_dump({"tenants": tenants}), encoding="utf-8")
    return cfg


def test_load_tenants_config(tmp_path: Path):
    cfg = _config(
        tmp_path,
        [{"slug": "alpha", "tenant_id": "t-a"}, {"slug": "beta", "tenant_id": "t-b"}],
    )
    defaults, tenants = load_tenants_config(cfg)
    assert defaults == {}
    assert [t["slug"] for t in tenants] == ["alpha", "beta"]


def test_load_tenants_config_with_defaults(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "defaults": {"auth": "client_secret", "packs": ["identity", "endpoint"]},
                "tenants": [{"slug": "alpha", "tenant_id": "t-a"}],
            }
        ),
        encoding="utf-8",
    )
    defaults, tenants = load_tenants_config(cfg)
    assert defaults["auth"] == "client_secret"
    assert defaults["packs"] == ["identity", "endpoint"]
    assert tenants[0]["slug"] == "alpha"


def test_load_tenants_config_rejects_non_list(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(yaml.safe_dump({"tenants": {"alpha": {}}}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_tenants_config(cfg)


def test_run_batch_dry_run(tmp_path: Path):
    cfg = _config(
        tmp_path,
        [{"slug": "alpha", "tenant_id": "t-a"}, {"slug": "beta", "tenant_id": "t-b"}],
    )
    out = tmp_path / "out"
    rows = run_batch(cfg, output_dir=out, dry_run=True)

    assert len(rows) == 2
    assert all(r["status"] == "ok" for r in rows)
    assert rows[0]["gaps"] > 0

    index = (out / "index.md").read_text(encoding="utf-8")
    assert "batch index" in index
    assert "alpha" in index and "beta" in index
    assert "| Tenant | Status gaps | Exposed | Realized | Worst move | Report |" in index
    assert rows[0]["realized_percent"] >= 0
    assert rows[0]["worst_move"]

    report_dir = Path(rows[0]["report_dir"])
    assert report_dir.is_dir()
    assert (report_dir / "security-license-lens-report.json").is_file()
    assert (report_dir / "security-license-lens-report.html").is_file()
    assert (report_dir / "security-license-lens-report.md").is_file()


def test_run_batch_isolates_tenant_failures(tmp_path: Path):
    cfg = _config(
        tmp_path,
        [
            {"slug": "good", "tenant_id": "t-a"},
            {
                "slug": "bad",
                "auth_mode": "client_secret",
                "tenant_id": "t-b",
            },
        ],
    )
    out = tmp_path / "out"
    rows = run_batch(cfg, output_dir=out, dry_run=True)

    by_slug = {r["slug"]: r for r in rows}
    assert by_slug["good"]["status"] == "ok"
    assert by_slug["bad"]["status"] == "error"
    assert by_slug["bad"]["error"]

    index = (out / "index.md").read_text(encoding="utf-8")
    assert "good" in index and "bad" in index


def test_run_batch_flags_exposed_tenants(tmp_path: Path, monkeypatch):
    cfg = _config(
        tmp_path,
        [
            {"slug": "hot", "tenant_id": "t-hot"},
            {"slug": "calm", "tenant_id": "t-calm"},
        ],
    )

    def fake_scan(*args, **kwargs):
        result = run_scan(*args, **kwargs)
        slug = kwargs.get("tenant_slug")
        if slug == "hot":
            result.exposed_check_ids = list(set(list(result.exposed_check_ids) + ["id-pim-unused"]))
            result.has_exposed = True
        return result

    monkeypatch.setattr("licenselens.batch.run_scan", fake_scan)
    out = tmp_path / "out"
    rows = run_batch(cfg, output_dir=out, dry_run=True)

    assert rows[0]["exposed"] >= 1
    index = (out / "index.md").read_text(encoding="utf-8")
    assert "Exposed tenants" in index
    # Exposed tenant sorts to the first data row.
    assert index.index("| hot |") < index.index("| calm |")
