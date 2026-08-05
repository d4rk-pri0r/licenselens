from pathlib import Path

from licenselens.output import build_report_dir, slugify


def test_slugify_basic():
    assert slugify("Contoso Demo (dry-run)") == "contoso-demo-dry-run"
    assert slugify("  ABC  ") == "abc"
    assert slugify("Fabrikam.West_1") == "fabrikam-west-1"


def test_slugify_empty_falls_back():
    assert slugify("!!!") == "tenant"


def test_build_report_dir_nested(tmp_path: Path):
    out = build_report_dir(
        tmp_path,
        tenant_slug="contoso",
        tenant_display_name="Ignored Name",
        tenant_id="abc123",
    )
    assert out.parent == tmp_path / "contoso"
    assert out.is_dir()
    assert out.name.startswith("20")


def test_build_report_dir_uses_display_name(tmp_path: Path):
    out = build_report_dir(tmp_path, tenant_display_name="Fabrikam West")
    assert out.parent == tmp_path / "fabrikam-west"
    assert out.is_dir()


def test_build_report_dir_uses_tenant_id_prefix(tmp_path: Path):
    out = build_report_dir(tmp_path, tenant_id="abcdefgh-1234-5678")
    assert out.parent == tmp_path / "abcdefgh"
    assert out.is_dir()


def test_build_report_dir_flat(tmp_path: Path):
    out = build_report_dir(tmp_path, tenant_slug="contoso", flat=True)
    assert out == tmp_path
    assert out.is_dir()
