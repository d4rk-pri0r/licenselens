import json
import re
from pathlib import Path

import yaml
from typer.testing import CliRunner

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS
from licenselens.cli import app
from licenselens.errors import AuthError

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Security License Lens" in result.stdout


def test_version_flag_prints_version():
    from licenselens import __version__

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert f"licenselens {__version__}" in result.stdout


def test_setup_command_prints_scaffold():
    result = runner.invoke(app, ["setup"])
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "tenant" in out.lower()
    assert "adminconsent" in out
    assert "https://login.microsoftonline.com/" in out
    assert "--tenant-id" in out
    assert "AZURE_TENANT_ID" in out
    assert "--client-secret" in out
    present = [perm for perm in REQUIRED_GRAPH_APP_PERMISSIONS if perm in out]
    assert len(present) >= 10
    assert "directory objects" in out  # one-line purpose rendered for a scope


def test_setup_alias_init():
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, result.output
    assert "adminconsent" in result.stdout


def test_setup_makes_no_network_calls(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise AssertionError("setup must not build credentials")

    monkeypatch.setattr("licenselens.cli.build_auth_context", _boom)
    result = runner.invoke(app, ["setup"])
    assert result.exit_code == 0, result.output


def test_help_renders_new_commands():
    for cmd in ["diff", "batch", "discover-workspace", "setup"]:
        result = runner.invoke(app, [cmd, "--help"])
        assert result.exit_code == 0, result.output
        assert "Usage" in result.stdout


def test_diff_command_writes_markdown(tmp_path: Path):
    out = tmp_path / "diff.md"
    result = runner.invoke(
        app,
        [
            "diff",
            str(FIXTURES / "scan-baseline.json"),
            str(FIXTURES / "scan-new.json"),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "Improved: 1" in text
    assert "New gaps: 1" in text


def test_diff_command_missing_input_exits_2(tmp_path: Path):
    result = runner.invoke(
        app,
        ["diff", str(tmp_path / "nope.json"), str(FIXTURES / "scan-new.json")],
    )
    assert result.exit_code == 2


def test_batch_command_dry_run(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "tenants": [
                    {"slug": "alpha", "tenant_id": "t-a"},
                    {"slug": "beta", "tenant_id": "t-b"},
                ]
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["batch", str(cfg), "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    assert "alpha" in result.stdout and "beta" in result.stdout
    index = (out / "index.md").read_text(encoding="utf-8")
    assert "alpha" in index and "beta" in index


def test_batch_command_reports_tenant_error(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "tenants": [
                    {"slug": "good", "tenant_id": "t-a"},
                    {"slug": "bad", "auth_mode": "client_secret", "tenant_id": "t-b"},
                ]
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["batch", str(cfg), "--output-dir", str(out)])
    assert result.exit_code == 2, result.output
    assert "error" in result.stdout.lower()
    assert (out / "index.md").is_file()


def test_doctor_command_invalid_profile_exits_2():
    result = runner.invoke(app, ["doctor", "--profile", "deep"])
    assert result.exit_code == 2
    assert "profile" in result.stdout.lower()


def test_scan_dry_run_prints_top_card(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path / "out")])
    # Dry-run has actionable gaps -> exit 1, report written, summary shown.
    assert result.exit_code == 1, result.output
    assert "Security posture" in result.stdout
    assert "Licensed capabilities detected: 25" in result.stdout
    assert "Prioritized now (identity, endpoint): 6" in result.stdout
    assert "Fully working (prioritized): 1" in result.stdout
    assert "Need attention (prioritized): 5" in result.stdout
    assert "Priority actions:" in result.stdout
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_scan_output_surfaces_diff_loop(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 1, result.output
    assert "To compare against a prior assessment" in result.stdout
    assert "licenselens diff <old.json> <new.json>" in result.stdout


def test_scan_second_run_preserves_prior_reports(tmp_path: Path):
    out = tmp_path / "out"
    first = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(out)])
    assert first.exit_code == 1, first.output
    original_json = out / "security-license-lens-report.json"
    assert original_json.is_file()
    before = original_json.read_text(encoding="utf-8")

    second = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(out)])
    assert second.exit_code == 1, second.output
    assert "Prior report files found" in second.stdout
    # The prior scan's flat artifacts (the diff baseline) are untouched.
    assert original_json.read_text(encoding="utf-8") == before
    fresh = [p for p in out.iterdir() if p.is_dir() and p.name.startswith("scan-")]
    assert len(fresh) == 1
    assert (fresh[0] / "security-license-lens-report.json").is_file()
    assert (fresh[0] / "security-license-lens-report.html").is_file()
    assert (fresh[0] / "security-license-lens-report.md").is_file()
    # No nested diversion: the fresh dir itself is written into directly.
    assert len(list(fresh[0].iterdir())) == 3


def test_scan_dry_run_prints_plain_language_exposure(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path / "out")])

    assert result.exit_code == 1, result.output
    assert "EXPOSED" not in result.stdout
    assert "id-ca-priv-gaps" not in result.stdout


def test_scan_dry_run_rejects_invalid_pack(tmp_path: Path):
    result = runner.invoke(
        app,
        ["scan", "--dry-run", "--pack", "bogus", "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 2, result.output
    assert "Invalid pack" in result.stdout
    assert "bogus" in result.stdout


def test_scan_non_tty_defaults_to_dry_run(tmp_path: Path):
    # CliRunner is non-interactive; bare scan without --live stays dry-run.
    result = runner.invoke(app, ["scan", "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 1, result.output
    assert "dry-run" in result.stdout
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_scan_dry_run_emits_progress_and_collection_summary(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 1, result.output
    out = result.stdout
    assert re.search(r"\b\d+/\d+ ", out)
    assert "access_review_definitions" in out
    assert " ok" in out
    assert "Collection summary:" in out
    assert "data sources" in out


def test_scan_summary_status_counts_render_as_table_without_repr_artifacts(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 1, result.output
    out = result.stdout
    # No dict repr or raw exception artifacts anywhere in the scan summary.
    assert "status_counts" not in out
    assert "{'" not in out
    assert "repr(" not in out
    assert "Traceback" not in out
    # The status counts render as a readable table with human labels.
    assert "Finding status" in out
    assert "Needs attention" in out
    assert "Count" in out


def test_status_count_rows_orders_known_statuses_and_keeps_unknown():
    from licenselens.engine.runner_findings import status_count_rows

    rows = status_count_rows({"ok": 40, "gap": 7, "error": 2, "mystery": 1})
    assert [status for status, _label, _count in rows] == ["gap", "error", "ok", "mystery"]
    assert rows[0][1] == "Needs attention"
    assert rows[1][2] == 2
    assert status_count_rows({}) == []


def test_scan_non_tty_without_mode_flag_warns_about_demo_dry_run(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 1, result.output
    assert "No terminal and no auth mode specified" in result.stdout
    assert "running the offline demo (dry-run)" in result.stdout
    assert "Pass --live --tenant-id" in result.stdout


def test_scan_explicit_dry_run_skips_demo_warning(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 1, result.output
    assert "No terminal and no auth mode specified" not in result.stdout


def test_scan_live_non_tty_missing_auth_exits_2(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    result = runner.invoke(
        app,
        ["scan", "--live", "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 2, result.output
    assert (
        "missing auth" in result.stdout.lower() or "interactive terminal" in result.stdout.lower()
    )


def test_scan_interactive_demo_path(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("licenselens.cli_prompts.is_interactive", lambda: True)
    # Mode: 1 = demo sample data. Remaining prompts should not run for dry-run.
    result = runner.invoke(
        app,
        ["scan", "--output-dir", str(tmp_path / "out")],
        input="1\n",
    )
    assert result.exit_code == 1, result.output
    assert "What do you want to scan?" in result.stdout
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_resolve_scan_inputs_non_interactive_uses_flags(monkeypatch, tmp_path: Path):
    from licenselens.auth import AuthMode
    from licenselens.cli_prompts import resolve_scan_inputs

    monkeypatch.setattr("licenselens.cli_prompts.is_interactive", lambda: False)
    result = resolve_scan_inputs(
        live=True,
        auth="client_secret",
        tenant_id="t1",
        client_id="c1",
        client_secret="s1",
        output_dir=tmp_path / "r",
        workspace_resource_id="/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z",
        open_browser=False,
    )
    assert result.live is True
    assert result.auth_mode == AuthMode.CLIENT_SECRET
    assert result.tenant_id == "t1"
    assert result.client_id == "c1"
    assert result.client_secret == "s1"
    assert result.run_doctor is False
    assert result.workspace_resource_id is not None


def test_resolve_scan_inputs_interactive_live_client_secret(monkeypatch, tmp_path: Path):
    from licenselens.auth import AuthMode
    from licenselens.cli_prompts import resolve_scan_inputs

    monkeypatch.setattr("licenselens.cli_prompts.is_interactive", lambda: True)
    prompts = iter(
        [
            "tenant-guid",
            "app-guid",
            "super-secret",
            str(tmp_path / "out"),
        ]
    )
    confirms = iter([False, False, False])  # open, sentinel, doctor
    monkeypatch.setattr("typer.prompt", lambda *a, **k: next(prompts))
    monkeypatch.setattr("typer.confirm", lambda *a, **k: next(confirms))

    result = resolve_scan_inputs(
        live=True,
        auth="client_secret",
        tenant_id=None,
        client_id=None,
        client_secret=None,
        output_dir=Path("reports"),
        workspace_resource_id=None,
        open_browser=False,
    )
    assert result.live is True
    assert result.auth_mode == AuthMode.CLIENT_SECRET
    assert result.tenant_id == "tenant-guid"
    assert result.client_id == "app-guid"
    assert result.client_secret == "super-secret"
    assert result.output_dir == tmp_path / "out"
    assert result.open_browser is False
    assert result.run_doctor is False


def test_demo_command_prints_html_path(tmp_path: Path):
    result = runner.invoke(app, ["demo", "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 0, result.output
    assert "offline demo scan" in result.stdout
    assert "Licensed capabilities detected: 25" in result.stdout
    assert "security-license-lens-report.html" in result.stdout.replace("\n", "")
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_resolve_quickstart_inputs_non_tty_falls_back_to_demo(monkeypatch):
    from licenselens.cli_prompts import resolve_quickstart_inputs

    monkeypatch.setattr("licenselens.cli_prompts.is_interactive", lambda: False)
    result = resolve_quickstart_inputs(tenant_id=None, client_id=None, client_secret=None)
    assert result.fallback_demo is True
    assert result.tenant_id is None


def test_resolve_quickstart_inputs_non_tty_uses_env_tenant_id(monkeypatch):
    from licenselens.cli_prompts import resolve_quickstart_inputs

    monkeypatch.setattr("licenselens.cli_prompts.is_interactive", lambda: False)
    monkeypatch.setenv("AZURE_TENANT_ID", "env-tid")
    result = resolve_quickstart_inputs(tenant_id=None, client_id=None, client_secret=None)
    assert result.fallback_demo is False
    assert result.tenant_id == "env-tid"


def test_resolve_quickstart_inputs_interactive_prompts_tenant_id(monkeypatch):
    from licenselens.cli_prompts import resolve_quickstart_inputs

    monkeypatch.setattr("licenselens.cli_prompts.is_interactive", lambda: True)
    prompts = iter(["tenant-guid", "app-guid"])
    confirms = iter([False])
    monkeypatch.setattr("typer.prompt", lambda *a, **k: next(prompts))
    monkeypatch.setattr("typer.confirm", lambda *a, **k: next(confirms))

    result = resolve_quickstart_inputs(tenant_id=None, client_id=None, client_secret=None)
    assert result.fallback_demo is False
    assert result.tenant_id == "tenant-guid"
    assert result.client_id == "app-guid"


def test_quickstart_help_and_invalid_secret_no_rail(monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    result = runner.invoke(app, ["quickstart", "--help"])
    assert result.exit_code == 0, result.output
    assert "read-only" in result.stdout.lower()

    # Client-secret path without the other credentials is a config error:
    # actionable message, exit 2, and NO "Sign-in blocked?" rail.
    result = runner.invoke(app, ["quickstart", "--client-secret", "s3cret"])
    assert result.exit_code == 2
    assert "tenant" in result.stdout.lower()
    assert "app-only" not in result.stdout.lower()


def test_quickstart_non_tty_no_tenant_id_falls_back_to_demo(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    out = tmp_path / "out"
    result = runner.invoke(app, ["quickstart", "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    assert "tenant" in result.stdout.lower()
    assert "demo" in result.stdout.lower()
    assert "app-only" not in result.stdout.lower()
    assert (out / "security-license-lens-report.html").is_file()


def test_quickstart_genuine_auth_failure_shows_rail(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)

    def _fail_doctor(_auth):
        raise AuthError("sign-in was blocked by a conditional-access policy")

    monkeypatch.setattr("licenselens.cli.run_doctor", _fail_doctor)
    result = runner.invoke(
        app,
        ["quickstart", "--tenant-id", "t-1234", "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 2, result.output
    assert "app-only" in result.stdout.lower()


def test_doctor_dry_run_does_not_print_ready():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "Ready — all preflight" not in result.stdout
    assert "dry-run" in result.stdout.lower()
    assert "no live tenant calls" in result.stdout.lower()
    assert "doctor --live" in result.stdout.lower()


def _doctor_live_graph_routes():
    from tests.fake_clients import FakeGraphClient, ok

    fake = FakeGraphClient()
    fake.register_list("/organization", ok({"value": [{"id": "t1", "displayName": "Contoso"}]}))
    fake.register_list("/subscribedSkus", ok({"value": []}))
    fake.register_list("/identity/conditionalAccess/policies", ok({"value": []}))
    fake.register_list("/roleManagement/directory/roleAssignments", ok({"value": []}))
    fake.register_get("/security/secureScores", ok({"value": [{"id": "s1", "controlScores": []}]}))
    return fake


def _patch_doctor_live_auth(monkeypatch, graph_fake):
    from unittest.mock import MagicMock

    from licenselens.auth import AuthContext

    class _FakeToken:
        token = "fake-token"

    def _build_auth_context(*, mode, tenant_id=None, client_id=None, client_secret=None):
        cred = MagicMock()
        cred.get_token.return_value = _FakeToken()
        return AuthContext(
            mode=mode, tenant_id=tenant_id or "t1", client_id=client_id, credential=cred
        )

    monkeypatch.setattr("licenselens.cli.build_auth_context", _build_auth_context)
    monkeypatch.setattr("licenselens.doctor.GraphClient", lambda auth: graph_fake)


def test_doctor_live_device_code_reports_delegated_note_not_missing_app_permissions(
    monkeypatch,
):
    _patch_doctor_live_auth(monkeypatch, _doctor_live_graph_routes())
    result = runner.invoke(app, ["doctor", "--live"])
    assert result.exit_code == 0, result.output
    text = " ".join(re.sub(r"[^\w\s\-(),.]", " ", result.stdout).split())
    assert "Missing application permission(s)" not in text
    assert "cannot be pre-verified" in text


def test_doctor_live_client_secret_still_reports_missing_app_permissions(monkeypatch):
    from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS
    from licenselens.doctor import GRAPH_RESOURCE_APP_ID
    from tests.fake_clients import ok

    client_id = "client-app-1"
    sp_id = "sp-1"
    granted = list(REQUIRED_GRAPH_APP_PERMISSIONS)[:5]

    fake = _doctor_live_graph_routes()
    fake.register_get(
        f"/servicePrincipals(appId='{client_id}')", ok({"id": sp_id, "appId": client_id})
    )
    fake.register_get(
        f"/servicePrincipals(appId='{GRAPH_RESOURCE_APP_ID}')",
        ok(
            {
                "id": "graph-sp",
                "appRoles": [{"id": f"graph-role-{p}", "value": p} for p in granted],
            }
        ),
    )
    fake.register_list(
        f"/servicePrincipals/{sp_id}/appRoleAssignments",
        ok({"value": [{"id": f"assign-{p}", "appRoleId": f"graph-role-{p}"} for p in granted]}),
    )

    _patch_doctor_live_auth(monkeypatch, fake)
    result = runner.invoke(
        app, ["doctor", "--live", "--auth", "client_secret", "--client-id", client_id]
    )
    assert result.exit_code == 0, result.output
    text = " ".join(re.sub(r"[^\w\s\-(),.]", " ", result.stdout).split())
    assert "Missing application permission(s)" in text


def test_scan_help_exposes_profile_config_rules_backend_archive():
    # GITHUB_ACTIONS/FORCE_COLOR make Typer's rich highlighter split "--opt"
    # into colored "-" + "-opt", so assert on ANSI-stripped help text.
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0, result.output
    help_text = _ANSI_ESCAPE.sub("", result.stdout or result.output)
    assert "--profile" in help_text
    assert "--config" in help_text
    assert "--rules" in help_text
    assert "--backend" in help_text
    assert "--report-archive" in help_text


def test_scan_dry_run_with_identity_profile_narrows_scope(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["scan", "--dry-run", "--profile", "identity", "--output-dir", str(out)],
    )
    assert result.exit_code == 1, result.output
    assert "Profile: identity" in result.stdout
    json_path = out / "security-license-lens-report.json"
    assert json_path.is_file()
    payload = yaml.safe_load(json_path.read_text(encoding="utf-8"))
    assert payload["profile_ids"] == ["identity"]
    assert payload["packs_scanned"] == ["identity"]
    check_ids = {finding["check_id"] for finding in payload["findings"]}
    assert "id-ca-priv-gaps" in check_ids
    assert "mde-onboard-gap" not in check_ids
    assert any(cid.startswith("custom:identity:") for cid in check_ids)


def test_scan_omitting_profile_matches_legacy_scope(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(out)])
    assert result.exit_code == 1, result.output
    payload = yaml.safe_load(
        (out / "security-license-lens-report.json").read_text(encoding="utf-8")
    )
    assert payload["profile_ids"] == []
    assert "Prioritized now (identity, endpoint): 6" in result.stdout


def test_scan_invalid_profile_exits_2_before_auth(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    auth_calls: list[object] = []

    def _boom(*_args, **_kwargs):
        auth_calls.append(1)
        raise AssertionError("build_auth_context must not run for bad profile")

    monkeypatch.setattr("licenselens.cli.build_auth_context", _boom)
    result = runner.invoke(
        app,
        [
            "scan",
            "--live",
            "--profile",
            "not-a-real-profile",
            "--auth",
            "client_secret",
            "--tenant-id",
            "t",
            "--client-id",
            "c",
            "--client-secret",
            "s",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2, result.output
    assert "unknown profile" in result.stdout.lower()
    assert "identity" in result.stdout.lower()
    assert auth_calls == []


def test_scan_invalid_rules_exits_2_before_auth(tmp_path: Path, monkeypatch):
    rules = tmp_path / "bad-rules.yaml"
    rules.write_text("custom_rules: not-a-list\n", encoding="utf-8")
    auth_calls: list[object] = []
    monkeypatch.setattr(
        "licenselens.cli.build_auth_context",
        lambda *a, **k: auth_calls.append(1),
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--rules",
            str(rules),
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2, result.output
    assert "configuration error" in result.stdout.lower()
    assert auth_calls == []


def test_scan_invalid_backend_exits_2(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--backend",
            "telepathy",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2, result.output
    assert "unknown backend" in result.stdout.lower()


def test_scan_report_archive_writes_zip(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--profile",
            "identity",
            "--report-archive",
            "--output-dir",
            str(out),
        ],
    )
    assert result.exit_code == 1, result.output
    assert (out / "security-license-lens-report.zip").is_file()
    assert "ZIP" in result.stdout


def test_demo_profile_and_archive(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["demo", "--profile", "email", "--report-archive", "--output-dir", str(out)],
    )
    assert result.exit_code == 0, result.output
    payload = yaml.safe_load(
        (out / "security-license-lens-report.json").read_text(encoding="utf-8")
    )
    assert payload["profile_ids"] == ["email"]
    assert (out / "security-license-lens-report.zip").is_file()


def test_batch_profile_flag_and_tenant_profile(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "defaults": {"profile": "identity"},
                "tenants": [
                    {"slug": "alpha", "tenant_id": "t-a"},
                    {"slug": "beta", "tenant_id": "t-b", "profile": "email"},
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["batch", str(cfg), "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    by_slug = {
        path.relative_to(out).parts[0]: path
        for path in out.rglob("security-license-lens-report.json")
    }
    alpha = yaml.safe_load(by_slug["alpha"].read_text(encoding="utf-8"))
    beta = yaml.safe_load(by_slug["beta"].read_text(encoding="utf-8"))
    assert alpha["profile_ids"] == ["identity"]
    assert beta["profile_ids"] == ["email"]


def test_batch_invalid_cli_profile_exits_2_before_tenants(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(
        yaml.safe_dump({"tenants": [{"slug": "alpha", "tenant_id": "t-a"}]}),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["batch", str(cfg), "--profile", "nope", "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 2, result.output
    assert "unknown profile" in result.stdout.lower()
    assert not (tmp_path / "out" / "index.md").exists()


def test_doctor_assessment_profile_prints_requirements():
    result = runner.invoke(app, ["doctor", "--assessment-profile", "identity"])
    assert result.exit_code == 0, result.output
    assert "Assessment profile requirements" in result.stdout
    assert "identity" in result.stdout.lower()
    assert "Capabilities:" in result.stdout
    assert "Permissions:" in result.stdout
    assert "Modules:" in result.stdout


def test_doctor_invalid_assessment_profile_exits_2_before_auth(monkeypatch):
    auth_calls: list[object] = []
    monkeypatch.setattr(
        "licenselens.cli.build_auth_context",
        lambda *a, **k: auth_calls.append(1),
    )
    result = runner.invoke(app, ["doctor", "--assessment-profile", "missing-profile"])
    assert result.exit_code == 2, result.output
    assert "unknown profile" in result.stdout.lower()
    assert auth_calls == []


def test_doctor_probe_profile_still_basic_full_only():
    result = runner.invoke(app, ["doctor", "--profile", "deep"])
    assert result.exit_code == 2
    assert "profile" in result.stdout.lower()
    assert "basic" in result.stdout.lower()
    assert "full" in result.stdout.lower()
    assert "--assessment-profile" in result.stdout.lower()


def test_checks_lists_profile_backend_mode_state():
    result = runner.invoke(app, ["checks"])
    assert result.exit_code == 0, result.output
    assert "Profiles" in result.stdout
    assert "Backend" in result.stdout
    assert "Mode" in result.stdout
    assert "State" in result.stdout
    assert "id-ca-pr…" in result.stdout
    assert "identity" in result.stdout
    assert "enabled" in result.stdout
    assert "direct" in result.stdout


def test_checks_json_emits_full_ids():
    result = runner.invoke(app, ["checks", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert isinstance(payload, list) and len(payload) >= 100
    by_id = {item["id"]: item for item in payload}
    assert "id-ca-priv-gaps" in by_id
    assert "endpoint-compliance-noncompliance-action" in by_id  # longest id, untruncated
    for item in payload:
        assert "…" not in item["id"]
        assert item["title"]
        assert item["workload"]
        assert item["severity"]
        assert isinstance(item["mode"], str) and item["mode"]
        assert item["state"] in {"enabled", "disabled"}
        assert isinstance(item["capabilities"], list)
        assert isinstance(item["profiles"], list)


def test_quickstart_invalid_profile_exits_2_before_auth(monkeypatch):
    auth_calls: list[object] = []
    monkeypatch.setattr(
        "licenselens.cli.build_auth_context",
        lambda *a, **k: auth_calls.append(1),
    )
    result = runner.invoke(app, ["quickstart", "--profile", "nope"])
    assert result.exit_code == 2, result.output
    assert "unknown profile" in result.stdout.lower()
    assert auth_calls == []


def test_scan_config_overlay_merges_custom_rules(tmp_path: Path):
    config = tmp_path / "org.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "id": "org-identity",
                "name": "Org identity",
                "custom_rules": [
                    {
                        "id": "org-gap-count",
                        "title": "Org gap count",
                        "selector": "finding.status",
                        "operator": "gte",
                        "value": 1,
                        "collection": "count",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--profile",
            "identity",
            "--config",
            str(config),
            "--output-dir",
            str(out),
        ],
    )
    assert result.exit_code == 1, result.output
    payload = yaml.safe_load(
        (out / "security-license-lens-report.json").read_text(encoding="utf-8")
    )
    assert payload["profile_ids"] == ["identity", "org-identity"]
    check_ids = {finding["check_id"] for finding in payload["findings"]}
    assert any("org-gap-count" in cid for cid in check_ids)
