import pytest
from typer.testing import CliRunner

from licenselens.auth import AuthMode, build_auth_context, build_credential
from licenselens.cli import app
from licenselens.errors import AuthConfigError

runner = CliRunner()


def test_oidc_credential_from_mocked_token():
    """A pre-fetched OIDC token builds a ClientAssertionCredential (no network)."""
    credential = build_credential(
        AuthMode.OIDC,
        tenant_id="tenant-id",
        client_id="client-id",
        oidc_token="mock-oidc-jwt",
    )
    assert credential is not None
    # ClientAssertionCredential stores the assertion-providing callable.
    assert credential._func() == "mock-oidc-jwt"


def test_oidc_requires_tenant_and_client_id():
    with pytest.raises(AuthConfigError):
        build_credential(AuthMode.OIDC, client_id="client-id", oidc_token="tok")
    with pytest.raises(AuthConfigError):
        build_credential(AuthMode.OIDC, tenant_id="tenant-id", oidc_token="tok")


def test_oidc_without_token_or_env_raises_config_error(monkeypatch: pytest.MonkeyPatch):
    """OIDC with neither oidc_token nor the Actions runtime env raises exit-2 error."""
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    with pytest.raises(AuthConfigError):
        build_credential(AuthMode.OIDC, tenant_id="tenant-id", client_id="client-id")


def test_oidc_build_auth_context_with_mocked_token():
    ctx = build_auth_context(
        mode=AuthMode.OIDC,
        tenant_id="tenant-id",
        client_id="client-id",
        oidc_token="mock-oidc-jwt",
    )
    assert ctx.mode == AuthMode.OIDC
    assert ctx.has_credentials
    assert ctx.credential is not None


# ---------------------------------------------------------------------------
# CLI wiring: --auth oidc must be accepted (not a typer invalid-choice error)
# ---------------------------------------------------------------------------


def test_scan_help_lists_oidc_in_auth_choices():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0, result.output
    assert "oidc" in result.stdout


def test_doctor_help_lists_oidc_in_auth_choices():
    result = runner.invoke(app, ["doctor", "--help"])
    assert result.exit_code == 0, result.output
    assert "oidc" in result.stdout


def test_scan_auth_oidc_reaches_oidc_path_not_typer_invalid_choice(
    monkeypatch: pytest.MonkeyPatch,
):
    """--auth oidc must NOT produce the typer 'not one of' invalid-choice error.

    It should reach the OIDC code path. Outside GitHub Actions the OIDC token
    fetch fails with a clean AuthConfigError (exit 2), never the typer
    invalid-choice error.
    """
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)

    result = runner.invoke(
        app,
        [
            "scan",
            "--live",
            "--auth",
            "oidc",
            "--tenant-id",
            "tenant-id",
            "--client-id",
            "client-id",
            "--output-dir",
            "reports",
        ],
    )
    # Must NOT be the typer invalid-choice error.
    assert "not one of" not in result.stdout
    assert "Invalid value for '--auth'" not in result.stdout
    # It reaches the OIDC code path, which fails cleanly outside the Actions
    # runtime with a config error (exit 2).
    assert result.exit_code == 2
    assert "OIDC" in result.stdout


def test_scan_auth_oidc_dry_run_accepts_flag(tmp_path):
    """--auth oidc --dry-run must not hit the typer invalid-choice error.

    Dry-run ignores the auth mode (DRY_RUN), so the scan proceeds normally.
    """
    result = runner.invoke(
        app,
        ["scan", "--auth", "oidc", "--dry-run", "--output-dir", str(tmp_path / "out")],
    )
    assert "not one of" not in result.stdout
    assert "Invalid value for '--auth'" not in result.stdout
    assert result.exit_code == 1, result.output
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


# ---------------------------------------------------------------------------
# CLI wiring: --auth certificate must be accepted (not a typer invalid-choice
# error, and not the "Unknown auth mode" scan-input error)
# ---------------------------------------------------------------------------


def test_scan_auth_certificate_reaches_cert_path_not_typer_invalid_choice(
    monkeypatch: pytest.MonkeyPatch,
):
    """--auth certificate must NOT produce the typer 'not one of' invalid-choice
    error, nor the scan-input "Unknown auth mode" error.

    It should reach the certificate code path. With no certificate path
    provided it fails cleanly with an AuthConfigError (exit 2), never the
    typer invalid-choice error or the "Unknown auth mode" error.
    """
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_CERTIFICATE_PATH", raising=False)

    result = runner.invoke(
        app,
        [
            "scan",
            "--live",
            "--auth",
            "certificate",
            "--tenant-id",
            "tenant-id",
            "--client-id",
            "client-id",
            "--output-dir",
            "reports",
        ],
    )
    # Must NOT be the typer invalid-choice error.
    assert "not one of" not in result.stdout
    assert "Invalid value for '--auth'" not in result.stdout
    # Must NOT be the scan-input "Unknown auth mode" error (the regression
    # guard: before the _parse_auth_flag fix this appeared).
    assert "Unknown auth mode" not in result.stdout
    # It reaches the certificate code path, which fails cleanly with a config
    # error (exit 2) because no certificate path is provided.
    assert result.exit_code == 2
    assert "Certificate auth requires" in result.stdout


def test_scan_auth_certificate_dry_run_accepts_flag(tmp_path):
    """--auth certificate --dry-run must not hit the typer invalid-choice error
    nor the "Unknown auth mode" error.

    Dry-run ignores the auth mode (DRY_RUN), so the scan proceeds normally.
    """
    result = runner.invoke(
        app,
        [
            "scan",
            "--auth",
            "certificate",
            "--dry-run",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert "not one of" not in result.stdout
    assert "Invalid value for '--auth'" not in result.stdout
    assert "Unknown auth mode" not in result.stdout
    assert result.exit_code == 1, result.output
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_discover_workspace_auth_certificate_reaches_cert_path(
    monkeypatch: pytest.MonkeyPatch,
):
    """--auth certificate on discover-workspace must reach the certificate code
    path, not the "Unknown auth mode" scan-input error."""
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_CERTIFICATE_PATH", raising=False)

    result = runner.invoke(
        app,
        [
            "discover-workspace",
            "--auth",
            "certificate",
            "--tenant-id",
            "tenant-id",
            "--client-id",
            "client-id",
        ],
    )
    assert "not one of" not in result.stdout
    assert "Invalid value for '--auth'" not in result.stdout
    assert "Unknown auth mode" not in result.stdout
    assert result.exit_code == 2
    assert "Certificate auth requires" in result.stdout
