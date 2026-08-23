import pytest

from licenselens.auth import AuthMode, build_auth_context, resolve_auth_inputs
from licenselens.errors import AuthError


def test_resolve_auth_inputs_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AZURE_TENANT_ID", " tid ")
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "sec")
    tid, cid, secret, cert_path, cert_thumb = resolve_auth_inputs(mode=AuthMode.CLIENT_SECRET)
    assert (tid, cid, secret) == ("tid", "cid", "sec")
    assert cert_path is None and cert_thumb is None


def test_resolve_certificate_inputs_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AZURE_CLIENT_CERTIFICATE_PATH", "/var/certs/app.pem")
    monkeypatch.setenv("AZURE_CLIENT_CERT_THUMBPRINT", "AB:CD:EF")
    _, _, _, cert_path, cert_thumb = resolve_auth_inputs(mode=AuthMode.CERTIFICATE)
    assert cert_path == "/var/certs/app.pem"
    assert cert_thumb == "AB:CD:EF"


def test_certificate_auth_requires_all_fields():
    with pytest.raises(AuthError):
        build_auth_context(mode=AuthMode.CERTIFICATE, tenant_id="t", client_id="c")


def test_client_secret_requires_all_fields():
    with pytest.raises(AuthError):
        build_auth_context(mode=AuthMode.CLIENT_SECRET, tenant_id="t", client_id="c")


def test_dry_run_has_no_credential():
    ctx = build_auth_context(mode=AuthMode.DRY_RUN)
    assert ctx.credential is None
    assert not ctx.has_credentials
