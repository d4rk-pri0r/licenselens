import pytest

from licenselens.auth import AuthMode, build_auth_context, resolve_auth_inputs
from licenselens.errors import AuthError


def test_resolve_auth_inputs_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AZURE_TENANT_ID", " tid ")
    monkeypatch.setenv("AZURE_CLIENT_ID", "cid")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "sec")
    tid, cid, secret = resolve_auth_inputs(mode=AuthMode.CLIENT_SECRET)
    assert (tid, cid, secret) == ("tid", "cid", "sec")


def test_client_secret_requires_all_fields():
    with pytest.raises(AuthError):
        build_auth_context(mode=AuthMode.CLIENT_SECRET, tenant_id="t", client_id="c")


def test_dry_run_has_no_credential():
    ctx = build_auth_context(mode=AuthMode.DRY_RUN)
    assert ctx.credential is None
    assert not ctx.has_credentials
