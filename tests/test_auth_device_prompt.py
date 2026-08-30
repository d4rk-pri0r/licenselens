"""Tests for the optional device-code prompt callback (T4).

The callback lets the local ui wizard capture
(verification_url, user_code, expires_on) when device-code auth fires,
without printing or logging anything.
"""

from datetime import datetime

import pytest
from azure.identity import DeviceCodeCredential

from licenselens.auth import AuthMode, build_auth_context, build_credential


class _RecordingDeviceCodeCredential:
    """Stands in for azure-identity's DeviceCodeCredential and records kwargs."""

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.prompt_callback: object | None = kwargs.get("prompt_callback")


@pytest.fixture()
def captured(monkeypatch: pytest.MonkeyPatch) -> list[_RecordingDeviceCodeCredential]:
    """Replace azure.identity.DeviceCodeCredential with the recording double."""
    constructed: list[_RecordingDeviceCodeCredential] = []
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)

    def _factory(**kwargs: object) -> _RecordingDeviceCodeCredential:
        instance = _RecordingDeviceCodeCredential(**kwargs)
        constructed.append(instance)
        return instance

    monkeypatch.setattr("azure.identity.DeviceCodeCredential", _factory)
    return constructed


def test_device_code_default_keeps_existing_behavior(captured) -> None:
    credential = build_credential(AuthMode.DEVICE_CODE, tenant_id="tenant-a")
    assert isinstance(credential, _RecordingDeviceCodeCredential)
    assert len(captured) == 1
    # No prompt callback requested: prompt_callback is None (azure-identity's default).
    assert captured[0].kwargs["prompt_callback"] is None
    assert captured[0].kwargs["tenant_id"] == "tenant-a"
    assert captured[0].kwargs["client_id"] == "14d82eec-204b-4c2f-b7e8-296a70dab67e"


def test_device_code_prompt_forwarded_when_provided(captured) -> None:
    def prompt(verification_url: str, user_code: str, expires_on: datetime) -> None:
        return None

    credential = build_credential(
        AuthMode.DEVICE_CODE, tenant_id="tenant-a", device_code_prompt=prompt
    )
    assert isinstance(credential, _RecordingDeviceCodeCredential)
    assert credential.prompt_callback is prompt


def test_build_auth_context_threads_prompt_to_credential(captured) -> None:
    seen: list[tuple[str, str, datetime]] = []

    def prompt(verification_url: str, user_code: str, expires_on: datetime) -> None:
        seen.append((verification_url, user_code, expires_on))

    ctx = build_auth_context(
        mode=AuthMode.DEVICE_CODE,
        tenant_id="tenant-a",
        device_code_prompt=prompt,
    )
    assert len(captured) == 1
    assert captured[0].prompt_callback is prompt

    # The callback wired into the (mocked) credential is invokable with the
    # azure-identity prompt_callback signature.
    assert ctx.credential is not None
    callback = captured[0].prompt_callback
    assert callable(callback)
    expires = datetime(2026, 8, 29, 12, 0, 0)
    callback("https://microsoft.com/devicelogin", "ABCD-EFGH", expires)
    assert seen == [("https://microsoft.com/devicelogin", "ABCD-EFGH", expires)]


def test_real_azure_device_code_credential_accepts_prompt_callback_none() -> None:
    # Sanity: azure-identity's real DeviceCodeCredential accepts the kwarg we
    # now always pass (prompt_callback=None is its documented default).
    credential = DeviceCodeCredential(
        tenant_id="tenant-a",
        client_id="14d82eec-204b-4c2f-b7e8-296a70dab67e",
        prompt_callback=None,
    )
    assert credential is not None
