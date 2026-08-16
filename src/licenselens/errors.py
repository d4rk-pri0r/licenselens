"""Typed errors for auth and Microsoft Graph access."""

from __future__ import annotations


class LicenseLensError(Exception):
    """Base error for Security License Lens."""


class AuthError(LicenseLensError):
    """Authentication or credential configuration failed."""


class AuthConfigError(AuthError):
    """Missing/incomplete auth configuration (tenant id, client id, secret).

    Distinct from a genuine sign-in failure: nothing was attempted against a
    live service, so guidance about consent/conditional-access blocking does
    not apply. Subclasses AuthError so existing handlers keep working.
    """


class GraphError(LicenseLensError):
    """Microsoft Graph request failed."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.request_id = request_id
