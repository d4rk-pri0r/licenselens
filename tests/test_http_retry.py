"""WS0-A: shared HTTP retry policy (Retry-After, capped exponential backoff)."""

from __future__ import annotations

import httpx

from licenselens.http_retry import retry_delay, should_retry


def _response(status: int = 429, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, headers=headers or {})


def test_retry_delay_prefers_retry_after_header() -> None:
    assert retry_delay(_response(headers={"Retry-After": "7"}), attempt=0) == 7.0
    assert retry_delay(_response(headers={"Retry-After": "0"}), attempt=5) == 0.0


def test_retry_delay_backoff_caps_at_eight() -> None:
    assert retry_delay(_response(), attempt=0) == 1.0
    assert retry_delay(_response(), attempt=3) == 8.0
    assert retry_delay(_response(), attempt=9) == 8.0
    # Non-digit Retry-After (HTTP-date form) falls back to backoff.
    assert retry_delay(_response(headers={"Retry-After": "Wed, 21 Oct 2026"}), attempt=1) == 2.0


def test_should_retry_429_and_5xx_only() -> None:
    assert should_retry(429) is True
    assert should_retry(500) is True
    assert should_retry(503) is True
    assert should_retry(400) is False
    assert should_retry(401) is False
    assert should_retry(403) is False
    assert should_retry(404) is False
    assert should_retry(200) is False
