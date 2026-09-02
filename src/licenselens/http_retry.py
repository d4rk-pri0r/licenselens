"""Shared HTTP retry policy for Microsoft API clients (Graph/ARM/MDE).

ARM returns 429 with a ``Retry-After`` header when throttling a tenant:
https://learn.microsoft.com/azure/azure-resource-manager/management/request-limits-and-throttling
MDE rate limits are stated per operation (e.g. List machines):
https://learn.microsoft.com/defender-endpoint/api/get-machines
"""

from __future__ import annotations

import httpx


def should_retry(status_code: int) -> bool:
    """True for transient statuses only: 429 and any 5xx."""
    return status_code == 429 or status_code >= 500


def retry_delay(response: httpx.Response, attempt: int) -> float:
    """Delay seconds: a digits-only Retry-After wins, else exponential capped at 8."""
    retry_after = response.headers.get("Retry-After")
    if retry_after and retry_after.isdigit():
        return float(retry_after)
    return float(min(2**attempt, 8))
