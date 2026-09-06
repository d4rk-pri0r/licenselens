"""Hash device identifiers for evidence (never store raw hostnames)."""

from __future__ import annotations

import hashlib

__all__ = ["hash_device_label"]


def hash_device_label(value: object) -> str:
    """Return the first 12 hex chars of sha256(value), or empty if blank."""
    text = str(value or "").strip()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
