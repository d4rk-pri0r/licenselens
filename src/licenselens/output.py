"""Report output path helpers (tenant slug + timestamp layout)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path


def slugify(value: str) -> str:
    text = value.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "tenant"


def build_report_dir(
    output_dir: Path,
    *,
    tenant_slug: str | None = None,
    tenant_id: str | None = None,
    tenant_display_name: str | None = None,
    timestamp: str | None = None,
    flat: bool = False,
) -> Path:
    """Return directory for report artifacts.

    Default layout:
      {output_dir}/{slug}/{timestamp}/
    Flat layout (legacy):
      {output_dir}/
    """
    if flat:
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    slug = tenant_slug
    if not slug:
        if tenant_display_name:
            slug = slugify(tenant_display_name)
        elif tenant_id:
            slug = slugify(tenant_id[:8])
        else:
            slug = "local"
    ts = timestamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / slug / ts
    path.mkdir(parents=True, exist_ok=True)
    return path
