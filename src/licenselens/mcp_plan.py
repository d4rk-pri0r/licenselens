"""Pure plan-preview layer for the MCP surface (no MCP SDK imports)."""

from __future__ import annotations

import os

from licenselens.engine.plan_preview import build_plan_preview, skus_from_assume
from licenselens.mcp_assess import _error, _validate_packs, _validate_workloads


def run_plan_preview(
    *,
    live: bool = False,
    assume_sku: list[str] | None = None,
    workloads: list[str] | None = None,
    packs: list[str] | None = None,
) -> dict:
    """Return PlanPreview.to_dict(), or an error envelope."""
    if live and os.environ.get("LICENSELENS_MCP_ALLOW_LIVE") != "1":
        return _error(
            "live_disabled",
            "Live plan preview over MCP is disabled by default.",
            "Set LICENSELENS_MCP_ALLOW_LIVE=1, or run `licenselens plan --demo` locally.",
        )
    if live:
        return _error(
            "live_not_supported",
            "Live plan preview over MCP is not enabled in this version.",
            "Run `licenselens plan --live` in a terminal.",
        )
    validated_workloads = _validate_workloads(workloads)
    if isinstance(validated_workloads, dict):
        return validated_workloads
    validated_packs = _validate_packs(packs)
    if isinstance(validated_packs, dict):
        return validated_packs
    from licenselens.models import CheckPack

    pack_enums = None
    if validated_packs is not None:
        pack_enums = [CheckPack(item) for item in validated_packs]
    preview = build_plan_preview(
        skus=skus_from_assume(assume_sku or []),
        workloads=validated_workloads,
        packs=pack_enums,
    )
    return preview.to_dict()
