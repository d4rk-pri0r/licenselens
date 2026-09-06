"""LicenseLens MCP stdio server (optional extra: licenselens[mcp])."""

from __future__ import annotations

try:  # MCP SDK v2 (mcp>=2.0)
    from mcp.server import MCPServer as _Server
except ImportError:  # MCP SDK v1 (mcp 1.x)
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

from licenselens.mcp_assess import run_assessment
from licenselens.mcp_plan import run_plan_preview

SERVER_TOOL_NAME = "posture.assess"
PLAN_TOOL_NAME = "plan.preview"

_TOOL_DESCRIPTION = (
    "Assess a Microsoft 365 tenant's security posture against the licenses it "
    "already owns. Read-only. Returns the LicenseLens report schema: findings "
    "(check_id, status, severity, exposure_class, evidence), owned capabilities, "
    "ranked next moves and recommended next steps, and a capability rollup. "
    "Defaults to the offline demo (curated sample data, no tenant contact). "
    "Set live=true for a real tenant using read-only, env-based credentials; live "
    "additionally requires LICENSELENS_MCP_ALLOW_LIVE=1 in the server's environment "
    "(live over MCP is disabled by default)."
)


def build_server() -> _Server:
    server = _Server("security-license-lens")

    @server.tool(name=SERVER_TOOL_NAME, description=_TOOL_DESCRIPTION)
    def posture_assess(
        live: bool = False,
        auth: str | None = None,
        tenant_id: str | None = None,
        workloads: list[str] | None = None,
        packs: list[str] | None = None,
    ) -> dict:
        return run_assessment(
            live=live, auth=auth, tenant_id=tenant_id, workloads=workloads, packs=packs
        )

    @server.tool(
        name=PLAN_TOOL_NAME,
        description=(
            "Preview what a LicenseLens scan would collect and evaluate. "
            "Read-only and offline by default (demo SKUs). Returns owned "
            "capabilities, checks that will run, collector DAG, and Graph "
            "permissions. Live preview over MCP is disabled unless "
            "LICENSELENS_MCP_ALLOW_LIVE=1."
        ),
    )
    def plan_preview(
        live: bool = False,
        assume_sku: list[str] | None = None,
        workloads: list[str] | None = None,
        packs: list[str] | None = None,
    ) -> dict:
        return run_plan_preview(live=live, assume_sku=assume_sku, workloads=workloads, packs=packs)

    return server


def main() -> None:
    build_server().run(transport="stdio")


__all__ = ["PLAN_TOOL_NAME", "SERVER_TOOL_NAME", "build_server", "main"]
