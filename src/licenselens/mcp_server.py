"""LicenseLens MCP stdio server (optional extra: licenselens[mcp])."""

from __future__ import annotations

try:  # MCP SDK v2 (mcp>=2.0)
    from mcp.server import MCPServer as _Server
except ImportError:  # MCP SDK v1 (mcp 1.x)
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

from licenselens.mcp_assess import run_assessment

SERVER_TOOL_NAME = "posture.assess"

_TOOL_DESCRIPTION = (
    "Assess a Microsoft 365 tenant's security posture against the licenses it "
    "already owns. Read-only. Returns the LicenseLens report schema: findings "
    "(check_id, status, severity, exposure_class, evidence), owned capabilities, "
    "ranked next moves and recommended next steps, and a capability rollup. "
    "Defaults to the offline demo (curated sample data, no tenant contact). "
    "Set live=true for a real tenant using read-only, env-based credentials."
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

    return server


def main() -> None:
    build_server().run(transport="stdio")


__all__ = ["SERVER_TOOL_NAME", "build_server", "main"]
