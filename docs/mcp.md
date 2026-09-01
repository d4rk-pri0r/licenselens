# MCP server: use LicenseLens from your AI assistant

LicenseLens ships a local [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server so AI assistants — Claude Code, Claude Desktop, Cursor, Copilot, and
others — can run a security posture assessment as a tool call and reason over the
same structured findings the CLI emits.

The server exposes **one tool, `posture.assess`**:

- **Read-only.** It assesses posture; it has no ability to change any tenant
  setting. There are no write verbs anywhere in its interface.
- **Offline demo by default.** Without arguments it assesses a curated sample
  dataset on your machine — no tenant contact, no credentials needed.
- **Live scans are opt-in.** With `live=true` it reads your tenant using
  read-only, environment-based credentials you provide (see below).

The tool returns the full LicenseLens report schema: every finding (`check_id`,
`status`, `severity`, `exposure_class`, evidence), the capabilities the tenant
owns, ranked next moves and recommended next steps, and a capability rollup.

## Install

The server is an optional extra, separate from the core CLI:

```bash
pipx install 'licenselens[mcp]'
# or, from a source checkout:
uv pip install '.[mcp]'
```

You can also run it without installing into your environment:

```bash
uvx --from 'licenselens[mcp]' licenselens mcp
# from a local tree:
uvx --from './.[mcp]' licenselens mcp
```

## Wire it into your assistant

The server speaks JSON-RPC over local stdio — it runs as a child process, makes
no network requests of its own beyond what a live scan you asked for performs,
and never sends data to a cloud service.

### Claude Code

```bash
claude mcp add licenselens -- uvx --from 'licenselens[mcp]' licenselens mcp
```

### Claude Desktop / Cursor (`mcp.json`)

```json
{
  "mcpServers": {
    "licenselens": {
      "command": "uvx",
      "args": ["--from", "licenselens[mcp]", "licenselens", "mcp"]
    }
  }
}
```

If you installed with pipx, the equivalent entry is:

```json
{
  "mcpServers": {
    "licenselens": {
      "command": "licenselens",
      "args": ["mcp"]
    }
  }
}
```

## Live assessments

A live scan uses the same credentials as the CLI. Set the environment variables
below for the assistant process (read-only directory permissions are enough —
see [permissions](permissions.md)):

| Environment variable | Purpose |
|----------------------|---------|
| `AZURE_TENANT_ID` | Directory (tenant) ID |
| `AZURE_CLIENT_ID` | App registration client ID |
| `AZURE_CLIENT_SECRET` | Client secret (app secret) |
| `AZURE_CLIENT_CERTIFICATE_PATH` | Certificate path (secret-free alternative) |

When asked for a live assessment without credentials, the tool replies with a
structured error that tells your assistant exactly how to fix it — run
`licenselens scan --live` in a terminal for interactive sign-in, or set the
environment variables above and retry.

Interactive browser sign-in is deliberately **CLI-only**: the MCP server never
prompts for a device sign-in, because a machine-to-machine tool surface has no
trustworthy way to show you a prompt. Prefer env-based credentials for live
scans over MCP.

## Security notes

- Local stdio only — no TCP listener, no hosted service, no telemetry.
- Read-only by construction: the tool cannot create, modify, or delete anything.
- Findings are advisory and come from the same engine as the CLI report; they
  are not a compliance certification.

## Limitations

- One tool per server (`posture.assess`); remediation planning and Sentinel
  queries are not exposed.
- Email policy configuration cannot be read via Graph and is out of scope for
  the MCP surface.
- Very large tenants may truncate some inventories, exactly like the CLI.
