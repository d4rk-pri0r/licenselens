# Collectors and backends

Collectors are **read-only** data sources. Each check names a collector, and
`backend_preferences` decides the order in which the tool tries them. No
collector calls a write API.

## Backends

| Backend | What it reads | Typical use |
|---------|---------------|-------------|
| `graph` | Microsoft Graph (app-only or device code) | SKUs, Conditional Access, roles, PIM, sign-ins, guests, apps, access reviews, auth methods, domains |
| `arm` | Azure Resource Manager (`management.azure.com`) | Sentinel alert rules, UEBA settings, workspace discovery |
| `defender` | Defender for Endpoint API (`api.securitycenter.microsoft.com`) | Machine inventory for onboard gaps |
| `secure_score` | Microsoft Secure Score (Graph) | Labeled proxy signals for MDI / Purview |
| `exchange_online` | Exchange Online PowerShell (bridge) | MDO policy config that has no Graph API |
| `manual` | Human-provided evidence | Anything not readable programmatically |

## The PowerShell bridge

Email (MDO) policy configuration has **no Graph read API**. When you opt in, the
tool shells out to an allowlisted, read-only PowerShell module —
`powershell/LicenseLens.Collectors` — whose adapters run exactly one exported
function, `Invoke-LicenseLensCollectorAdapter`, over Exchange Online, SharePoint,
Teams, Power Platform, and Purview.

The bridge is deliberately narrow: adapters are allowlisted, return structured
JSON, and never call write cmdlets. See [Windows](windows.md) for prerequisites.

## Proxy policy

A backend is a **proxy** when it infers a control from a neighboring signal
instead of reading the control directly (Secure Score for MDI/Purview, for
example). Proxy results are labeled, subject to the quality policy, and never
presented as "fully working". `--allow-email-proxy` opts in explicitly;
`backend_preferences.allow_proxy` and `allow_manual` gate the rest.

## Extending

- Add collectors named in check `collector` fields under
  `src/licenselens/collectors/`.
- Register pure evaluators in `src/licenselens/engine/evaluate.py`.
- Keep every collector read-only and pagination/retry-safe.

See [Architecture](architecture.md) for the pipeline and
[Permissions](permissions.md) for the exact Graph scopes each collector needs.
