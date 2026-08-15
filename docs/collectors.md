# Collectors and backends

Collectors are **read-only** data sources. Each check names a collector, and
backend preferences decide the order in which the tool tries them. No collector
calls a write API.

## `--backend` tokens

Operators pass preferred collection backends with repeatable `--backend` on
`scan`, `demo`, `quickstart`, and `batch` (and as batch defaults). Valid tokens:

| Backend | What it reads | Typical use |
|---------|---------------|-------------|
| `graph` | Microsoft Graph (app-only, device code, or Azure CLI) | SKUs, Conditional Access, roles, PIM, sign-ins, guests, apps, access reviews, auth methods, domains, Intune |
| `arm` | Azure Resource Manager (`management.azure.com`) | Sentinel alert rules, UEBA settings, workspace discovery |
| `exchange_online` | Exchange Online via the PowerShell bridge | MDO / mail policy config that has no Graph read API |
| `defender` | Defender for Endpoint API (`api.securitycenter.microsoft.com`) | Machine inventory for onboard gaps |
| `secure_score` | Microsoft Secure Score (Graph) | Labeled proxy signals (for example MDI / Purview / opt-in email) |
| `manual` | Human-provided evidence | Surfaces not readable programmatically |

See [CLI reference](cli.md) for how `--backend` interacts with assessment
profiles and `--allow-email-proxy`.

## Collector families

Internal collectors are finer-grained than the six operator tokens. Families
include Graph directory and security reads, MDE machine inventory, ARM/Sentinel,
public DNS for mail authentication, Secure Score proxies, and allowlisted
PowerShell adapters. Contributors should treat
`src/licenselens/engine/_registry_source_meta.py` as the authoritative map of
source keys → backend, permissions, and labels — not this operator page.

## The PowerShell bridge

Some policy surfaces (notably email / MDO configuration) have **no Graph read
API**. When those collectors run, the tool shells out to an allowlisted,
read-only PowerShell module:

- Module path: `powershell/LicenseLens.Collectors`
- Single exported entrypoint: `Invoke-LicenseLensCollectorAdapter`
- Adapters cover Exchange Online and related allowlisted workloads (SharePoint,
  Teams, Power Platform, Purview) as registered in the module

The bridge is deliberately narrow: adapters are allowlisted, return structured
JSON, and never call write cmdlets. See [Windows](windows.md) for prerequisites
and how to import the module.

## Proxy policy

A backend is a **proxy** when it infers a control from a neighboring signal
instead of reading the control directly (Secure Score for MDI/Purview, for
example). Proxy results are labeled, subject to the quality policy, and never
presented as "fully working". `--allow-email-proxy` opts in explicitly;
profile `backend_preferences.allow_proxy` and `allow_manual` gate the rest.

## Extending

- Add collectors named in check `collector` fields under
  `src/licenselens/collectors/`.
- Register source metadata in `src/licenselens/engine/_registry_source_meta.py`.
- Register pure evaluators in `src/licenselens/engine/evaluate.py`.
- Keep every collector read-only and pagination/retry-safe.

See [Architecture](architecture.md) for the pipeline and
[Permissions](permissions.md) for the Graph scopes collectors need.
