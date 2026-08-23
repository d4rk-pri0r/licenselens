# Authentication Model Audit — §16 of the product-maturity goal

**Scope.** This document reviews the authentication model of Security License
Lens for MSP unattended use. It documents the permissions the product requests,
why each is needed, whether delegated or application permission is used, the
risk each creates, the current credential mechanisms, how assessment profiles
scope permissions, and the honest gap between the current and aspirational
credential paths.

Every claim is grounded in the actual code and docs. Where a feature is **not**
implemented (e.g., certificate auth), that is stated plainly as a gap. This is
an analysis document only — no code, YAML, or docs were modified.

---

## 1. Permissions the product requests

### 1.1 Microsoft Graph (application permissions)

The authoritative list is `REQUIRED_GRAPH_APP_PERMISSIONS` in
`src/licenselens/auth.py:30-51` — **20 application permissions**, all read-only.
The same constant is the single source of truth for the `setup` scaffold
(`src/licenselens/cli.py:311-330`, `docs/cli.md:18-28`), the `doctor` preflight
(`src/licenselens/doctor.py:355`), and the generated reference
(`src/licenselens/catalog/reference.py:88,144-149`). The per-operation matrix
lives in `src/licenselens/graph_ops_catalog_identity.py` and
`src/licenselens/graph_ops_catalog_endpoint.py`.

| Permission | Why it is needed (which checks/collectors depend on it) |
|------------|----------------------------------------------------------|
| `Organization.Read.All` | Tenant profile + `subscribedSkus` — the entitlement model's foundation (`docs/permissions.md:9`, `docs/methodology/entitlement-model.md:10-12`). |
| `Directory.Read.All` | Directory object lookup for privileged principals, guest users, domains, OAuth grants (`src/licenselens/graph_ops_catalog_identity.py:19,166,201,228`). |
| `Domain.Read.All` | Verified domain password-validity settings (`docs/permissions.md:11`, `graph_ops_catalog_identity.py:224-232`). |
| `User.Read.All` | Guest user inventory (`docs/permissions.md:12`, `graph_ops_catalog_identity.py:197-205`). |
| `RoleManagement.Read.Directory` | Role assignments + PIM eligibility and policy rules (`docs/permissions.md:13`, `graph_ops_catalog_identity.py:17,94-125`). |
| `Policy.Read.All` | Conditional Access, named locations, auth methods, cross-tenant access (`docs/permissions.md:14`, `graph_ops_catalog_identity.py:16,50-89,172-196,207-223`). |
| `Application.Read.All` | App registrations and service principals (`docs/permissions.md:15`, `graph_ops_catalog_identity.py:18,144-161`). |
| `DelegatedPermissionGrant.Read.All` | OAuth2 delegated permission grants (`docs/permissions.md:16`, `graph_ops_catalog_identity.py:162-170`). |
| `AuditLog.Read.All` | Sign-in logs (dormant privileged) (`docs/permissions.md:17`). |
| `SecurityEvents.Read.All` | Secure Score (MDO/MDI/DLP proxy signals) (`docs/permissions.md:18`, `docs/permissions.md:83-86`). |
| `SecurityIncident.Read.All` | Defender XDR incidents (capability operation signal) (`docs/permissions.md:19`, `graph_ops_catalog_endpoint.py:111-119`). |
| `SecurityAlert.Read.All` | Defender XDR alerts_v2 (capability operation signal) (`docs/permissions.md:20`, `graph_ops_catalog_endpoint.py:120-128`). |
| `AccessReview.Read.All` | Access review definitions (`docs/permissions.md:21`). |
| `EntitlementManagement.Read.All` | Entitlement Management access packages (`docs/permissions.md:22`, `graph_ops_catalog_identity.py:126-134`). |
| `IdentityRiskyServicePrincipal.Read.All` | Risky workload-identity (service principal) detection (`docs/permissions.md:23`, `graph_ops_catalog_identity.py:135-143`). |
| `DeviceManagementApps.Read.All` | Intune MAM app-protection policies (`docs/permissions.md:24`, `graph_ops_catalog_endpoint.py:103-110`). |
| `DeviceManagementConfiguration.Read.All` | Intune compliance/configuration/endpoint-security policies (`docs/permissions.md:25`, `graph_ops_catalog_endpoint.py:12,44-102`). |
| `DeviceManagementManagedDevices.Read.All` | Intune managed device inventory (bounded) (`docs/permissions.md:26`, `graph_ops_catalog_endpoint.py:13,68-76`). |
| `DlpPolicy.Read.All` | Purview DLP policies + apps (direct `/security/dataLossPreventionPolicies`) (`docs/permissions.md:27`, `docs/permissions.md:83-86`). |
| `eDiscovery.Read.All` | Premium eDiscovery cases (direct `/security/cases/ediscoveryCases`) (`docs/permissions.md:28`, `docs/permissions.md:88-92`). |

### 1.2 Other resources (separate APIs)

- **Power BI / Fabric admin REST** — `Tenant.Read.All` (application) on
  `https://analysis.windows.net/powerbi/api/.default`, for
  `pbi-premium-capacity-governance` (`src/licenselens/auth.py:28,54`,
  `docs/permissions.md:103-114`).
- **Microsoft Defender for Endpoint** — `Machine.Read.All` (application) on
  `https://api.securitycenter.microsoft.com`, for `mde-onboard-gap` and related
  endpoint probes (`docs/permissions.md:40-48`, `graph_ops_catalog_endpoint.py:129-148`).
- **Microsoft Sentinel / selective Azure** — Azure RBAC (Microsoft Sentinel
  Reader on the workspace; Security Reader on the subscription for Defender for
  Cloud pricing), not a Graph permission (`docs/permissions.md:50-79`,
  `graph_ops_catalog_endpoint.py:149-178`).
- **Exchange Online / Teams / SharePoint / Power Platform** — PowerShell bridge
  using official modules; requires admin roles (Global Reader / Security Reader
  plus workload-specific roles), not Graph permissions
  (`docs/permissions.md:116-138`).

---

## 2. Delegated vs application permission

**Application permission is the primary model.** The 20 Graph permissions are
declared as **application** permissions with admin consent
(`docs/app-registration.md:67-129`, `docs/permissions.md:30`). The `doctor`
preflight compares the app's granted `appRoleAssignments` against
`REQUIRED_GRAPH_APP_PERMISSIONS` (`src/licenselens/doctor.py:355`).

**Delegated permission is used only for interactive device-code and the
Insider Risk surface.** The per-operation matrix declares both application and
delegated scopes (`src/licenselens/graph_ops_catalog_identity.py:22-46`), and
delegated equivalents are always read-only (`docs/permissions.md:32-33`).
Device-code mode **cannot** introspect application roles, so `doctor` reports a
note instead of a permission comparison in that mode
(`src/licenselens/doctor.py:101-106`). The Insider Risk Management surface
(`pur-insider-risk-readiness`) uses the delegated scope
`InsiderRiskPolicy.Read.All` and requires the signed-in user to hold an Insider
Risk Management role group membership; it is **not** part of the pre-verified
application permission list (`docs/permissions.md:94-98`).

**The Graph client enforces read-only at the HTTP layer.** `graph.py` blocks
write methods (POST/PUT/PATCH/DELETE) except a single allowlisted POST
(`/directoryObjects/getByIds`) and blocks beta endpoints unless a profile opts
into preview (`src/licenselens/graph.py:17-22,94-123`). This is a defense-in-depth
guard independent of the granted permissions.

---

## 3. Risk created by each permission

All permissions are read-only, which bounds the blast radius, but several are
**broad tenant-wide reads** that an MSP should treat as sensitive:

- **`Directory.Read.All`** — full directory object read across the tenant. The
  single most sensitive permission; it underpins privileged-principal, guest,
  domain, and OAuth-grant reads (`graph_ops_catalog_identity.py:19,166,201,228`).
- **`User.Read.All`** — all user profiles and sign-in data
  (`docs/permissions.md:12`). Combined with `AuditLog.Read.All`, this is a
  tenant-wide identity read.
- **`AuditLog.Read.All`** — directory and sign-in audit logs; sensitive
  operational data (`docs/permissions.md:17`).
- **`Application.Read.All`** — all app registrations and service principals;
  reveals the tenant's application estate (`docs/permissions.md:15`).
- **`DelegatedPermissionGrant.Read.All`** — all OAuth consent grants; reveals
  which apps hold delegated access (`docs/permissions.md:16`).
- **`Policy.Read.All`** — conditional access, auth methods, cross-tenant access;
  reveals the tenant's security posture directly (`docs/permissions.md:14`).
- **`RoleManagement.Read.Directory`** — role assignments and PIM settings;
  reveals privileged access (`docs/permissions.md:13`).
- **`SecurityEvents.Read.All` / `SecurityIncident.Read.All` /
  `SecurityAlert.Read.All`** — security signals; sensitive operational data
  (`docs/permissions.md:18-20`).
- **`DeviceManagementManagedDevices.Read.All`** — managed device inventory;
  device-level data (`docs/permissions.md:26`).
- **`DlpPolicy.Read.All` / `eDiscovery.Read.All`** — Purview DLP policies and
  eDiscovery cases; sensitive compliance data (`docs/permissions.md:27-28`).

**Risk posture.** Because the product is read-only and ships no telemetry
(`SECURITY.md:27-28`), the primary risk is **data exposure** (a compromised
credential or a leaked report), not **tenant modification**. The broad
tenant-wide read permissions mean a single compromised app credential exposes a
large read surface. The product mitigates this with default redaction
(`docs/limitations.md:43`) and the read-only HTTP guard (`graph.py:94-123`), but
the credential itself remains a high-value target.

---

## 4. Current credential mechanisms

The auth modes are enumerated in `AuthMode` (`src/licenselens/auth.py:17-22`)
and built in `build_credential` (`src/licenselens/auth.py:121-202`):

| Mode | Credential class | Status |
|------|------------------|--------|
| `device_code` | `DeviceCodeCredential` | Implemented. Interactive; falls back to the Microsoft Graph PowerShell public client `14d82eec-204b-4c2f-b7e8-296a70dab67e` when no `--client-id` is given (`auth.py:14,192-200`). |
| `client_secret` | `ClientSecretCredential` | Implemented. App-only; the default live mode for `batch` (`batch.py:101`). |
| `azure_cli` | `AzureCliCredential` | Implemented. Reuses an existing `az login` session (`auth.py:146-147`). |
| `oidc` | `ClientAssertionCredential` | Implemented for `scan`/`doctor` only. Mints an assertion from a GitHub Actions OIDC token (`auth.py:149-168`). **Not available in `batch`** (see §6). |
| `dry_run` | none | Implemented. No live calls (`auth.py:130-131`). |

**Certificate credentials are NOT implemented.** This is stated explicitly in
`SECURITY.md:31` ("certificate credentials are **not** implemented") and
`docs/msp-batch.md:27-28` ("certificate credentials are **not** implemented by
LicenseLens"). The app-registration guide instructs operators to create a
**client secret** (`docs/app-registration.md:133-137`). There is no
`CertificateCredential` import or path in `build_credential`
(`src/licenselens/auth.py:121-202`).

**Workload identity / managed identity are NOT implemented as first-class
modes.** The only workload-identity path is the GitHub Actions OIDC federation
(`auth.py:149-168`), which is a `ClientAssertionCredential` fed by the Actions
runtime. There is no `DefaultAzureCredential`, no `ManagedIdentityCredential`,
and no generic workload-identity federation for Azure-hosted runners or other
CI systems. The `oidc` mode is hard-wired to the GitHub Actions env vars
(`ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN`,
`auth.py:94-118`).

**Secret handling.** Client secrets are preferred via env vars
(`AZURE_CLIENT_SECRET`), also accepted via `--client-secret` (visible in process
lists) and `tenants.yaml` `client_secret` (discouraged, must not be committed)
(`SECURITY.md:39`, `docs/msp-batch.md:121-124`). There is no secret-rotation
mechanism, no per-tenant secret store integration, and no certificate-based
alternative.

---

## 5. Assessment-profile-based least privilege

**The permission catalog is global, not profile-scoped.** The 20 Graph
permissions are a single constant (`src/licenselens/auth.py:30-51`) that the
`doctor` preflight and `setup` scaffold always present in full
(`src/licenselens/doctor.py:355`, `src/licenselens/cli.py:365`). The generated
reference lists all 20 as required (`docs/reference/permissions.md:4-29`).

**However, the CLI can report per-profile permission requirements.** The
`doctor --assessment-profile <id>` flag calls `profile_requirement_report`
(`src/licenselens/cli.py:518-540`), which computes the union of permissions
across the checks and data sources a profile selects
(`src/licenselens/cli_profile_info.py:48-93`). This is a **reporting** feature:
it tells an operator which permissions a given profile needs, but it does not
change what the product requests or enforces. The app registration still needs
the full 20-permission set granted and consented for any profile to run
(`docs/app-registration.md:67-129`).

**Least-privilege gap.** Because the permission list is a single global constant
and the app registration is granted the full set, an MSP cannot run a narrow
`identity`-only profile with a reduced permission set. The product does not
derive a minimal permission set from the selected profile and does not validate
that the granted permissions are a superset of the profile's needs. The
`profile_requirement_report` output is advisory only.

**Additional least-privilege notes.**
- The `_GRAPH_PERMISSION_PURPOSES` map in `cli.py:314-330` documents only **15**
  of the 20 permissions (missing `DeviceManagementApps.Read.All`,
  `DlpPolicy.Read.All`, `eDiscovery.Read.All`, `EntitlementManagement.Read.All`,
  `IdentityRiskyServicePrincipal.Read.All`), so the `setup` scaffold prints those
  five without a purpose line (`docs/cli.md:22`).
- The Insider Risk delegated scope and the PowerShell-bridge admin roles are
  **not** part of the pre-verified application list and are documented as
  additional, per-surface requirements (`docs/permissions.md:94-98,116-138`).

---

## 6. Strongest credential path for MSP unattended use

**Current strongest path: OIDC workload-identity federation (`--auth oidc`).**
This is the only secret-free, unattended path the product supports. It mints a
`ClientAssertionCredential` from a GitHub Actions OIDC token, requires only
`AZURE_TENANT_ID` + `AZURE_CLIENT_ID`, and is enforced by the CI guard
(`src/licenselens/auth.py:149-168`, `docs/msp-batch.md:36-55`,
`src/licenselens/ci_guard.py`). The scheduled `continuous-assessment.yml`
workflow uses it with `id-token: write` granted only there and every action
pinned by SHA (`docs/msp-batch.md:57-75`).

**Critical limitation: OIDC is not available in `batch`.** The `batch` command
has no `--auth` flag (`src/licenselens/cli.py:1314-1347`), and `batch.py`'s
`_AUTH_MODE_ALIASES` (`src/licenselens/batch.py:16-28`) does not include `oidc`.
Batch live mode defaults to `client_secret` (`src/licenselens/batch.py:101`).
So the secret-free unattended path cannot drive a multi-tenant portfolio; an MSP
must either run each tenant via `scan --auth oidc` or fall back to client
secrets in batch.

**Honest gap between current and aspirational.**

| Aspirational capability | Current status |
|-------------------------|----------------|
| **Certificate auth** | **Not implemented.** No `CertificateCredential` path (`auth.py:121-202`); explicitly documented as not implemented (`SECURITY.md:31`, `docs/msp-batch.md:27-28`). |
| **Workload identity (generic)** | **Not implemented.** Only GitHub Actions OIDC federation exists (`auth.py:149-168`); no `DefaultAzureCredential`/`ManagedIdentityCredential`. |
| **Managed identity** | **Not implemented.** No `ManagedIdentityCredential` path. |
| **GDAP / CSP / partner scenarios** | **Not implemented.** No GDAP (Granular Delegated Admin Privileges) or CSP (Cloud Solution Provider) partner-relationship handling. The product reads a single tenant per credential; there is no partner-scoped multi-tenant credential. |
| **Secret rotation** | **Not implemented.** No rotation mechanism; operators must manually create a new secret and update env/YAML (`docs/app-registration.md:133-137`). |
| **Tenant-specific credentials** | **Partially supported.** Per-tenant `client_id`/`client_secret` in `tenants.yaml` (`docs/msp-batch.md:97-119`), but no secrets-manager integration and no certificate per tenant. |
| **Explicit consent boundaries** | **Partially supported.** Admin consent is documented (`docs/app-registration.md:129`), and the read-only HTTP guard bounds behavior (`graph.py:94-123`), but the app registration is granted the full 20-permission set regardless of profile (§5). |

---

## 7. Prioritized minimum-credible-features recommendations

The goal is to prefer secure unattended auth patterns appropriate for MSP use;
client secrets may remain supported but should not be the aspirational
architecture. These are the smallest changes that move the product toward that
goal.

1. **Add `oidc` to `batch` auth** (highest leverage). Add `--auth` to the
   `batch` command and accept `oidc` in `_AUTH_MODE_ALIASES`
   (`src/licenselens/cli.py:1314-1347`, `src/licenselens/batch.py:16-28`). This
   makes the existing secret-free path usable for a multi-tenant portfolio and
   directly reduces client-secret reliance for scheduled scans.

2. **Implement certificate auth as a first-class mode.** Add a
   `CertificateCredential` path in `build_credential`
   (`src/licenselens/auth.py:121-202`) driven by a PEM/cert + private key (or a
   key-vault reference), and update `SECURITY.md:31` and
   `docs/msp-batch.md:27-28` which currently state it is not implemented. This
   is the standard MSP unattended pattern and removes the client-secret
   lifecycle entirely.

3. **Derive a minimal permission set from the selected profile.** Make
   `profile_requirement_report` (`src/licenselens/cli_profile_info.py:48-93`)
   drive the actual permission request/validation rather than being advisory, so
   a narrow profile can run with a reduced app registration. At minimum, add a
   `doctor` check that warns when granted permissions exceed the profile's
   needs. This closes the least-privilege gap in §5.

4. **Add a `doctor`-style preflight for batch credentials.** Before running a
   batch, confirm each tenant's credential resolves (and, for `oidc`, that the
   runtime token is available) so a portfolio run fails fast instead of
   producing per-tenant errors. Pointer: `src/licenselens/batch.py:122-127`.

5. **Document the GDAP/CSP gap explicitly and add a per-tenant credential
   abstraction.** Add a `credential` reference key to `tenants.yaml` that points
   to a named secret (env var or secrets-manager reference) rather than an
   inline value, and document that GDAP/CSP partner-scoped auth is not yet
   supported. This is the honest minimum for MSP multi-tenant credential
   management without building a platform.

These five items keep client secrets supported (for compatibility) while making
the secure unattended path (OIDC, then certificate) the credible default for MSP
use.
