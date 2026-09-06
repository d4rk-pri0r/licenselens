# LicenseLens Check Catalog — Semantic Correctness Audit

**Scope:** All 166 checks in the LicenseLens catalog (`docs/reference/reference.json` → `checks`).
**Purpose:** For every check, record what it claims, what evidence actually supports that claim, how the
evidence is assessed, what entitlement gates it, its edge cases, its false-positive/false-negative risk,
its confidence, and what must change to make it defensible.
**Method:** Each entry is grounded in the actual evaluator source under `src/licenselens/evaluators/**`
(following `check_id → collector → evaluator`), the check YAML under `checks/<workload>/<id>.yaml`, and the
quality policy in `src/licenselens/engine/quality.py` plus the model validator in `src/licenselens/models.py`.
No evaluator, check YAML, catalog, or test file was modified to produce this document.
**Validation Status:** Every check is recorded as **not-yet-reviewed**. No check has been externally
validated by a practitioner; the "reviewed" state is reserved for a future human validation pass.

---

## Assessment-Type Taxonomy

Each check is classified by how its evidence is obtained and whether that evidence can support the
conclusion it draws. The classification is derived from the evaluator's actual behavior, not from the
`support_state` field alone (a check may be labeled `direct` in the reference yet still be a proxy or
manual in practice when its evaluator falls back to Secure Score or returns SKIPPED).

| Type | Meaning |
|------|---------|
| **DIRECT** | The evaluator reads an authoritative Microsoft API/configuration surface that directly represents the setting or state being asserted. The evidence supports the conclusion. |
| **PROXY** | The evaluator infers the conclusion from a surrogate signal (e.g., Microsoft Secure Score control completion) rather than the authoritative surface. The evidence is correlated, not definitive. |
| **MANUAL** | The evaluator cannot prove the claim from any API and returns SKIPPED, requiring a human to verify in the portal. |
| **UNKNOWN / INSUFFICIENT** | The evaluator returns PARTIAL/ERROR because the required evidence is missing, unreadable, or ambiguous; the conclusion cannot be reached. |
| **UNSUPPORTED** | The capability is intentionally out of scope and the evaluator returns SKIPPED with an explicit "unsupported" note. |

**Fail-closed policy:** The engine's `apply_required_evidence_policy` (in `limitations_policy.py`) demotes any
finding whose limitations contain an outcome-blocking marker (e.g., "could not be read", "proxy", "was
truncated", "manual verification required") away from `OK`/`HIGH` confidence. The model validator
`reject_indirect_high_confidence_ok` in `models.py` rejects any PROXY/MANUAL/UNSUPPORTED evaluation that
claims `OK` with `HIGH` confidence. Consequently, a check that cannot read its required surface can never
report a clean pass — it degrades to PARTIAL/UNKNOWN. This is reflected in the per-check entries below.

---

## Summary Tables

### Counts by Workload

| Workload | Checks |
|----------|--------|
| identity | 52 |
| defender | 27 |
| collaboration | 24 |
| endpoint | 13 |
| purview | 13 |
| exchange | 12 |
| power-bi | 10 |
| power-platform | 8 |
| sentinel | 5 |
| azure | 2 |
| **Total** | **166** |

### Counts by Assessment Type (as classified in this audit)

| Assessment Type | Checks |
|-----------------|--------|
| DIRECT | 158 |
| PROXY | 1 |
| MANUAL | 6 |
| MANUAL / UNSUPPORTED | 1 |
| **Total** | **166** |

> The single PROXY check is `mdi-sensors-missing` (Secure Score proxy for MDI sensor health). The six MANUAL
> checks are `id-guest-invite-domains`, `id-idprotect-notify-high-risk`, `id-logs-to-soc`,
> `mdo-alert-policies-enabled`, `mdo-audit-retention`, and `pur-communication-compliance-readiness`. The one
> MANUAL/UNSUPPORTED check is `az-cspm-out-of-scope` (intentionally out of scope).
>
> **Dynamic degradation note:** Several checks classified as DIRECT can degrade to **UNKNOWN / INSUFFICIENT**
> at runtime when their required evidence is missing, unreadable, or ambiguous. Under the engine's fail-closed
> policy (`apply_required_evidence_policy`), such a check returns PARTIAL/ERROR and can never report a clean
> pass. This is captured per-check in the **Known Edge Cases** and **Confidence** fields. Notable examples:
> `id-pim-activation-controls`, `id-number-matching`, `pur-ediscovery-readiness`,
> `pbi-premium-capacity-governance`, and the `sen-*` workspace-required checks. Additionally, the two
> `direct_with_proxy_fallback` checks (`mdo-p2-policies-default`, `pur-dlp-not-enforced`) and the two
> denominator/coverage checks (`mde-onboard-gap`, `endpoint-enrollment-coverage`) are classified DIRECT when
> their authoritative surface is readable, but degrade to PROXY (Secure Score or licensing-leverage signal)
> when it is not — this is noted in each entry's Assessment Type and Confidence.

### Checks with False-Positive Risk > None

These checks can report a gap when none exists (i.e., they may flag a real configuration as a problem).

| Check | Risk | Why |
|-------|------|-----|
| `id-ga-count-bounds` | MEDIUM | Hard-coded 2–8 Global Admin bounds may not match an org's actual break-glass design. |
| `id-ga-finer-roles` | MEDIUM | Heuristic "GA count > 8 and no finer roles" may misclassify a legitimately GA-heavy small org. |
| `id-app-ownerless-or-stale` | MEDIUM | "Stale" heuristic (created >365d and no creds) can flag long-lived but active apps. |
| `id-dormant-privileged` | MEDIUM | Sign-in sampling truncation can mislabel an active-but-unsampled principal as dormant. |
| `id-ca-mfa-registration-managed` | MEDIUM | Requires a managed-device policy specifically targeting security-info registration; a tenant using a broader managed-device policy may be flagged. |
| `id-ca-phishing-resistant-all` | MEDIUM | Requires phishing-resistant MFA for *all* users; orgs that only require it for privileged roles are flagged. |
| `id-ca-managed-devices` | MEDIUM | Requires an all-user managed-device policy; orgs that scope it to specific apps may be flagged. |
| `id-ai-agents-risky-block` | MEDIUM | Keyword heuristic may match an unrelated policy. |
| `mde-onboard-gap` | MEDIUM | License-vs-device comparison is a licensing-leverage signal, not coverage; can overstate a gap when licenses exceed devices for legitimate reasons. |
| `endpoint-enrollment-coverage` | MEDIUM | Same licensing-leverage caveat as `mde-onboard-gap`. |
| `mdo-safe-links-click-through` | MEDIUM | Flags any policy with click-through enabled; a single per-user policy may be intentional. |
| `mdo-quarantine-policy` | MEDIUM | Flags end-user full-access quarantine permissions; some orgs intentionally allow release. |
| `teams-guest-access-restricted` | MEDIUM | Flags guest access as "wide open" when calling/chat are on but domain allowlist is managed in Entra (not Teams). |
| `teams-recording-disabled` | MEDIUM | Flags recording enabled as a gap; recording may be a legitimate compliance requirement. |
| `teams-broadcast-not-always-record` | MEDIUM | Flags "always record" as a gap; some orgs require it for compliance. |
| `pur-dlp-locations-complete` | MEDIUM | Derives coverage from workload flags, not full location enumeration; may under-count. |
| `sen-analytics-rule-coverage` | MEDIUM | Rule-count baseline (≥10 rules, ≥3 tactics) is arbitrary; a lean-but-effective workspace is flagged. |
| `sen-data-connectors` | MEDIUM | Connector-count baseline (≥3 total, ≥2 key) is arbitrary. |

### Checks with False-Negative Risk > None

These checks can miss a real gap (i.e., report OK when a problem exists).

| Check | Risk | Why |
|-------|------|-----|
| `id-ca-mfa-all-users` | MEDIUM | Only checks for an all-user MFA policy; a policy covering all users via a dynamic group may be missed if `includes_all_users` is strict. |
| `id-ca-legacy-auth-block` | MEDIUM | Only recognizes policies whose predicate matches `is_legacy_auth_block`; a differently-shaped block may be missed. |
| `id-ca-priv-gaps` | MEDIUM | Requires MFA for all users OR privileged roles; a policy covering only a subset of privileged roles may be missed. |
| `id-break-glass-exclusion` | MEDIUM | Requires break-glass principals to be declared in config; if not declared, returns PARTIAL/GAP even when a valid break-glass account exists. |
| `id-pim-unused` | MEDIUM | If no privileged assignments/eligibilities are found, returns PARTIAL (inconclusive), not a definitive gap. |
| `id-dormant-privileged` | MEDIUM | Sign-in sampling truncation can miss a genuinely dormant principal (false negative on the OK side). |
| `id-identity-protection-workload` | MEDIUM | Unclassified risk states return PARTIAL; a genuinely risky SP with an unknown state is not flagged as a gap. |
| `id-app-risky-delegated-consent` | MEDIUM | Only flags `AllPrincipals` consent type; per-user risky grants are not flagged. |
| `id-app-password-addition-blocked` | MEDIUM | Only recognizes block policies whose name contains "app password"; a block with a different name is missed. |
| `id-ai-agents-risky-block` | HIGH | A real agent-risk block with a non-matching name is missed. |
| `mde-sensor-health` | MEDIUM | Truncated inventory can understate unhealthy sensors. |
| `mdi-sensors-missing` | HIGH | Secure Score proxy cannot detect a missing/unhealthy sensor directly; a real sensor gap may be missed. |
| `mdo-p2-policies-default` | HIGH | Secure Score proxy (when direct EXO read unavailable) cannot confirm actual Safe Links/Attachments enforcement. |
| `pur-dlp-not-enforced` | HIGH | Secure Score proxy cannot confirm DLP enforce mode. |
| `pur-dlp-locations-complete` | MEDIUM | Workload-flag derivation may miss a location not flagged. |
| `pur-ediscovery-readiness` | MEDIUM | Empty case list is ambiguous (no cases vs. no permission); a real readiness gap may be missed. |
| `sen-ueba-not-enabled` | MEDIUM | Settings read failure is distinguished from explicitly-off, but a partial read may miss the real state. |
| `exo-dkim-enabled` | MEDIUM | Only checks returned DKIM configs; a domain with no DKIM config returned is not flagged. |
| `exo-spf-published` / `exo-dmarc-*` | MEDIUM | Only checks tenant-owned custom domains; a domain not in the DNS inventory is not assessed. |
| `teams-external-access-per-domain` | MEDIUM | If federation is disabled, returns OK without checking domain allowlist (correct), but a partially-open federation may be missed. |

### Checks Requiring Changes (non-empty Required Changes)

See the [Prioritized Required-Changes Backlog](#prioritized-required-changes-backlog) at the end of this
document for the full ordered list. In summary, **15 checks** carry a non-empty Required Changes field.

---

## Per-Check Audit

Each subsection lists the 12 audit fields. Priority checks (identity/CA/PIM/MFA, Defender endpoint/MDE,
proxy/manual/dynamic evidence, and denominator/coverage checks) receive full-depth entries with explicit
edge cases and FP/FN analysis. Remaining direct low-risk checks receive compact one-line-per-field entries.

### Workload: identity (52 checks)

#### `id-ca-mfa-all-users` — MFA for all users via Conditional Access

- **Current Claim:** Every user signs in with MFA enforced by Conditional Access.
- **Actual Evidence Available:** `ca_policies` (Graph `conditionalAccess`). The evaluator
  `evaluate_ca_mfa_all_users` calls `ca_coverage_result` with predicate `ca.requires_mfa` and
  `require_all_users=True`, so only an *enforced, all-user* MFA policy clears the check. Report-only or
  non-all-user policies yield PARTIAL; no matching policy yields GAP. Evidence now includes the
  effective-scope keys `universal_policies`, `scoped_policies`, `scope_gaps_best`, and
  `security_defaults_enabled`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` (Entra ID P1/P2).
- **Known Edge Cases:** (1) A policy that covers all users via a dynamic group rather than the literal
  "All users" assignment may not satisfy `includes_all_users`. (2) Break-glass exclusions without a
  documented rationale demote OK→PARTIAL. (3) Security Defaults providing baseline MFA yields PARTIAL
  here (baseline present, the licensed CA capability unused); the activation gap itself is
  `id-security-defaults-on`.
- Scoped, risk-conditioned, location-bypassed, or platform/client-limited policies are reported as
  PARTIAL, not OK.
- **False Positive Risk:** HIGH before 0.5 (scoped/risk-conditioned policies passed as OK); MEDIUM after
  (joint coverage across narrower policies is not computed).
- **False Negative Risk:** MEDIUM — a policy covering all users via a non-standard assignment shape may be
  missed, under-reporting coverage.
- **Confidence:** HIGH (direct read; demoted to MEDIUM if exclusions are unjustified).
- **Required Changes:** Scope semantics implemented in 0.5 (PolicyScope + purpose_scope + Security
  Defaults ladder). Remaining: joint coverage across narrower policies is not computed.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa`
- **Validation Status:** not-yet-reviewed

#### `id-ca-legacy-auth-block` — Legacy authentication blocked

- **Current Claim:** Enforced Conditional Access blocks legacy authentication clients.
- **Actual Evidence Available:** `ca_policies`; predicate `ca.is_legacy_auth_block` with `require_all_users=True`.
  Evidence now includes the effective-scope keys `universal_policies`, `scoped_policies`, `scope_gaps_best`,
  and `security_defaults_enabled`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access`.
- **Known Edge Cases:** Security Defaults also blocks legacy auth; this check reports PARTIAL (not GAP)
  when Security Defaults is on, because SD blocks legacy authentication at the baseline;
  `id-ca-priv-gaps` consumes the same signal for its exposure flag. A legacy-auth block scoped to a
  subset of users is treated as a gap.
- Scoped, risk-conditioned, location-bypassed, or platform/client-limited policies are reported as
  PARTIAL, not OK.
- **False Positive Risk:** HIGH before 0.5 (scoped/risk-conditioned policies passed as OK); MEDIUM after
  (joint coverage across narrower policies is not computed).
- **False Negative Risk:** MEDIUM — a block policy with an unusual grant-control shape may not match the predicate.
- **Confidence:** HIGH.
- **Required Changes:** Scope semantics implemented in 0.5 (PolicyScope + purpose_scope + Security
  Defaults ladder). Remaining: joint coverage across narrower policies is not computed.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/block-legacy-authentication`
- **Validation Status:** not-yet-reviewed

#### `id-ca-phishing-resistant-all` — Phishing-resistant MFA for all users

- **Current Claim:** Every user signs in with phishing-resistant MFA (FIDO2/CBA) enforced by CA.
- **Actual Evidence Available:** `ca_policies`; predicate `ca.requires_phishing_resistant`, all-user
  required. Evidence now includes the effective-scope keys `universal_policies`, `scoped_policies`,
  `scope_gaps_best`, and `security_defaults_enabled`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + phishing-resistant method availability (FIDO2/CBA).
- **Known Edge Cases:** (1) Orgs that require phishing-resistant MFA only for privileged roles are flagged
  as a gap here (that is `id-ca-phishing-resistant-privileged`). (2) A policy requiring phishing-resistant
  MFA for all users but with an unjustified break-glass exclusion demotes to PARTIAL.
- Scoped, risk-conditioned, location-bypassed, or platform/client-limited policies are reported as
  PARTIAL, not OK.
- **False Positive Risk:** HIGH before 0.5 (scoped/risk-conditioned policies passed as OK); MEDIUM after
  (joint coverage across narrower policies is not computed).
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** Scope semantics implemented in 0.5 (PolicyScope + purpose_scope + Security
  Defaults ladder). Remaining: joint coverage across narrower policies is not computed.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa`
- **Validation Status:** not-yet-reviewed

#### `id-ca-phishing-resistant-privileged` — Phishing-resistant MFA for privileged roles

- **Current Claim:** Highly privileged roles (or all users) require phishing-resistant MFA.
- **Actual Evidence Available:** `ca_policies`; `role_targeted_result` with `HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS`.
  Evidence now includes the effective-scope keys `universal_policies`, `scoped_policies`, `scope_gaps_best`,
  and `security_defaults_enabled`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + PIM/privileged-role licensing.
- **Known Edge Cases:** A policy that covers all users satisfies this check (via `includes_all_users`).
  Role targeting relies on the privileged-role template ID set being current.
- Scoped, risk-conditioned, location-bypassed, or platform/client-limited policies are reported as
  PARTIAL, not OK.
- **False Positive Risk:** HIGH before 0.5 (scoped/risk-conditioned policies passed as OK); MEDIUM after
  (joint coverage across narrower policies is not computed).
- **False Negative Risk:** MEDIUM — if the privileged-role template ID set is stale, a policy targeting a
  newly-added privileged role may be missed.
- **Confidence:** HIGH.
- **Required Changes:** Scope semantics implemented in 0.5 (PolicyScope + purpose_scope + Security
  Defaults ladder). Remaining: joint coverage across narrower policies is not computed.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa`
- **Validation Status:** not-yet-reviewed

#### `id-ca-managed-devices` — Managed device required

- **Current Claim:** Enforced Conditional Access requires a managed device for access.
- **Actual Evidence Available:** `ca_policies`; predicate `ca.requires_managed_device`, all-user required.
  Evidence now includes the effective-scope keys `universal_policies`, `scoped_policies`, `scope_gaps_best`,
  and `security_defaults_enabled`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + Intune (managed-device compliance).
- **Known Edge Cases:** A managed-device policy scoped to specific apps (not all users) is treated as a gap.
- Scoped, risk-conditioned, location-bypassed, or platform/client-limited policies are reported as
  PARTIAL, not OK.
- **False Positive Risk:** HIGH before 0.5 (scoped/risk-conditioned policies passed as OK); MEDIUM after
  (joint coverage across narrower policies is not computed).
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** Scope semantics implemented in 0.5 (PolicyScope + purpose_scope + Security
  Defaults ladder). Remaining: joint coverage across narrower policies is not computed.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-azure-management`
- **Validation Status:** not-yet-reviewed

#### `id-ca-mfa-registration-managed` — Managed device for MFA registration

- **Current Claim:** Users can only register security info (MFA methods) from managed devices.
- **Actual Evidence Available:** `ca_policies`; predicate requires a policy that both targets
  `registerSecurityInfo` and requires a managed device. Evidence now includes the effective-scope keys
  `universal_policies`, `scoped_policies`, `scope_gaps_best`, and `security_defaults_enabled`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + Intune.
- **Known Edge Cases:** A tenant that enforces managed devices broadly (but not specifically on the
  security-info registration app) is flagged as a gap even though the practical effect is similar.
- Scoped, risk-conditioned, location-bypassed, or platform/client-limited policies are reported as
  PARTIAL, not OK.
- **False Positive Risk:** HIGH before 0.5 (scoped/risk-conditioned policies passed as OK); MEDIUM after
  (joint coverage across narrower policies is not computed).
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** Scope semantics implemented in 0.5 (PolicyScope + purpose_scope + Security
  Defaults ladder). Remaining: joint coverage across narrower policies is not computed.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-registration`
- **Validation Status:** not-yet-reviewed

#### `id-ca-device-code-block` — Device code flow blocked

- **Current Claim:** The device-code authentication flow is blocked by Conditional Access.
- **Actual Evidence Available:** `ca_policies`; predicate `ca.is_device_code_block`. Evidence now includes
  the effective-scope keys `universal_policies`, `scoped_policies`, `scope_gaps_best`, and
  `security_defaults_enabled`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access`.
- **Known Edge Cases:** Device-code flow is a phishing vector; a block policy with an unusual grant-control
  shape may not match the predicate.
- Scoped, risk-conditioned, location-bypassed, or platform/client-limited policies are reported as
  PARTIAL, not OK.
- **False Positive Risk:** HIGH before 0.5 (scoped/risk-conditioned policies passed as OK); MEDIUM after
  (joint coverage across narrower policies is not computed).
- **False Negative Risk:** MEDIUM.
- **Confidence:** HIGH.
- **Required Changes:** Scope semantics implemented in 0.5 (PolicyScope + purpose_scope + Security
  Defaults ladder). Remaining: joint coverage across narrower policies is not computed.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/block-device-code-flow`
- **Validation Status:** not-yet-reviewed

#### `id-ca-high-risk-signins` — High-risk sign-ins blocked

- **Current Claim:** Enforced Conditional Access blocks sign-ins Microsoft marks as high risk.
- **Actual Evidence Available:** `ca_policies`; predicate `ca.blocks_high_sign_in_risk`, all-user required.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + Identity Protection (risk signals).
- **Known Edge Cases:** Requires an all-user policy; a risk policy scoped to a subset is treated as a gap.
- Risk conditioning is this check's purpose, so purpose_scope clears risk_conditioned; every other scope
  dimension still counts.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-risk`
- **Validation Status:** not-yet-reviewed

#### `id-ca-high-risk-users` — High-risk users blocked

- **Current Claim:** Enforced Conditional Access blocks users Microsoft marks as high risk.
- **Actual Evidence Available:** `ca_policies`; predicate `ca.blocks_high_user_risk`, all-user required.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + Identity Protection.
- **Known Edge Cases:** Same all-user requirement as `id-ca-high-risk-signins`.
- Risk conditioning is this check's purpose, so purpose_scope clears risk_conditioned; every other scope
  dimension still counts.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-risk`
- **Validation Status:** not-yet-reviewed

#### `id-ca-priv-gaps` — Privileged sign-ins strongly gated

- **Current Claim:** Privileged accounts cannot sign in without MFA, and legacy auth is blocked.
- **Actual Evidence Available:** `ca_policies`, `role_assignments`, `security_defaults_policy`. The
  evaluator `evaluate_ca_priv_gaps` computes MFA coverage for all users or privileged roles, legacy-auth
  blocking, and an `ExposureClass.EXPOSED` flag when privileged principals exist with no enforced MFA or
  legacy auth is broadly allowed. MFA and legacy coverage now require a universal (or role-targeted,
  all-cloud-app) policy, not merely a matching predicate; `security_defaults_policy` is consulted for
  the exposure flag.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + privileged-role licensing.
- **Known Edge Cases:** (1) Security Defaults, when enabled, clears the legacy-auth exposure flag.
  (2) Unjustified break-glass exclusions demote effective MFA/legacy coverage. (3) Report-only MFA does not
  clear the exposure flag.
- Scoped, risk-conditioned, location-bypassed, or platform/client-limited policies are reported as
  PARTIAL, not OK.
- **False Positive Risk:** HIGH before 0.5 (scoped/risk-conditioned policies passed as OK); MEDIUM after
  (joint coverage across narrower policies is not computed).
- **False Negative Risk:** MEDIUM — a policy covering only a subset of privileged roles may be missed.
- **Confidence:** HIGH.
- **Required Changes:** Scope semantics implemented in 0.5 (PolicyScope + purpose_scope + Security
  Defaults ladder). Remaining: joint coverage across narrower policies is not computed.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa`
- **Validation Status:** not-yet-reviewed

#### `id-ca-workload-identity` — Service-principal risk gated by CA

- **Current Claim:** Conditional Access covers service-principal (workload) risk.
- **Actual Evidence Available:** `ca_policies`; predicate `ca.targets_service_principal_risk`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + workload-identity risk licensing.
- **Known Edge Cases:** Report-only workload-risk policies are treated as a gap (not enforced). Policies
  targeting service principals without risk levels are also a gap.
- Effective-scope tokens do not apply: this check's predicate targets service-principal risk conditions
  directly (scope N/A).
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/workload-identities`
- **Validation Status:** not-yet-reviewed

#### `id-break-glass-exclusion` — Break-glass account exists and exclusions justified

- **Current Claim:** A dedicated break-glass (emergency access) Global Administrator exists, and its
  Conditional Access exclusions are documented.
- **Actual Evidence Available:** `ca_policies`, `break_glass_principal_ids`, `role_assignments`,
  `role_eligibilities`. The evaluator `evaluate_break_glass_exclusion` intersects declared break-glass
  principals with scanned Global Administrators and checks that CA exclusions carry a documented rationale.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + Global Administrator role.
- **Known Edge Cases:** (1) If no break-glass principal is declared in config, the check returns
  PARTIAL/GAP even when a valid emergency account exists. (2) If declared principals don't match any
  scanned Global Admin, returns PARTIAL with a "cannot identify" note. (3) Unjustified exclusions demote
  OK→PARTIAL.
- **False Positive Risk:** MEDIUM — a valid break-glass account that isn't declared in config is reported
  as a gap.
- **False Negative Risk:** MEDIUM — an unjustified exclusion on a non-GA principal is not counted.
- **Confidence:** HIGH (when break-glass is declared and matched); MEDIUM otherwise.
- **Required Changes:** None (behavior is fail-closed and well-documented).
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access`
- **Validation Status:** not-yet-reviewed

#### `id-security-defaults-on` — Security defaults vs Conditional Access

- **Current Claim:** Security defaults are enabled, providing baseline MFA/legacy-auth protection, but the
  paid Conditional Access customization is unused.
- **Actual Evidence Available:** `security_defaults_policy`, `ca_policies`. The evaluator
  `evaluate_security_defaults_on` returns GAP when security defaults are enabled (because paid CA
  customization is unused), OK when security defaults are off and enforced CA policies exist, PARTIAL when
  only report-only/disabled CA policies exist, and GAP when neither security defaults nor CA policies exist.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` (the paid capability being assessed).
- **Known Edge Cases:** (1) Security defaults ON is reported as a GAP — this is a deliberate "paid
  capability unused" signal, not a security failure. (2) Security defaults OFF with no CA policies is a
  genuine GAP (no baseline protection).
- **False Positive Risk:** LOW — the GAP on the "security defaults ON" path is a deliberate activation
  signal (the paid CA tier is unused), not a false security verdict. The customer copy correctly explains
  that the paid capability remains unused.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** Documentation/clarity only (no evaluator status change). The GAP on the "security
  defaults ON" path is a deliberate licensing/activation observation. Ensure the finding's terminology and
  copy never imply a security deficiency — the customer copy already states the paid capability remains
  unused, which is the intended framing.
- **Reference Documentation:** `https://learn.microsoft.com/entra/fundamentals/security-defaults`
- **Validation Status:** not-yet-reviewed

#### `id-auth-methods-migration` — Authentication methods migration complete

- **Current Claim:** Sign-in methods are managed from the modern central policy page (migration complete).
- **Actual Evidence Available:** `auth_methods_bundle` → `policy.policyMigrationState`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID authentication methods policy.
- **Known Edge Cases:** Migration state values are normalized (`migrationcomplete`/`complete` → OK,
  `migrationinprogress`/`inprogress` → PARTIAL, else GAP).
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods-manage`
- **Validation Status:** not-yet-reviewed

#### `id-auth-weak-methods-disabled` — Weak authentication methods disabled

- **Current Claim:** SMS, voice, and email OTP authentication methods are disabled.
- **Actual Evidence Available:** `auth_methods_bundle` → `configurations`; weak method IDs are
  `{sms, voice, email, emailotp}`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID authentication methods policy.
- **Known Edge Cases:** If no configurations are returned, returns PARTIAL (cannot confirm). A method with
  an unexpected ID is not treated as weak.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — a weak method with a non-standard ID is not flagged.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods`
- **Validation Status:** not-yet-reviewed

#### `id-auth-authenticator-context` — Authenticator login context

- **Current Claim:** Microsoft Authenticator shows application name and geographic location, and number
  matching is enabled.
- **Actual Evidence Available:** `auth_methods_bundle` → `configurations` (Microsoft Authenticator
  `featureSettings`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID authentication methods policy.
- **Known Edge Cases:** (1) If Authenticator is not enabled tenant-wide, returns GAP. (2) If number
  matching is disabled, returns GAP. (3) If Authenticator config is absent, returns PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if the feature-setting shape differs from the expected dict, context
  may be under-detected.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/authentication/howto-mfa-microsoft-authenticator-app`
- **Validation Status:** not-yet-reviewed

#### `id-number-matching` — Authenticator number matching enforced

- **Current Claim:** Microsoft Authenticator number matching is required for push approvals.
- **Actual Evidence Available:** `auth_methods_bundle` → `configurations` (Microsoft Authenticator
  `numberMatchingRequiredState`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID authentication methods policy.
- **Known Edge Cases:** (1) If the number-matching setting is absent, returns PARTIAL (cannot verify).
  (2) If Authenticator is not enabled, returns PARTIAL. (3) `default` state is treated as OK (Microsoft
  enforces number matching by default). (4) `disabled` is a GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — an unexpected state value returns PARTIAL (inconclusive).
- **Confidence:** HIGH (when state is explicit); MEDIUM otherwise.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/authentication/howto-mfa-microsoft-authenticator-app-number-matching`
- **Validation Status:** not-yet-reviewed

#### `id-app-registration-admin-only` — Only admins register apps

- **Current Claim:** Non-admin users cannot register applications.
- **Actual Evidence Available:** `authorization_policy` → `defaultUserRolePermissions.allowedToCreateApps`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID authorization policy.
- **Known Edge Cases:** If `allowedToCreateApps` is absent, defaults to `True` (treated as a gap).
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/role-based-access-control/delegate-app-roles`
- **Validation Status:** not-yet-reviewed

#### `id-app-user-consent-restricted` — User consent restricted

- **Current Claim:** Users cannot freely approve risky app permissions.
- **Actual Evidence Available:** `authorization_policy` → `defaultUserRolePermissions.permissionGrantPoliciesAssigned`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID authorization policy.
- **Known Edge Cases:** Unrestricted is inferred when no grant policies are assigned or when the legacy
  default policy is present.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — a custom permissive grant policy not matching the known markers may be
  missed.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent`
- **Validation Status:** not-yet-reviewed

#### `id-app-admin-consent-workflow` — Admin consent workflow enabled

- **Current Claim:** Users can request admin approval for apps instead of consenting alone.
- **Actual Evidence Available:** `admin_consent_request_policy.isEnabled`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID authorization policy.
- **Known Edge Cases:** None significant.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow`
- **Validation Status:** not-yet-reviewed

#### `id-app-password-addition-blocked` — App password addition blocked

- **Current Claim:** Users cannot create legacy app passwords that bypass MFA.
- **Actual Evidence Available:** `ca_policies`; block policies whose name contains "app password".
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access`.
- **Known Edge Cases:** Only recognizes block policies whose display name contains "app password" or
  "apppasswords". A block with a different name is missed.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — a block policy with a non-matching name is missed.
- **Confidence:** HIGH.
- **Required Changes:** Consider matching on grant-control shape rather than policy name to reduce false
  negatives.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/block-legacy-authentication`
- **Validation Status:** not-yet-reviewed

#### `id-app-password-lifetime` — App password lifetime

- **Current Claim:** No app password credential lasts longer than 180 days.
- **Actual Evidence Available:** `applications_bundle` → `applications[].passwordCredentials[].endDateTime`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID app registrations.
- **Known Edge Cases:** Uses `scanned_at` or current time as the reference; a credential with no
  `endDateTime` is skipped.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — a credential with a missing `endDateTime` is not flagged.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/enterprise-apps/application-credential-management`
- **Validation Status:** not-yet-reviewed

#### `id-app-certificate-lifetime` — App certificate lifetime

- **Current Claim:** No app certificate lasts longer than 365 days.
- **Actual Evidence Available:** `applications_bundle` → `applications[].keyCredentials[].endDateTime`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID app registrations.
- **Known Edge Cases:** Same as `id-app-password-lifetime`; a cert with no `endDateTime` is skipped.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/enterprise-apps/application-credential-management`
- **Validation Status:** not-yet-reviewed

#### `id-app-expiring-credentials` — App credentials expiring soon

- **Current Claim:** No app credentials are expired or expiring within 30 days.
- **Actual Evidence Available:** `applications_bundle` → `applications[].{passwordCredentials,keyCredentials}[].endDateTime`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID app registrations.
- **Known Edge Cases:** Expired credentials → GAP; expiring within 30 days → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — a credential with a missing `endDateTime` is not flagged.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/enterprise-apps/application-credential-management`
- **Validation Status:** not-yet-reviewed

#### `id-app-ownerless-or-stale` — Ownerless or stale apps

- **Current Claim:** No app registrations are ownerless or clearly stale.
- **Actual Evidence Available:** `applications_bundle` → `applications[]`, `application_owners`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID app registrations.
- **Known Edge Cases:** "Stale" is inferred when an app is >365 days old with no credentials, or when its
  latest credential expired >30 days ago. Ownerless requires the owners map to be present.
- **False Positive Risk:** MEDIUM — a long-lived but active app with no credentials may be flagged stale.
- **False Negative Risk:** MEDIUM — if the owners map is absent, ownerless detection is skipped.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions`
- **Validation Status:** not-yet-reviewed

#### `id-app-risky-delegated-consent` — Risky tenant-wide delegated consent

- **Current Claim:** No tenant-wide delegated grants carry high-impact scopes (mail, files, directory).
- **Actual Evidence Available:** `applications_bundle` → `oauth2_permission_grants` with `consentType=AllPrincipals`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID app registrations / consent.
- **Known Edge Cases:** Only `AllPrincipals` grants are flagged; per-user risky grants are not.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — per-user risky grants are not flagged.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests`
- **Validation Status:** not-yet-reviewed

#### `id-ga-count-bounds` — Global Administrator count bounds

- **Current Claim:** Global Administrator principal count is between 2 and 8.
- **Actual Evidence Available:** `role_assignments` filtered to the Global Admin template ID.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID privileged roles.
- **Known Edge Cases:** Hard-coded 2–8 bounds; a tenant with a legitimate 1-GA design (single break-glass)
  is flagged as a gap.
- **False Positive Risk:** MEDIUM — the 2–8 bounds may not match an org's actual break-glass design.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** Consider making the bounds configurable or documenting the SCuBA basis for 2–8.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access`
- **Validation Status:** not-yet-reviewed

#### `id-ga-finer-roles` — Privileged work not over-concentrated in GA

- **Current Claim:** Finer-grained privileged roles are in use alongside a bounded Global Admin set.
- **Actual Evidence Available:** `role_assignments`; compares GA principal count to other highly privileged
  assignments.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID privileged roles.
- **Known Edge Cases:** Heuristic: GA count >8 with no finer roles → GAP; otherwise PARTIAL/OK.
- **False Positive Risk:** MEDIUM — a legitimately GA-heavy small org may be misclassified.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices`
- **Validation Status:** not-yet-reviewed

#### `id-pim-unused` — PIM licensed but not operationalized

- **Current Claim:** Privileged access uses PIM eligibility vs standing roles.
- **Actual Evidence Available:** `role_assignments`, `role_eligibilities`, `break_glass_principal_ids`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID PIM.
- **Known Edge Cases:** (1) No privileged assignments/eligibilities found → PARTIAL (inconclusive).
  (2) Standing privileged assignments with no PIM eligibility → GAP. (3) Standing only for break-glass with
  full eligible coverage → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if no privileged roles are found, returns PARTIAL rather than a
  definitive gap.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure`
- **Validation Status:** not-yet-reviewed

#### `id-pim-no-permanent-privileged` — No permanent highly privileged roles

- **Current Claim:** No highly privileged role is permanently assigned.
- **Actual Evidence Available:** `role_assignments` filtered to highly privileged roles.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID PIM.
- **Known Edge Cases:** Any standing highly privileged assignment → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure`
- **Validation Status:** not-yet-reviewed

#### `id-pim-no-outside-pam` — Privileged provisioning inside PIM

- **Current Claim:** Highly privileged access is provisioned through PIM eligibility, not outside it.
- **Actual Evidence Available:** `role_assignments`, `role_eligibilities`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID PIM.
- **Known Edge Cases:** Standing assignments with no eligibility → GAP; standing + eligibility → PARTIAL;
  eligible-only → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure`
- **Validation Status:** not-yet-reviewed

#### `id-pim-activation-controls` — PIM activation guardrails

- **Current Claim:** Privileged-role activation requires justification, an authentication context, and is
  capped to a short window (≤8h).
- **Actual Evidence Available:** `pim_policies_bundle` → `policies[].rules[]` (expiration, authentication
  context, enablement/justification rules).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID PIM.
- **Known Edge Cases:** (1) If policy rules are unavailable, returns PARTIAL (cannot verify). (2) If the
  bundle has an error, returns ERROR. (3) Missing any of the three guardrails → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if the rule shape differs from the expected `@odata.type` markers, a
  guardrail may be under-detected.
- **Confidence:** HIGH (when rules are readable); MEDIUM otherwise.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-activate-role`
- **Validation Status:** not-yet-reviewed

#### `id-pim-ga-activation-approval` — GA activation requires approval

- **Current Claim:** Global Administrator activation requires a second approver.
- **Actual Evidence Available:** `pim_policies_bundle` → GA role rules with `isApprovalRequired`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID PIM.
- **Known Edge Cases:** If no GA rules are found, returns PARTIAL (cannot confirm).
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if GA rules are unavailable, returns PARTIAL rather than a definitive gap.
- **Confidence:** HIGH (when rules readable); MEDIUM otherwise.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-approve-activation`
- **Validation Status:** not-yet-reviewed

#### `id-pim-ga-activation-alert` — Alert on GA activation

- **Current Claim:** Global Administrator activation triggers notification rules.
- **Actual Evidence Available:** `pim_policies_bundle` → GA role notification rules.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID PIM.
- **Known Edge Cases:** No notification rules → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if GA rules are unavailable, returns GAP (may be a false gap).
- **Confidence:** HIGH.
- **Required Changes:** Consider returning PARTIAL (not GAP) when GA policy rules are unavailable, to avoid
  a false gap.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts`
- **Validation Status:** not-yet-reviewed

#### `id-pim-other-activation-alert` — Alert on non-GA privileged activation

- **Current Claim:** Activating non-GA privileged roles generates alerts.
- **Actual Evidence Available:** `pim_policies_bundle` → all notification rules.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID PIM.
- **Known Edge Cases:** No notification rules → PARTIAL (not GAP), which may under-report a real gap.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — returns PARTIAL when no notification rules found, so a real gap is
  under-reported.
- **Confidence:** HIGH.
- **Required Changes:** Consider returning GAP (not PARTIAL) when no notification rules are found, to avoid
  a false negative.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts`
- **Validation Status:** not-yet-reviewed

#### `id-pim-privileged-assignment-alert` — Alert on privileged role assignment

- **Current Claim:** Admins get alerts when powerful roles are assigned.
- **Actual Evidence Available:** `pim_policies_bundle` → notification rules.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID PIM.
- **Known Edge Cases:** No notification rules → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if policy rules are unavailable, returns GAP (may be a false gap).
- **Confidence:** HIGH.
- **Required Changes:** Consider returning PARTIAL when policy rules are unavailable.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts`
- **Validation Status:** not-yet-reviewed

#### `id-dormant-privileged` — Dormant privileged identities

- **Current Claim:** No enabled privileged principal is dormant (no successful sign-in in lookback).
- **Actual Evidence Available:** `role_assignments`, `recent_signin_user_ids`,
  `recent_signin_service_principal_ids`, `principal_directory`, `signin_lookback_days`,
  `signin_sample_truncated`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID privileged roles + sign-in logs.
- **Known Edge Cases:** (1) Sign-in sampling truncation demotes OK→PARTIAL. (2) Enabled service principals
  with credentials but no usage signal are "unverifiable" → PARTIAL. (3) Disabled principals are excluded.
  (4) ≥2 dormant principals → GAP; 1 → PARTIAL.
- **False Positive Risk:** MEDIUM — truncation can mislabel an active-but-unsampled principal as dormant.
- **False Negative Risk:** MEDIUM — truncation can miss a genuinely dormant principal.
- **Confidence:** HIGH (when not truncated); MEDIUM when truncated.
- **Required Changes:** None (truncation is handled via the quality policy).
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access`
- **Validation Status:** not-yet-reviewed

#### `id-priv-cloud-only` — Privileged accounts cloud-only

- **Current Claim:** Privileged principals are cloud-only (not synced from on-premises).
- **Actual Evidence Available:** `role_assignments`, `principal_directory` (`onPremisesSyncEnabled`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID privileged roles + directory sync.
- **Known Edge Cases:** A synced principal → GAP; unknown sync state → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if `onPremisesSyncEnabled` is absent, the principal is counted as
  cloud-only (may miss a synced account).
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-whatis`
- **Validation Status:** not-yet-reviewed

#### `id-password-never-expire` — No periodic password expiration

- **Current Claim:** Verified domains do not enforce periodic password expiration.
- **Actual Evidence Available:** `domains` → `passwordValidityPeriodInDays`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID domain settings.
- **Known Edge Cases:** A domain with `passwordValidityPeriodInDays` set (finite) → GAP; `2147483647` or
  ≤0 → OK (never expire). This follows modern NIST guidance that periodic expiration is harmful.
- **False Positive Risk:** LOW — the check correctly flags periodic-expiration enforcement as a gap, which
  aligns with modern NIST guidance (SP 800-63B). A tenant that enforces periodic expiration is reported as a
  gap because that is the intended, standards-aligned behavior.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None (verify: the check correctly follows modern NIST guidance; only a documentation
  note clarifying that this is the intended NIST-aligned baseline is warranted).
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy`
- **Validation Status:** not-yet-reviewed

#### `id-guest-directory-access-limited` — Guest directory access limited

- **Current Claim:** Guest users have limited or restricted directory permissions.
- **Actual Evidence Available:** `authorization_policy` → `guestUserRoleId`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID guest settings.
- **Known Edge Cases:** Guest role ID in `{guest, guest_limited}` → OK; `user_default` → GAP; unknown → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/external-id/what-is-b2b`
- **Validation Status:** not-yet-reviewed

#### `id-guest-inviter-restricted` — Guest invitations restricted

- **Current Claim:** Guest invitations are limited to admins and/or Guest Inviter role.
- **Actual Evidence Available:** `authorization_policy` → `allowInvitesFrom`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID guest settings.
- **Known Edge Cases:** `adminsandguestinviters`/`none`/`admins` → OK; `everyone`/`adminsguestinvitersandallmembers`/empty → GAP; other → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure`
- **Validation Status:** not-yet-reviewed

#### `id-guest-invite-domains` — Guest invite domain allowlist

- **Current Claim:** Guest invite domains are allowlisted to approved partner domains.
- **Actual Evidence Available:** `approved_guest_domains` (config), `guests_bundle` → default.
- **Assessment Type:** MANUAL.
- **Entitlement Dependency:** Entra ID guest settings.
- **Known Edge Cases:** If no approved domains are configured, returns SKIPPED (cannot judge). If
  configured, returns PARTIAL asking the user to verify the live Entra allowlist matches.
- **False Positive Risk:** LOW (returns SKIPPED/PARTIAL, never a definitive gap).
- **False Negative Risk:** MEDIUM — the check never confirms the live allowlist, so a real mismatch is
  under-reported.
- **Confidence:** LOW.
- **Required Changes:** None (inherently manual; the live Entra B2B allowlist is not exposed via a
  deterministic Graph read used here).
- **Reference Documentation:** `https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure`
- **Validation Status:** not-yet-reviewed

#### `id-cross-tenant-defaults` — Cross-tenant collaboration defaults

- **Current Claim:** Default cross-tenant B2B inbound collaboration is blocked.
- **Actual Evidence Available:** `guests_bundle` → `default.b2bCollaborationInbound.usersAndGroups.accessType`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID cross-tenant access settings.
- **Known Edge Cases:** `blocked` → OK; `allowed` → PARTIAL; inconclusive → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — an inconclusive setting returns PARTIAL, not a definitive gap.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration`
- **Validation Status:** not-yet-reviewed

#### `id-cross-tenant-mfa-trust` — Cross-tenant MFA trust

- **Current Claim:** Cross-tenant inbound settings do not accept external MFA claims by default.
- **Actual Evidence Available:** `guests_bundle` → `default`/`partners` trust settings.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID cross-tenant access settings.
- **Known Edge Cases:** (1) Inbound MFA trust `True` by default → GAP. (2) Partner-level explicit trust is
  *not* counted as a gap — it is only reported as a note in the OK summary when the default is not trusted.
  (3) Inconclusive → PARTIAL.
- **False Positive Risk:** LOW — only the *default* inbound MFA trust is flagged as a gap; intentional
  partner-level trust is reported as a note, not a gap.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None (verify: the evaluator already distinguishes intentional partner-level trust
  from a broad default trust; partner-level trust is noted, not flagged).
- **Reference Documentation:** `https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration`
- **Validation Status:** not-yet-reviewed

#### `id-access-reviews-unused` — Access Reviews licensed but not configured

- **Current Claim:** Access Reviews are configured (at least one privileged-scoped recurring review).
- **Actual Evidence Available:** `access_review_definitions`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID Governance (Access Reviews).
- **Known Edge Cases:** (1) No definitions → GAP. (2) Privileged + recurring → OK. (3) Privileged but not
  recurring → PARTIAL. (4) Recurring but not privileged-scoped → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — privileged-scope detection relies on keyword/scope heuristics that may
  miss a review targeting privileged roles via an unusual scope.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/access-reviews-overview`
- **Validation Status:** not-yet-reviewed

#### `id-access-reviews-scope` — Access reviews cover privileged roles, recur, and completed a round

- **Current Claim:** Recurring privileged-role access reviews have actually run to completion.
- **Actual Evidence Available:** `access_review_definitions`, `access_review_instances`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID Governance (Access Reviews).
- **Known Edge Cases:** (1) No definitions → GAP. (2) No privileged-scoped → GAP. (3) Privileged but not
  recurring → PARTIAL. (4) Recurring but no completed round → GAP/PARTIAL depending on instance presence.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — instance-status matching relies on `completed`/`applied` statuses; a
  review with a different terminal status may be missed.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/access-reviews-overview`
- **Validation Status:** not-yet-reviewed

#### `id-entitlement-access-packages` — Entitlement Management access packages

- **Current Claim:** Entitlement Management access packages are configured (lifecycle-governed access).
- **Actual Evidence Available:** `access_packages`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID Governance (Entitlement Management).
- **Known Edge Cases:** (1) No packages → GAP. (2) Visible packages → OK. (3) All hidden → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-governance/entitlement-management-overview`
- **Validation Status:** not-yet-reviewed

#### `id-idprotect-off` — Identity Protection risk policies

- **Current Claim:** Enforced Conditional Access addresses both sign-in risk and user risk.
- **Actual Evidence Available:** `ca_policies` with risk conditions.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** `conditional_access` + Identity Protection.
- **Known Edge Cases:** (1) Both sign-in and user risk enforced → OK. (2) One enforced, other report-only →
  PARTIAL. (3) Neither → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — a risk policy with an unusual grant-control shape may be missed.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies`
- **Validation Status:** not-yet-reviewed

#### `id-identity-protection-workload` — Workload Identity Protection

- **Current Claim:** No service principal is flagged as risky or compromised.
- **Actual Evidence Available:** `risky_service_principals`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Entra ID Protection (workload identities).
- **Known Edge Cases:** (1) Risky/compromised SP → GAP. (2) Unclassified risk states → PARTIAL.
  (3) Permission-denied error → ERROR.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — an SP with an unknown risk state is not flagged as a gap.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-protection/concept-workload-identity-risk`
- **Validation Status:** not-yet-reviewed

#### `id-idprotect-notify-high-risk` — High-risk user admin notifications

- **Current Claim:** Identity Protection emails high-risk user alerts to a monitored mailbox.
- **Actual Evidence Available:** None (portal-configured, not exposed as a complete Graph control).
- **Assessment Type:** MANUAL.
- **Entitlement Dependency:** Entra ID Protection.
- **Known Edge Cases:** Always returns SKIPPED with a manual-verification note.
- **False Positive Risk:** LOW (never reports a gap).
- **False Negative Risk:** HIGH — the check cannot detect a missing notification configuration.
- **Confidence:** LOW.
- **Required Changes:** None (inherently manual).
- **Reference Documentation:** `https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-notifications`
- **Validation Status:** not-yet-reviewed

#### `id-logs-to-soc` — Entra log shipping to SOC

- **Current Claim:** Entra sign-in/audit logs reach a security monitoring platform.
- **Actual Evidence Available:** None (environment-specific, SIEM-side).
- **Assessment Type:** MANUAL.
- **Entitlement Dependency:** Entra ID + SIEM.
- **Known Edge Cases:** Always returns SKIPPED with a manual-verification note.
- **False Positive Risk:** LOW.
- **False Negative Risk:** HIGH — cannot detect missing log shipping.
- **Confidence:** LOW.
- **Required Changes:** None (inherently manual).
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/monitoring-health/howto-integrate-activity-logs-with-arcsight`
- **Validation Status:** not-yet-reviewed

#### `id-ai-agents-risky-block` — Risky AI agents blocked

- **Current Claim:** Conditional Access blocks risky AI agents.
- **Actual Evidence Available:** `ca_policies`; heuristic keyword match on "agent" + "risk"/"block".
- **Assessment Type:** DIRECT (with heuristic fallback). Note: this check is bound via
  `bindings/identity_manual.py` but registered with `evaluation_mode=DIRECT`; it does **not** return
  SKIPPED. It returns PARTIAL (when a candidate policy is found) or GAP (otherwise), both with LOW
  confidence and an advisory limitation — it is a heuristic/advisory check, not a manual-only one.
- **Entitlement Dependency:** `conditional_access` + AI-agent risk controls (license-dependent).
- **Known Edge Cases:** (1) If a matching policy is found, returns PARTIAL (needs specialist review).
  (2) Otherwise returns GAP with an advisory note that agent risk controls vary by cloud/license.
- **False Positive Risk:** MEDIUM — the keyword heuristic may match an unrelated policy.
- **False Negative Risk:** HIGH — a real agent-risk block with a non-matching name is missed.
- **Confidence:** LOW.
- **Required Changes:** This is a heuristic/advisory check. Consider marking it MANUAL or UNKNOWN rather
  than a definitive GAP, since AI-agent risk controls are not a stable, well-defined CA surface.
- **Reference Documentation:** `https://learn.microsoft.com/entra/identity/conditional-access/ai-agents`
- **Validation Status:** not-yet-reviewed

---

### Workload: defender (27 checks)

#### `mde-onboard-gap` — Defender for Endpoint licensed seats vs onboarded devices

- **Current Claim:** Licensed devices are onboarded to Defender for Endpoint with healthy sensors.
- **Actual Evidence Available:** `mde_summary` (MDE machine inventory via `mde.api.machines`) plus
  `graph.subscribedSkus` for licensed seats. The evaluator `evaluate_mde_onboard_gap` implements the §6
  methodology: license-vs-device is a **licensing-leverage signal capped at PARTIAL**, and genuine
  `coverage_ratio` is only computed when an authoritative `eligible_devices` inventory is present.
- **Assessment Type:** DIRECT (when `eligible_devices` present); PROXY (licensing-leverage signal otherwise).
- **Entitlement Dependency:** `defender_endpoint_p2`, `defender_endpoint_p1`.
- **Known Edge Cases:** (1) Without `eligible_devices`, the licensed-seat comparison is labeled `proxy=True`
  and can never reach OK. (2) Truncated machine inventory demotes confidence to MEDIUM. (3) `eligible_devices`
  of zero → PARTIAL (coverage unresolved). (4) Ratio thresholds: ≥0.85 OK, ≥0.5 PARTIAL, else GAP.
- **False Positive Risk:** MEDIUM — license-vs-device comparison can overstate a gap when licenses exceed
  devices for legitimate reasons (e.g., pooled licensing, unassigned seats).
- **False Negative Risk:** LOW — the check is deliberately conservative and never claims coverage without
  an authoritative inventory.
- **Confidence:** HIGH (with `eligible_devices`); LOW (licensing-leverage proxy).
- **Required Changes:** None — the §6 methodology is correctly implemented (license is never a coverage
  denominator; coverage requires an authoritative eligible-device inventory).
- **Reference Documentation:** `https://learn.microsoft.com/defender-endpoint/onboarding`
- **Validation Status:** not-yet-reviewed

#### `mdi-sensors-missing` — Defender for Identity sensors

- **Current Claim:** Defender for Identity sensors are deployed and healthy.
- **Actual Evidence Available:** `secure_score_controls` (Secure Score MDI control hints). The evaluator
  `evaluate_mdi_sensors` uses `summarize_controls` with `MDI_CONTROL_HINTS` as a **proxy**; it never reads
  the actual MDI sensor inventory.
- **Assessment Type:** PROXY.
- **Entitlement Dependency:** `defender_for_identity`.
- **Known Edge Cases:** (1) No matching Secure Score controls → PARTIAL (cannot confirm). (2) Score ratio
  is used to infer sensor health; OK is always demoted to PARTIAL under strict proxy policy.
- **False Positive Risk:** LOW (never reports a definitive gap from the proxy).
- **False Negative Risk:** HIGH — a missing/unhealthy sensor may not be reflected in Secure Score controls,
  so a real sensor gap can be missed.
- **Confidence:** LOW (proxy).
- **Required Changes:** This is a proxy check. To be defensible, it needs a direct MDI sensor-health API
  read (e.g., `microsoft.graph.security.identitySensors` or the MDI portal API). Until then it should be
  labeled PROXY and never treated as definitive.
- **Reference Documentation:** `https://learn.microsoft.com/defender-for-identity/sensor-health`
- **Validation Status:** not-yet-reviewed

#### `mdo-p2-policies-default` — Defender for Office 365 P2 policies

- **Current Claim:** Safe Links and Safe Attachments are broadly enforced.
- **Actual Evidence Available:** Direct Exchange Online PowerShell read (`exchange_threat_policies`) when
  available; otherwise Secure Score MDO controls as a proxy. The evaluator `evaluate_mdo_p2_policies`
  prefers the direct EXO read and falls back to Secure Score.
- **Assessment Type:** DIRECT (when EXO read usable); PROXY (Secure Score fallback).
- **Entitlement Dependency:** `defender_for_office_365_p2`.
- **Known Edge Cases:** (1) Direct read: enabled Safe Links + Safe Attachments + preset → OK. (2) Proxy
  fallback: OK is demoted to PARTIAL under strict proxy policy. (3) No enabled policies → GAP.
- **False Positive Risk:** LOW (direct); MEDIUM (proxy may overstate enforcement).
- **False Negative Risk:** HIGH (proxy cannot confirm actual enforcement).
- **Confidence:** HIGH (direct); LOW (proxy).
- **Required Changes:** The proxy fallback path should be clearly labeled and never reach OK (it is already
  demoted by the quality policy). Prefer the direct EXO read; document that the proxy path is degraded.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/safe-links`
- **Validation Status:** not-yet-reviewed

#### `mdo-alert-policies-enabled` — Defender alert policies

- **Current Claim:** Required suspicious-email and connector alerts are enabled.
- **Actual Evidence Available:** None (portal-configured).
- **Assessment Type:** MANUAL.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** Always returns SKIPPED with a manual-verification note.
- **False Positive Risk:** LOW.
- **False Negative Risk:** HIGH.
- **Confidence:** LOW.
- **Required Changes:** None (inherently manual).
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/alert-policies`
- **Validation Status:** not-yet-reviewed

#### `mdo-audit-retention` — Audit log retention

- **Current Claim:** Audit logs stay searchable 3 months and retrievable 12 months.
- **Actual Evidence Available:** None (license-tier dependent, not fully automated).
- **Assessment Type:** MANUAL.
- **Entitlement Dependency:** Microsoft 365 audit (license tier).
- **Known Edge Cases:** Always returns SKIPPED with a manual-verification note.
- **False Positive Risk:** LOW.
- **False Negative Risk:** HIGH.
- **Confidence:** LOW.
- **Required Changes:** None (inherently manual).
- **Reference Documentation:** `https://learn.microsoft.com/purview/audit-log-retention`
- **Validation Status:** not-yet-reviewed

#### `mdo-anti-spam-no-allowed-domains` — Anti-spam allow lists empty

- **Current Claim:** Anti-spam policies do not include allowed senders or domains.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.anti_spam` (`AllowedSenderDomains`, `AllowedSenders`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365 / Exchange Online Protection.
- **Known Edge Cases:** Any allowed sender/domain → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/anti-spam-policies-configure`
- **Validation Status:** not-yet-reviewed

#### `mdo-connection-filter-no-ip-allow` — Connection filter IP allow list empty

- **Current Claim:** Connection filter IP allow list is empty.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.connection_filter` (`IPAllowList`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online Protection.
- **Known Edge Cases:** Any allow-listed IP → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/connection-filter-policies-configure`
- **Validation Status:** not-yet-reviewed

#### `mdo-connection-filter-no-safe-list` — Connection filter safe list disabled

- **Current Claim:** Connection filter safe list is disabled.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.connection_filter` (`EnableSafeList`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online Protection.
- **Known Edge Cases:** Safe list enabled → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/connection-filter-policies-configure`
- **Validation Status:** not-yet-reviewed

#### `mdo-impersonation-domains-owned` — Domain impersonation protection (owned)

- **Current Claim:** Domain impersonation protection is enabled for owned domains.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.impersonation` (`EnableOrganizationDomainsProtection` / `EnableTargetedDomainsProtection`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** Falls back to `EnableTargetedDomainsProtection` if the org-domains flag is absent.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if both flags are absent, returns PARTIAL.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about`
- **Validation Status:** not-yet-reviewed

#### `mdo-impersonation-partner-domains` — Partner domain impersonation protection

- **Current Claim:** Domain impersonation protection is enabled for partner domains.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.impersonation` (`EnableTargetedDomainsProtection`) + `sensitive_domains` config.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** If no partner domains are configured, returns SKIPPED.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if the flag is absent, returns PARTIAL.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about`
- **Validation Status:** not-yet-reviewed

#### `mdo-impersonation-users-protected` — User impersonation protection

- **Current Claim:** User impersonation protection is enabled for sensitive accounts.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.impersonation` (`EnableTargetedUserProtection`) + `sensitive_users` config.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** If no sensitive users are configured, returns SKIPPED.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if the flag is absent, returns PARTIAL.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about`
- **Validation Status:** not-yet-reviewed

#### `mdo-mailbox-intelligence` — Mailbox intelligence enabled

- **Current Claim:** Mailbox intelligence is enabled across all anti-phish policies.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.anti_phish` (`EnableMailboxIntelligence`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** All policies on → OK; some → PARTIAL; none → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about`
- **Validation Status:** not-yet-reviewed

#### `mdo-malware-file-filter` — Common attachment filter

- **Current Claim:** Click-to-run attachment filtering (common attachments filter) is enabled.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.anti_malware` (`EnableFileFilter`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** None significant.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/anti-malware-policies-configure`
- **Validation Status:** not-yet-reviewed

#### `mdo-malware-zap` — Zero-hour auto purge

- **Current Claim:** Zero-hour auto purge (ZAP) is enabled for malware.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.anti_malware` (`ZapEnabled`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** None significant.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/zero-hour-auto-purge`
- **Validation Status:** not-yet-reviewed

#### `mdo-outbound-spam-forwarding-block` — Outbound automatic forwarding blocked

- **Current Claim:** Outbound automatic forwarding is blocked tenant-wide.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.outbound_spam` (`AutoForwardingEnabled`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365 / Exchange Online Protection.
- **Known Edge Cases:** Any policy with forwarding enabled → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/outbound-spam-policies-configure`
- **Validation Status:** not-yet-reviewed

#### `mdo-quarantine-policy` — End-user quarantine permissions

- **Current Claim:** End users cannot release quarantined mail, and retention is adequate (≥30 days).
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.quarantine` (`EndUserQuarantinePermissionsValue`, `RetentionDurationInDays`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** (1) Full-access quarantine permission → GAP. (2) Retention <30 days → PARTIAL.
- **False Positive Risk:** MEDIUM — some orgs intentionally allow end-user release.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/quarantine-policies`
- **Validation Status:** not-yet-reviewed

#### `mdo-safe-attachments-block` — Safe Attachments set to block

- **Current Claim:** Safe Attachments is set to block or replace detected malware.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.safe_attachments` (`Action` in block set).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** Block/dynamic-delivery/replace/remove → OK; other → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/safe-attachments`
- **Validation Status:** not-yet-reviewed

#### `mdo-safe-attachments-spo-teams` — Safe Attachments for SPO/Teams

- **Current Claim:** Safe Attachments covers SharePoint, OneDrive, and Teams.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.atp_global` (`EnableATPForSPOTeamsODB` / `EnableSafeAttachmentsForSPOTeamsODB`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** None significant.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/safe-attachments`
- **Validation Status:** not-yet-reviewed

#### `mdo-safe-documents` — Safe Documents

- **Current Claim:** Safe Documents scans Office files opened from untrusted sources.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.atp_global` (`EnableSafeDocs`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365 (P2).
- **Known Edge Cases:** None significant.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/safe-documents`
- **Validation Status:** not-yet-reviewed

#### `mdo-safe-links-block-list` — Safe Links block-list checks

- **Current Claim:** Safe Links screens URLs in email, Teams, and Office apps.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.safe_links` (`EnableSafeLinksForEmail/Teams/Office`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** All three surfaces on → OK; email on but others off → PARTIAL; email off → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/safe-links`
- **Validation Status:** not-yet-reviewed

#### `mdo-safe-links-click-through` — Safe Links click-through blocked

- **Current Claim:** Users cannot click through to the original URL.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.safe_links` (`AllowClickThrough`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** Any policy with click-through → GAP.
- **False Positive Risk:** MEDIUM — a single per-user policy with click-through may be intentional.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/safe-links`
- **Validation Status:** not-yet-reviewed

#### `mdo-safe-links-click-tracking` — Safe Links click tracking

- **Current Claim:** Safe Links click tracking is enabled.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.safe_links` (`TrackClicks`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** None significant.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/safe-links`
- **Validation Status:** not-yet-reviewed

#### `mdo-safe-links-real-time-scan` — Safe Links real-time scan

- **Current Claim:** Safe Links performs real-time scanning of suspicious and download links.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.safe_links` (`ScanUrls`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** None significant.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/safe-links`
- **Validation Status:** not-yet-reviewed

#### `mdo-safety-tips-enabled` — Anti-phish safety tips

- **Current Claim:** All anti-phish safety tips are enabled.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.anti_phish` (four safety-tip flags).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365.
- **Known Edge Cases:** All four on → OK; some → PARTIAL; none → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about`
- **Validation Status:** not-yet-reviewed

#### `mdo-spam-phish-not-inbox` — Spam/phishing kept out of inbox

- **Current Claim:** Spam and phishing actions keep messages out of the inbox.
- **Actual Evidence Available:** `exchange_bundle` → `exo_threat_policies.anti_spam` (spam/phish action fields).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Office 365 / Exchange Online Protection.
- **Known Edge Cases:** Any action that delivers to inbox → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/anti-spam-policies-configure`
- **Validation Status:** not-yet-reviewed

#### `mdo-transport-rule-external-forward` — Transport rule external forwarding

- **Current Claim:** No transport rule forwards or Bcc's mail to external domains.
- **Actual Evidence Available:** `exchange_bundle` → `exo_transport.transport_rules` (`RedirectMessageTo`, `BlindCopyTo`) + `exo_accepted_domains`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online / Defender for Office 365.
- **Known Edge Cases:** (1) If accepted domains are unreadable, returns PARTIAL (unresolved). (2) External
  forward/Bcc → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if accepted domains are unreadable, external forwarding may be missed.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules`
- **Validation Status:** not-yet-reviewed

#### `mdo-unified-audit-enabled` — Unified audit logging

- **Current Claim:** Unified audit logging is enabled.
- **Actual Evidence Available:** `exchange_bundle` → `scc_compliance.audit_config` or `exo_audit.mailbox_audit` (`UnifiedAuditLogIngestionEnabled`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft 365 audit.
- **Known Edge Cases:** Falls back from SCC to EXO audit surface if the first is unreadable.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/audit-log-enable-disable`
- **Validation Status:** not-yet-reviewed

---

### Workload: endpoint (13 checks)

#### `endpoint-enrollment-coverage` — Intune licensed seats vs enrolled devices

- **Current Claim:** Licensed devices are enrolled in Intune management.
- **Actual Evidence Available:** `intune_bundle` → `managed_devices` plus `licensed_units` and optional
  `eligible_devices`. The evaluator `evaluate_endpoint_enrollment_coverage` implements the §6 methodology:
  license-vs-device is a licensing-leverage signal capped at PARTIAL; genuine coverage requires an
  authoritative `eligible_devices` inventory.
- **Assessment Type:** DIRECT (with `eligible_devices`); PROXY (licensing-leverage signal otherwise).
- **Entitlement Dependency:** Intune (Microsoft 365 E3/E5 or standalone).
- **Known Edge Cases:** (1) Without `eligible_devices`, the licensed-seat comparison is `proxy=True` and
  never reaches OK. (2) `eligible_devices` of zero → PARTIAL. (3) Zero managed devices with licenses → GAP.
  (4) Truncation demotes confidence.
- **False Positive Risk:** MEDIUM — license-vs-device comparison can overstate a gap.
- **False Negative Risk:** LOW — never claims coverage without an authoritative inventory.
- **Confidence:** HIGH (with `eligible_devices`); LOW (licensing-leverage proxy).
- **Required Changes:** None — the §6 methodology is correctly implemented.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/fundamentals/planning-guide`
- **Validation Status:** not-yet-reviewed

#### `endpoint-compliance-policy-assigned` — Compliance policies defined and assigned

- **Current Claim:** Intune compliance policies exist, are assigned, and cover managed-device platforms.
- **Actual Evidence Available:** `intune_bundle` → `compliance_policies` (assigned + platforms) and `managed_devices`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune.
- **Known Edge Cases:** (1) No policies → GAP. (2) Policies but none assigned → GAP. (3) Assigned but some
  managed platforms uncovered → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — platform matching is substring-based and may miss a platform.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started`
- **Validation Status:** not-yet-reviewed

#### `endpoint-compliance-noncompliance-action` — Noncompliance actions configured

- **Current Claim:** Compliance policies carry a noncompliance action (notify/block).
- **Actual Evidence Available:** `intune_bundle` → `compliance_policies` (`has_noncompliance_action`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune.
- **Known Edge Cases:** (1) No policies → GAP. (2) Policies with no action → GAP. (3) Some with action →
  PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/protect/actions-for-noncompliance`
- **Validation Status:** not-yet-reviewed

#### `endpoint-mde-connector` — Intune-MDE connector active

- **Current Claim:** Devices are flowing from Intune into Defender for Endpoint.
- **Actual Evidence Available:** `intune_bundle` → `atp_onboarding_state` (`onboardedDeviceCount`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune + Defender for Endpoint.
- **Known Edge Cases:** (1) Onboarded >0 → OK. (2) Unknown >0 → GAP. (3) No applicable devices → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — no applicable devices returns PARTIAL, not a definitive gap.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/protect/advanced-threat-protection`
- **Validation Status:** not-yet-reviewed

#### `endpoint-security-baseline` — Endpoint-security baseline applied

- **Current Claim:** An Intune endpoint-security baseline profile is configured.
- **Actual Evidence Available:** `intune_bundle` → `configuration_policies` (baseline family).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune.
- **Known Edge Cases:** No baseline → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — baseline detection relies on the template family string.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/protect/security-baselines`
- **Validation Status:** not-yet-reviewed

#### `endpoint-security-policy-coverage` — Antivirus/firewall/encryption/ASR coverage

- **Current Claim:** Antivirus, firewall, disk-encryption, and ASR policies are all configured.
- **Actual Evidence Available:** `intune_bundle` → `configuration_policies` (template families).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune.
- **Known Edge Cases:** All four families → OK; some → PARTIAL; none → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — family detection relies on template-family string matching.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/protect/endpoint-security`
- **Validation Status:** not-yet-reviewed

#### `ep-asr-rules` — Attack-surface-reduction rules

- **Current Claim:** ASR policies exist, are assigned, and carry rules.
- **Actual Evidence Available:** `intune_bundle` → `asr_policies` (assigned + rule_count).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune + Defender for Endpoint.
- **Known Edge Cases:** (1) No policies → GAP. (2) Policies but none assigned → GAP. (3) Assigned but no
  rules → PARTIAL. (4) Assignment/rule details unreadable → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — assignment/rule detail unreadable returns PARTIAL.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/protect/endpoint-security-asr-policy`
- **Validation Status:** not-yet-reviewed

#### `ep-bitlocker-policy` — BitLocker/disk-encryption policy

- **Current Claim:** A BitLocker/disk-encryption device configuration exists and is assigned.
- **Actual Evidence Available:** `intune_bundle` → `device_configurations` (BitLocker configs).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune.
- **Known Edge Cases:** (1) No config → GAP. (2) Config but none assigned → GAP. (3) Assignment unreadable →
  PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — BitLocker detection relies on odata-type/name heuristics.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/protect/encrypt-devices`
- **Validation Status:** not-yet-reviewed

#### `ep-tamper-protection` — Defender tamper protection

- **Current Claim:** Defender tamper protection is assigned and enabled on devices.
- **Actual Evidence Available:** `intune_bundle` → `device_configurations` (Defender ATP config) + `tamper_device_state`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune + Defender for Endpoint.
- **Known Edge Cases:** (1) No assigned config → GAP (unless devices report tamper on). (2) Assigned but
  disabled on some devices → PARTIAL. (3) Assigned but no device confirms enabled → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — unknown device tamper states are not counted as gaps.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection`
- **Validation Status:** not-yet-reviewed

#### `ep-compliance-enforcement` — Devices actually compliant

- **Current Claim:** Managed devices are actually compliant, not just covered by a policy.
- **Actual Evidence Available:** `intune_bundle` → `compliance_state_summary` (compliant/noncompliant counts).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune.
- **Known Edge Cases:** (1) No compliance state → PARTIAL. (2) Zero compliant with noncompliant → GAP.
  (3) Some noncompliant → PARTIAL. (4) All compliant → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — unknown/error/conflict device states are not counted as noncompliant.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/protect/device-compliance-monitor`
- **Validation Status:** not-yet-reviewed

#### `ep-mam-app-protection` — MAM app protection policies

- **Current Claim:** App protection policies exist and are assigned (or org-wide defaults).
- **Actual Evidence Available:** `intune_bundle` → `app_protection_policies` (assigned + assignment_mode).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Intune (MAM).
- **Known Edge Cases:** (1) No policies → GAP. (2) Policies but none assigned → GAP. (3) Assignment
  unreadable → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — unknown assignment semantics return PARTIAL.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/mem/intune/apps/app-protection-policy`
- **Validation Status:** not-yet-reviewed

#### `mde-sensor-health` — MDE sensor health

- **Current Claim:** Defender for Endpoint sensors report active health.
- **Actual Evidence Available:** `mde_health` (MDE machine health via `mde.api.machines.health`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Defender for Endpoint.
- **Known Edge Cases:** (1) Empty inventory → PARTIAL. (2) Truncated inventory demotes confidence. (3) <25%
  unhealthy → PARTIAL; ≥25% → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — truncation can understate unhealthy sensors.
- **Confidence:** HIGH (when not truncated); MEDIUM when truncated.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-endpoint/machines-view`
- **Validation Status:** not-yet-reviewed

#### `xdr-incident-readiness` — Defender XDR correlation active

- **Current Claim:** Defender XDR correlation is actively in use.
- **Actual Evidence Available:** `security_alerts_bundle` (`incident_count`, `alert_count`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft 365 Defender (XDR).
- **Known Edge Cases:** (1) Incidents/alerts present → OK. (2) Absence of incidents → PARTIAL (never a gap
  or a pass; absence is not treated as evidence of absence).
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW — absence is deliberately not treated as a failure.
- **Confidence:** HIGH (when incidents present); MEDIUM otherwise.
- **Required Changes:** None — the evaluator correctly avoids treating incident absence as a gap.
- **Reference Documentation:** `https://learn.microsoft.com/defender-xdr/incidents-overview`
- **Validation Status:** not-yet-reviewed

---

### Workload: collaboration (24 checks)

#### `spo-sharing-capability-limited` — SharePoint external sharing limited

- **Current Claim:** SharePoint external sharing is limited to existing guests or internal users.
- **Actual Evidence Available:** `collaboration_bundle` → `spo_tenant.sharing_capability`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** SharePoint Online.
- **Known Edge Cases:** Sharing capability `disabled`/`existingexternalusersharingonly` → OK; broader → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off`
- **Validation Status:** not-yet-reviewed

#### `spo-onedrive-sharing-limited` — OneDrive external sharing limited

- **Current Claim:** OneDrive external sharing is limited to existing guests or internal users.
- **Actual Evidence Available:** `collaboration_bundle` → `spo_tenant.onedrive_sharing` (`OneDriveSharingCapability`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** OneDrive for Business.
- **Known Edge Cases:** If the setting is returned without a value → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off`
- **Validation Status:** not-yet-reviewed

#### `spo-unmanaged-device-access` — Unmanaged devices blocked

- **Current Claim:** Unmanaged devices are blocked from SharePoint and OneDrive content.
- **Actual Evidence Available:** `collaboration_bundle` → `spo_tenant.unmanaged_device_policy` (`ConditionalAccessPolicy`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** SharePoint Online + Conditional Access.
- **Known Edge Cases:** `blockaccess` → OK; other/not set → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/sharepoint/control-access-from-unmanaged-devices`
- **Validation Status:** not-yet-reviewed

#### `spo-domain-restrictions` — External sharing domain allowlist

- **Current Claim:** External sharing is limited to an approved domain allowlist.
- **Actual Evidence Available:** `collaboration_bundle` → `spo_tenant.domain_restrictions` + `approved_partner_domains` config.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** SharePoint Online.
- **Known Edge Cases:** (1) Sharing disabled → not-applicable. (2) Mode not `allowlist` → GAP. (3) Allowlist
  contains unapproved domains → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/sharepoint/restrict-sharing-to-specific-domains`
- **Validation Status:** not-yet-reviewed

#### `spo-default-link-specific` — Default sharing links scoped to specific people

- **Current Claim:** Default sharing links are scoped to specific people.
- **Actual Evidence Available:** `collaboration_bundle` → `spo_tenant.default_link` (`DefaultSharingLinkType`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** SharePoint Online.
- **Known Edge Cases:** `direct` → OK; `internal` → PARTIAL; other → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/sharepoint/change-default-sharing-link`
- **Validation Status:** not-yet-reviewed

#### `spo-default-link-view` — Default sharing links view-only

- **Current Claim:** Default sharing links grant view-only permission.
- **Actual Evidence Available:** `collaboration_bundle` → `spo_tenant.default_link` (`DefaultLinkPermission`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** SharePoint Online.
- **Known Edge Cases:** `view` → OK; other → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/sharepoint/change-default-sharing-link`
- **Validation Status:** not-yet-reviewed

#### `spo-anyone-link-expiration` — Anyone links expire

- **Current Claim:** Anyone links expire within 30 days.
- **Actual Evidence Available:** `collaboration_bundle` → `spo_tenant.anyone_link_expiration` (`RequireAnonymousLinksExpireInDays`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** SharePoint Online.
- **Known Edge Cases:** (1) Anyone links disabled → not-applicable. (2) Expiration 1–30 days → OK; else GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off`
- **Validation Status:** not-yet-reviewed

#### `spo-anyone-link-view` — Anyone links view-only

- **Current Claim:** Anyone links are limited to view-only permission.
- **Actual Evidence Available:** `collaboration_bundle` → `spo_tenant.anyone_link_permissions` (`FileAnonymousLinkType`, `FolderAnonymousLinkType`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** SharePoint Online.
- **Known Edge Cases:** Both file and folder `view` → OK; else GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off`
- **Validation Status:** not-yet-reviewed

#### `spo-verification-reauth` — Verification-code reauthentication

- **Current Claim:** Verification-code users must reauthenticate within 30 days.
- **Actual Evidence Available:** `collaboration_bundle` → `spo_tenant.reauth_days` (`EmailAttestationRequired`, `EmailAttestationReAuthDays`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** SharePoint Online.
- **Known Edge Cases:** (1) External sharing disabled → not-applicable. (2) Required + ≤30 days → OK; else GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off`
- **Validation Status:** not-yet-reviewed

#### `teams-external-access-per-domain` — Teams external access domain-limited

- **Current Claim:** Teams external access is limited to specific approved domains.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_federation.federation` (`AllowFederatedUsers`, `AllowedDomains`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** (1) Federation disabled → OK. (2) Open federation (no allowlist or `*`) → GAP.
  (3) Allowlist with unapproved domains → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — a partially-open federation may be missed if the allowlist is present
  but incomplete.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/manage-external-access`
- **Validation Status:** not-yet-reviewed

#### `teams-unmanaged-inbound-blocked` — Unmanaged inbound contact blocked

- **Current Claim:** Unmanaged users cannot initiate contact with internal users.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_federation.unmanaged_users` (`EnableTeamsConsumerInbound`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/manage-external-access`
- **Validation Status:** not-yet-reviewed

#### `teams-unmanaged-outbound-blocked` — Unmanaged outbound contact blocked

- **Current Claim:** Internal users cannot initiate contact with unmanaged users.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_federation.unmanaged_users` (`EnableTeamsConsumerAccess`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/manage-external-access`
- **Validation Status:** not-yet-reviewed

#### `teams-email-integration-disabled` — Teams channel email disabled

- **Current Claim:** Teams channel email integration is disabled.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_client.email_integration` (`AllowEmailIntoChannel`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/teams-channels-overview`
- **Validation Status:** not-yet-reviewed

#### `teams-guest-access-restricted` — Teams guest access restricted

- **Current Claim:** Teams guest access is restricted (or disabled).
- **Actual Evidence Available:** `collaboration_bundle` → `teams_client.guest_access` (`AllowGuestUser`, `AllowGuestCalling`, `AllowGuestChat`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** (1) Guest access disabled → OK. (2) Guest calling/chat disabled → PARTIAL (domain
  allowlist is managed in Entra, not Teams). (3) Guest calling/chat enabled → GAP.
- **False Positive Risk:** MEDIUM — a tenant with guest access enabled but domain-allowlisted in Entra is
  flagged as "wide open".
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** Consider cross-referencing the Entra guest domain allowlist (from
  `id-guest-invite-domains`) to avoid flagging a domain-allowlisted tenant as "wide open".
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/guest-access`
- **Validation Status:** not-yet-reviewed

#### `teams-microsoft-apps-governed` — Microsoft app installation governed

- **Current Claim:** Microsoft app installation is not open to all.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_apps.app_permission_policies` (`DefaultCatalogAppsType`) + `app_settings_v2`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** (1) `allowedapplist` → GAP. (2) Org-wide v2 settings unreadable → PARTIAL (fail-closed).
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — if v2 settings are unreadable, returns PARTIAL.
- **Confidence:** HIGH (when v2 readable); MEDIUM otherwise.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/manage-apps`
- **Validation Status:** not-yet-reviewed

#### `teams-third-party-apps-governed` — Third-party app installation governed

- **Current Claim:** Third-party app installation is not open to all.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_apps.app_permission_policies` (`GlobalCatalogAppsType`) + `app_settings_v2`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** Same as `teams-microsoft-apps-governed`.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM.
- **Confidence:** HIGH (when v2 readable); MEDIUM otherwise.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/manage-apps`
- **Validation Status:** not-yet-reviewed

#### `teams-custom-apps-governed` — Custom app installation governed

- **Current Claim:** Custom app installation is not open to all.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_apps.app_permission_policies` (`PrivateCatalogAppsType`) + `app_settings_v2`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** Same as `teams-microsoft-apps-governed`.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM.
- **Confidence:** HIGH (when v2 readable); MEDIUM otherwise.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/manage-apps`
- **Validation Status:** not-yet-reviewed

#### `teams-external-control-disabled` — External participants cannot request control

- **Current Claim:** External participants cannot request control of shared content.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_meeting.meeting_policies` (`AllowExternalParticipantGiveRequestControl`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/meeting-policies-participants-and-guests`
- **Validation Status:** not-yet-reviewed

#### `teams-anonymous-start-disabled` — Anonymous users cannot start meetings

- **Current Claim:** Anonymous users cannot start meetings.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_meeting.meeting_policies` (`AllowAnonymousUsersToStartMeeting`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/meeting-policies-participants-and-guests`
- **Validation Status:** not-yet-reviewed

#### `teams-anonymous-lobby` — Anonymous users wait in lobby

- **Current Claim:** Anonymous users and dial-in callers are not auto-admitted.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_meeting.meeting_policies` (`AutoAdmittedUsers`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** `everyone` → GAP; else OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/meeting-policies-participants-and-guests`
- **Validation Status:** not-yet-reviewed

#### `teams-internal-auto-admit` — Internal users auto-admitted

- **Current Claim:** Internal users are auto-admitted to meetings.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_meeting.meeting_policies` (`AutoAdmittedUsers`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** `everyoneincompany` → OK; else GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/meeting-policies-participants-and-guests`
- **Validation Status:** not-yet-reviewed

#### `teams-dialin-lobby` — Dial-in callers wait in lobby

- **Current Claim:** Dial-in callers cannot bypass the meeting lobby.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_meeting.meeting_policies` (`AllowPSTNUsersToBypassLobby`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/meeting-policies-participants-and-guests`
- **Validation Status:** not-yet-reviewed

#### `teams-recording-disabled` — Meeting recording disabled

- **Current Claim:** Meeting recording is disabled.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_meeting.meeting_policies` (`AllowCloudRecording`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** MEDIUM — recording may be a legitimate compliance requirement.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/cloud-recording`
- **Validation Status:** not-yet-reviewed

#### `teams-broadcast-not-always-record` — Live events not always recorded

- **Current Claim:** Live events are not set to always record.
- **Actual Evidence Available:** `collaboration_bundle` → `teams_meeting.broadcast_policies` (`BroadcastRecordingMode`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Teams.
- **Known Edge Cases:** `alwaysenabled` → GAP; else OK.
- **False Positive Risk:** MEDIUM — some orgs require always-record for compliance.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/microsoftteams/teams-live-events/what-are-teams-live-events`
- **Validation Status:** not-yet-reviewed

---

### Workload: exchange (12 checks)

#### `exo-dkim-enabled` — DKIM signing enabled

- **Current Claim:** DKIM signing is enabled for all returned domains.
- **Actual Evidence Available:** `exchange_bundle` → `exo_dkim.dkim` (`Enabled`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online.
- **Known Edge Cases:** (1) DKIM surface unreadable → PARTIAL. (2) No DKIM configs returned → PARTIAL.
  (3) Disabled domains → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — a domain with no DKIM config returned is not flagged.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure`
- **Validation Status:** not-yet-reviewed

#### `exo-spf-published` — SPF published with hard fail

- **Current Claim:** Every assessed domain publishes an SPF record that fails unapproved senders.
- **Actual Evidence Available:** `dns_records` (DNS TXT resolution via system resolver).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online (DNS).
- **Known Edge Cases:** (1) No custom domains → SKIPPED. (2) Missing SPF or no hard fail → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — only tenant-owned custom domains are assessed.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure`
- **Validation Status:** not-yet-reviewed

#### `exo-dmarc-published` — DMARC published

- **Current Claim:** Every assessed domain publishes a DMARC record.
- **Actual Evidence Available:** `dns_records` (DNS TXT resolution).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online (DNS).
- **Known Edge Cases:** (1) No custom domains → SKIPPED. (2) Missing DMARC → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — only tenant-owned custom domains are assessed.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure`
- **Validation Status:** not-yet-reviewed

#### `exo-dmarc-reject` — DMARC reject policy

- **Current Claim:** Every assessed domain publishes DMARC with a reject policy.
- **Actual Evidence Available:** `dns_records` (DNS TXT resolution).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online (DNS).
- **Known Edge Cases:** Missing DMARC or non-reject policy → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — only tenant-owned custom domains are assessed.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure`
- **Validation Status:** not-yet-reviewed

#### `exo-dmarc-agency-contact` — DMARC agency report contact

- **Current Claim:** DMARC agency report contact is present for every assessed domain.
- **Actual Evidence Available:** `dns_records` (DMARC `rua`/`ruf`) + `dmarc_agency_contact` config.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online (DNS).
- **Known Edge Cases:** (1) No contact configured → SKIPPED. (2) No custom domains → SKIPPED. (3) Missing
  contact → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — only tenant-owned custom domains are assessed.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure`
- **Validation Status:** not-yet-reviewed

#### `exo-dmarc-federal-contact` — DMARC federal report contact

- **Current Claim:** DMARC federal report contact is present for every assessed domain.
- **Actual Evidence Available:** `dns_records` (DMARC `rua`/`ruf`) + `dmarc_federal_contact` config.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online (DNS).
- **Known Edge Cases:** Same as `exo-dmarc-agency-contact`.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure`
- **Validation Status:** not-yet-reviewed

#### `exo-forwarding-external-disabled` — External forwarding locked down

- **Current Claim:** Automatic forwarding to external domains is disabled or limited to approved domains.
- **Actual Evidence Available:** `exchange_bundle` → `exo_remote_domains.remote_domains` (`AutoForwardEnabled`) + `allowed_forwarding_domains` config.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online.
- **Known Edge Cases:** (1) Surface unreadable → PARTIAL. (2) Unapproved forwarding domains → GAP.
  (3) Forwarding limited to approved → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/exchange/recipients/external-recipients/external-recipients`
- **Validation Status:** not-yet-reviewed

#### `exo-smtp-auth-disabled` — SMTP AUTH disabled

- **Current Claim:** SMTP AUTH is disabled at the organization level.
- **Actual Evidence Available:** `exchange_bundle` → `exo_smtp_auth.smtp_auth` (`SmtpClientAuthenticationDisabled`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online.
- **Known Edge Cases:** (1) Non-boolean value → PARTIAL. (2) Disabled → OK; enabled → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online`
- **Validation Status:** not-yet-reviewed

#### `exo-external-sender-warnings` — External sender warnings

- **Current Claim:** Users see a clear flag when mail comes from outside the organization.
- **Actual Evidence Available:** `exchange_bundle` → `exo_transport.external_warning` (mail tips) + `exo_transport.transport_rules` (subject/disclaimer rule).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online.
- **Known Edge Cases:** (1) Mail tips or rule present → OK. (2) Both unreadable → PARTIAL. (3) Neither → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules`
- **Validation Status:** not-yet-reviewed

#### `exo-mailbox-audit-enabled` — Mailbox auditing enabled

- **Current Claim:** Mailbox auditing is enabled for the organization.
- **Actual Evidence Available:** `exchange_bundle` → `exo_audit.organization_audit` (`AuditDisabled`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online.
- **Known Edge Cases:** (1) Non-boolean value → PARTIAL. (2) Not disabled → OK; disabled → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/audit-mailboxes`
- **Validation Status:** not-yet-reviewed

#### `exo-sharing-calendar-not-all-domains` — Calendar not shared with all domains

- **Current Claim:** Calendar sharing is not open to all domains.
- **Actual Evidence Available:** `exchange_bundle` → `exo_sharing.sharing_policies` (`Domains`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online.
- **Known Edge Cases:** (1) Anonymous sharing → GAP. (2) Surface unreadable → PARTIAL. (3) Limitation notes
  that free/busy vs full-detail granularity is not distinguished.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — free/busy vs full-detail granularity is not distinguished.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/exchange/sharing/sharing-policies/sharing-policies`
- **Validation Status:** not-yet-reviewed

#### `exo-sharing-contact-not-all-domains` — Contact folders not shared with all domains

- **Current Claim:** Contact folder sharing is not open to all domains.
- **Actual Evidence Available:** `exchange_bundle` → `exo_sharing.sharing_policies` (`Domains`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Exchange Online.
- **Known Edge Cases:** Same as `exo-sharing-calendar-not-all-domains`.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/exchange/sharing/sharing-policies/sharing-policies`
- **Validation Status:** not-yet-reviewed

---

### Workload: purview (13 checks)

#### `pur-dlp-not-enforced` — Purview DLP enforced in production

- **Current Claim:** DLP policies are enforced in production (not test/simulation).
- **Actual Evidence Available:** Direct Graph `dataLossPreventionPolicies` when available; otherwise Secure
  Score DLP controls as a proxy. The evaluator `evaluate_purview_dlp` prefers the direct Graph read and
  falls back to Secure Score.
- **Assessment Type:** DIRECT (when Graph read available); PROXY (Secure Score fallback).
- **Entitlement Dependency:** Microsoft Purview (DLP).
- **Known Edge Cases:** (1) Direct: no policies → GAP; policies but none enforced → GAP; enforced → OK.
  (2) Proxy: OK is demoted to PARTIAL under strict proxy policy.
- **False Positive Risk:** LOW (direct); MEDIUM (proxy may overstate enforcement).
- **False Negative Risk:** HIGH (proxy cannot confirm enforce mode).
- **Confidence:** HIGH (direct); LOW (proxy).
- **Required Changes:** The proxy fallback path should be clearly labeled and never reach OK (already
  demoted by the quality policy). Prefer the direct Graph read.
- **Reference Documentation:** `https://learn.microsoft.com/purview/dlp-learn-about-dlp`
- **Validation Status:** not-yet-reviewed

#### `pur-dlp-policy-present` — Enforced DLP policy present

- **Current Claim:** At least one DLP policy is actively protecting sensitive data.
- **Actual Evidence Available:** `exchange_bundle` → `scc_compliance.dlp_policies` (`Mode`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (DLP).
- **Known Edge Cases:** (1) Surface unreadable → PARTIAL. (2) No enforced policy → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/dlp-learn-about-dlp`
- **Validation Status:** not-yet-reviewed

#### `pur-dlp-locations-complete` — DLP covers key locations

- **Current Claim:** DLP policies span multiple workload locations (Exchange, SharePoint, OneDrive, Teams).
- **Actual Evidence Available:** `exchange_bundle` → `scc_compliance.dlp_policies` (`Workload`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (DLP).
- **Known Edge Cases:** (1) ≥3 covered workloads → OK. (2) Some → PARTIAL. (3) None → GAP. (4) Coverage is
  derived from workload flags, not full location enumeration.
- **False Positive Risk:** MEDIUM — workload-flag derivation may under-count actual coverage.
- **False Negative Risk:** MEDIUM — a location not flagged in the workload field is missed.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/dlp-learn-about-dlp`
- **Validation Status:** not-yet-reviewed

#### `pur-dlp-enforcement-block` — DLP blocks sharing sensitive data

- **Current Claim:** DLP rules block sharing sensitive information.
- **Actual Evidence Available:** `exchange_bundle` → `scc_compliance.dlp_rules` (`BlockAccess`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (DLP).
- **Known Edge Cases:** (1) Surface unreadable → PARTIAL. (2) No blocking rule → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/dlp-learn-about-dlp`
- **Validation Status:** not-yet-reviewed

#### `pur-dlp-notifications` — DLP user notifications

- **Current Claim:** DLP rules notify users about sensitive data.
- **Actual Evidence Available:** `exchange_bundle` → `scc_compliance.dlp_rules` (`NotifyUser`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (DLP).
- **Known Edge Cases:** (1) Surface unreadable → PARTIAL. (2) No notifying rule → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/dlp-learn-about-dlp`
- **Validation Status:** not-yet-reviewed

#### `pur-endpoint-dlp` — Endpoint DLP coverage

- **Current Claim:** DLP policies cover endpoint devices.
- **Actual Evidence Available:** `exchange_bundle` → `scc_compliance.dlp_policies` (`Workload` includes "devices").
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (Endpoint DLP).
- **Known Edge Cases:** (1) Surface unreadable → PARTIAL. (2) No endpoint DLP policy → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/endpoint-dlp-learn-about`
- **Validation Status:** not-yet-reviewed

#### `pur-sensitivity-labels-published` — Sensitivity labels published

- **Current Claim:** Sensitivity labels are defined and published to users.
- **Actual Evidence Available:** `purview` surfaces `sensitivity_labels` + `label_policies`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (Information Protection).
- **Known Edge Cases:** (1) Labels defined + published → OK. (2) Defined but not published → GAP.
  (3) None defined → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/sensitivity-labels`
- **Validation Status:** not-yet-reviewed

#### `pur-sensitivity-auto-labeling` — Auto-labeling configured

- **Current Claim:** Auto-labeling is configured for sensitivity labels.
- **Actual Evidence Available:** `purview` surface `label_policies` (auto-labeling markers).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (Information Protection).
- **Known Edge Cases:** Auto-labeling marker present → OK; else GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — auto-labeling detection relies on property-name markers.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/apply-sensitivity-label-automatically`
- **Validation Status:** not-yet-reviewed

#### `pur-default-and-mandatory-labels` — Default and mandatory labeling

- **Current Claim:** A published label policy sets a default label and requires labeling.
- **Actual Evidence Available:** `purview` surface `label_policies` (default/mandatory flags).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (Information Protection).
- **Known Edge Cases:** (1) Both → OK. (2) One → PARTIAL. (3) Neither → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — flag parsing relies on `Settings` dict/list shape.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/sensitivity-labels`
- **Validation Status:** not-yet-reviewed

#### `pur-retention-policy-coverage` — Retention policies govern content

- **Current Claim:** Retention policies and rules are configured.
- **Actual Evidence Available:** `purview` surfaces `retention_policies` + `retention_rules`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (Records Management).
- **Known Edge Cases:** (1) Policies + rules → OK. (2) Policies but no rules → PARTIAL. (3) No policies → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/retention-policies`
- **Validation Status:** not-yet-reviewed

#### `pur-ediscovery-readiness` — eDiscovery readiness

- **Current Claim:** Premium eDiscovery cases and holds are in use.
- **Actual Evidence Available:** `purview_ediscovery` (Graph `security.cases.ediscoveryCases`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (eDiscovery Premium).
- **Known Edge Cases:** (1) Cases present → OK. (2) Empty case list → PARTIAL (ambiguous: no cases vs. no
  permission). (3) Evidence not collected → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — an empty case list is ambiguous and may miss a real readiness gap.
- **Confidence:** HIGH (when cases present); MEDIUM otherwise.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/ediscovery`
- **Validation Status:** not-yet-reviewed

#### `pur-insider-risk-readiness` — Insider risk readiness

- **Current Claim:** Insider Risk Management policies are live.
- **Actual Evidence Available:** `purview_insider_risk` (Graph beta `insiderRiskManagement.policies`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Purview (Insider Risk Management).
- **Known Edge Cases:** (1) Policies present → OK. (2) No policies → GAP. (3) Evidence not collected →
  PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — analytics state is not exposed by the API.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/purview/insider-risk-management`
- **Validation Status:** not-yet-reviewed

#### `pur-communication-compliance-readiness` — Communication compliance readiness

- **Current Claim:** Communication compliance policies cover the channels that matter.
- **Actual Evidence Available:** None (portal-configured).
- **Assessment Type:** MANUAL.
- **Entitlement Dependency:** Microsoft Purview (Communication Compliance).
- **Known Edge Cases:** Always returns SKIPPED with a manual-verification note.
- **False Positive Risk:** LOW.
- **False Negative Risk:** HIGH.
- **Confidence:** LOW.
- **Required Changes:** None (inherently manual).
- **Reference Documentation:** `https://learn.microsoft.com/purview/communication-compliance`
- **Validation Status:** not-yet-reviewed

---

### Workload: power-bi (10 checks)

#### `pbi-publish-to-web-disabled` — Publish to web disabled

- **Current Claim:** Power BI publish to web is disabled.
- **Actual Evidence Available:** `power_bundle` → `pbi_tenant.publish_to_web`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-portal-publish-to-web`
- **Validation Status:** not-yet-reviewed

#### `pbi-guest-access-disabled` — Guest access disabled

- **Current Claim:** Power BI guest user access is disabled.
- **Actual Evidence Available:** `power_bundle` → `pbi_tenant.guest_access`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-portal-export-sharing`
- **Validation Status:** not-yet-reviewed

#### `pbi-external-invite-disabled` — External invitations disabled

- **Current Claim:** External invitations to Power BI content are disabled.
- **Actual Evidence Available:** `power_bundle` → `pbi_tenant.external_invite`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-portal-export-sharing`
- **Validation Status:** not-yet-reviewed

#### `pbi-sp-api-restricted` — Service principal API restricted

- **Current Claim:** Service principals cannot use Power BI/Fabric APIs, or are limited to security groups.
- **Actual Evidence Available:** `power_bundle` → `pbi_tenant.service_principal_api` (`enabled`, `securityGroups`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI.
- **Known Edge Cases:** (1) Disabled → OK. (2) Enabled + groups → OK. (3) Enabled without groups → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-portal-developer`
- **Validation Status:** not-yet-reviewed

#### `pbi-sp-profiles-disabled` — Service principal profiles disabled

- **Current Claim:** Service principal Power BI profile creation is disabled.
- **Actual Evidence Available:** `power_bundle` → `pbi_tenant.service_principal_profiles`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-portal-developer`
- **Validation Status:** not-yet-reviewed

#### `pbi-resource-key-auth-blocked` — Resource key auth blocked

- **Current Claim:** Power BI resource key authentication is blocked.
- **Actual Evidence Available:** `power_bundle` → `pbi_tenant.resource_key_auth`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI.
- **Known Edge Cases:** Blocked → OK; not blocked → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-portal-developer`
- **Validation Status:** not-yet-reviewed

#### `pbi-python-r-visuals-disabled` — Python/R visuals disabled

- **Current Claim:** Python and R visuals are disabled.
- **Actual Evidence Available:** `power_bundle` → `pbi_tenant.python_r_visuals`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-portal-developer`
- **Validation Status:** not-yet-reviewed

#### `pbi-sensitivity-labels-enabled` — Sensitivity labels enabled

- **Current Claim:** Power BI sensitivity labels are enabled.
- **Actual Evidence Available:** `power_bundle` → `pbi_tenant.sensitivity_labels`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI + Microsoft Purview.
- **Known Edge Cases:** Enabled → OK; not enabled → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-portal-information-protection`
- **Validation Status:** not-yet-reviewed

#### `pbi-export-controls` — Data export disabled

- **Current Claim:** Power BI data export is disabled.
- **Actual Evidence Available:** `power_bundle` → `pbi_tenant.export_data`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI.
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-portal-export-sharing`
- **Validation Status:** not-yet-reviewed

#### `pbi-premium-capacity-governance` — Premium capacity governance

- **Current Claim:** Power BI Premium/Fabric capacities are governed (admins assigned, workspaces mapped).
- **Actual Evidence Available:** `pbi_capacity_bundle` (Power BI admin REST `capacities` + `tenantsettings`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power BI Premium / Fabric.
- **Known Edge Cases:** (1) No capacities → PARTIAL (may rely on Premium-per-user; PPU seat assignment is
  not readable via the capacities API). (2) Capacities present → OK with a note that workspace mapping and
  per-user entitlement provenance still require portal review.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — PPU seat assignment is not readable, so a PPU-only tenant is reported
  as PARTIAL.
- **Confidence:** HIGH (when capacities present); MEDIUM otherwise.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-bi/admin/service-admin-premium-capacity` (plus Fabric capacity docs)
- **Validation Status:** not-yet-reviewed

---

### Workload: power-platform (8 checks)

#### `pp-env-creation-admin-only` — Environment creation admin-only

- **Current Claim:** Environment creation is restricted to admins.
- **Actual Evidence Available:** `power_bundle` → `power_platform_tenant.environment_creation` (`disableEnvironmentCreationByNonAdminUsers`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power Platform.
- **Known Edge Cases:** Disabled-by-non-admin → GAP; admin-only → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-platform/admin/control-environment-creation`
- **Validation Status:** not-yet-reviewed

#### `pp-trial-creation-admin-only` — Trial environment creation admin-only

- **Current Claim:** Trial environment creation is restricted to admins.
- **Actual Evidence Available:** `power_bundle` → `power_platform_tenant.environment_creation` (`disableTrialEnvironmentCreationByNonAdminUsers`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power Platform.
- **Known Edge Cases:** Disabled-by-non-admin → GAP; admin-only → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-platform/admin/control-environment-creation`
- **Validation Status:** not-yet-reviewed

#### `pp-pages-creation-admin-only` — Power Pages creation admin-only

- **Current Claim:** Power Pages creation is restricted to admins.
- **Actual Evidence Available:** `power_bundle` → `power_platform_tenant.power_pages` (`disablePortalsCreationByNonAdminUsers`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power Platform (Power Pages).
- **Known Edge Cases:** Disabled-by-non-admin → GAP; admin-only → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-pages/admin/control-portal-creation`
- **Validation Status:** not-yet-reviewed

#### `pp-share-with-everyone-disabled` — Share-with-everyone disabled

- **Current Claim:** Sharing Power Apps with everyone is disabled.
- **Actual Evidence Available:** `power_bundle` → `power_platform_tenant.share_with_everyone` (`disableShareWithEveryone`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power Platform (Power Apps).
- **Known Edge Cases:** Enabled → GAP; disabled → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-platform/admin/control-share-with-everyone`
- **Validation Status:** not-yet-reviewed

#### `pp-dlp-all-environments` — DLP covers all environments

- **Current Claim:** Every Power Platform environment is covered by a DLP policy.
- **Actual Evidence Available:** `power_bundle` → `power_platform_env.environments` + `power_platform_env.dlp_policies`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power Platform (DLP).
- **Known Edge Cases:** (1) No environments → PARTIAL. (2) No DLP policies → GAP. (3) Uncovered environments
  → GAP. (4) All covered → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — environment coverage is derived from policy assignment semantics.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-platform/admin/wp-data-loss-prevention`
- **Validation Status:** not-yet-reviewed

#### `pp-dlp-nondefault-envs` — DLP covers non-default environments

- **Current Claim:** Every non-default Power Platform environment is covered by a DLP policy.
- **Actual Evidence Available:** `power_bundle` → `power_platform_env.environments` + `power_platform_env.dlp_policies`.
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power Platform (DLP).
- **Known Edge Cases:** (1) No non-default environments → OK. (2) Uncovered non-default → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-platform/admin/wp-data-loss-prevention`
- **Validation Status:** not-yet-reviewed

#### `pp-tenant-isolation-enabled` — Tenant isolation enabled

- **Current Claim:** Power Platform tenant isolation is enabled.
- **Actual Evidence Available:** `power_bundle` → `power_platform_env.tenant_isolation` (`isolationEnabled`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power Platform.
- **Known Edge Cases:** Enabled → OK; disabled → GAP; inconclusive → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-platform/admin/cross-tenant-restrictions`
- **Validation Status:** not-yet-reviewed

#### `pp-tenant-isolation-allowlist` — Tenant isolation allowlist

- **Current Claim:** Cross-tenant connections are limited to an explicit allowlist.
- **Actual Evidence Available:** `power_bundle` → `power_platform_env.tenant_isolation` (`isolationEnabled`, `allowedTenants`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Power Platform.
- **Known Edge Cases:** (1) Isolation disabled → GAP. (2) Isolation on but no allowlist → GAP. (3) Isolation
  on with allowlist → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/power-platform/admin/cross-tenant-restrictions`
- **Validation Status:** not-yet-reviewed

---

### Workload: sentinel (5 checks)

#### `sen-analytics-rule-coverage` — Sentinel analytics rule coverage

- **Current Claim:** Sentinel has a configured set of detection alarms covering multiple attack stages.
- **Actual Evidence Available:** `sentinel_rules` (Azure ARM `securityInsights` analytics rules).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** observed via ARM onboardingStates (0.5).
- **Known Edge Cases:** (1) Workspace missing → ERROR. (2) No rules → GAP. (3) Rules but none enabled → GAP.
  (4) ≥10 enabled rules + ≥3 tactics → OK; else PARTIAL. (5) Rule counts do not prove detection effectiveness.
- **False Positive Risk:** MEDIUM — the ≥10 rules / ≥3 tactics baseline is arbitrary; a lean-but-effective
  workspace is flagged.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** Consider documenting that the rule-count baseline is a heuristic, not a proof of
  detection effectiveness.
- **Reference Documentation:** `https://learn.microsoft.com/azure/sentinel/detect-threats-custom`
- **Validation Status:** not-yet-reviewed

#### `sen-data-connectors` — Sentinel data connectors

- **Current Claim:** Sentinel has several connected data sources, including high-value identity/M365 signals.
- **Actual Evidence Available:** `sentinel_data_connectors` (Azure ARM).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** observed via ARM onboardingStates (0.5).
- **Known Edge Cases:** (1) Workspace missing → ERROR. (2) No connectors → GAP. (3) ≥3 total + ≥2 key → OK;
  else PARTIAL. (4) Connected counts do not prove collection quality.
- **False Positive Risk:** MEDIUM — the connector-count baseline is arbitrary.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** Consider documenting that connector counts are a heuristic, not proof of collection
  quality.
- **Reference Documentation:** `https://learn.microsoft.com/azure/sentinel/connect-data-sources`
- **Validation Status:** not-yet-reviewed

#### `sen-automation-rules` — Sentinel automation rules / playbooks

- **Current Claim:** Sentinel can react to alerts automatically (playbook action present).
- **Actual Evidence Available:** `sentinel_automation_rules` (Azure ARM).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** observed via ARM onboardingStates (0.5).
- **Known Edge Cases:** (1) Workspace missing → ERROR. (2) No rules → GAP. (3) Rules but no playbook → PARTIAL.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks`
- **Validation Status:** not-yet-reviewed

#### `sen-log-analytics-retention` — Log Analytics retention

- **Current Claim:** Log Analytics retention meets the 90-day target.
- **Actual Evidence Available:** `sentinel_workspace` (`retention_in_days`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** observed via ARM onboardingStates (0.5).
- **Known Edge Cases:** (1) Workspace missing → ERROR. (2) Retention ≥90 → OK; ≥60 → PARTIAL; <60 → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-archive`
- **Validation Status:** not-yet-reviewed

#### `sen-ueba-not-enabled` — Sentinel UEBA / entity analytics

- **Current Claim:** Sentinel UEBA / entity analytics is enabled.
- **Actual Evidence Available:** `sentinel_ueba` (Azure ARM settings).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** observed via ARM onboardingStates (0.5).
- **Known Edge Cases:** (1) Workspace missing → ERROR. (2) Settings read failure distinguished from
  explicitly-off. (3) Enabled → OK; not enabled → GAP.
- **False Positive Risk:** LOW.
- **False Negative Risk:** MEDIUM — a partial settings read may miss the real state.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/azure/sentinel/identify-threats-with-entity-behavior-analytics`
- **Validation Status:** not-yet-reviewed

---

### Workload: azure (2 checks)

#### `az-defender-plan-enabled` — Defender for Cloud plan enabled

- **Current Claim:** Defender for Cloud is enabled at the Standard tier for the subscription.
- **Actual Evidence Available:** `defender_for_cloud_pricings` (Azure ARM `securityPricings`).
- **Assessment Type:** DIRECT.
- **Entitlement Dependency:** Microsoft Defender for Cloud.
- **Known Edge Cases:** (1) Pricing read error → ERROR. (2) No Standard plans → GAP. (3) Standard plans → OK.
- **False Positive Risk:** LOW.
- **False Negative Risk:** LOW.
- **Confidence:** HIGH.
- **Required Changes:** None.
- **Reference Documentation:** `https://learn.microsoft.com/azure/defender-for-cloud/enable-enhanced-security`
- **Validation Status:** not-yet-reviewed

#### `az-cspm-out-of-scope` — Generic Azure CSPM out of scope

- **Current Claim:** Generic Azure CSPM posture (VMs, storage, SQL, networking) is out of scope.
- **Actual Evidence Available:** None (intentionally unsupported).
- **Assessment Type:** MANUAL / UNSUPPORTED.
- **Entitlement Dependency:** Microsoft Defender for Cloud (CSPM).
- **Known Edge Cases:** Always returns SKIPPED with an explicit out-of-scope note.
- **False Positive Risk:** LOW (never reports a gap).
- **False Negative Risk:** HIGH — generic CSPM gaps are not assessed.
- **Confidence:** LOW.
- **Required Changes:** None (intentionally out of scope; documented as such).
- **Reference Documentation:** `https://learn.microsoft.com/azure/defender-for-cloud/concept-cloud-security-posture-management`
- **Validation Status:** not-yet-reviewed

---

## Prioritized Required-Changes Backlog

Every check with a non-empty **Required Changes** field, ordered by the severity of the underlying semantic
issue. Severity reflects how much the current behavior could mislead a reader (false gap, false pass, or
overstated confidence), not the security impact of the underlying control.

### Tier 1 — Semantically inverted or misleading verdicts (highest priority)

1. **`id-security-defaults-on`** — The check reports a GAP when security defaults are **enabled**, because
   the paid Conditional Access tier is unused. This is a **deliberate activation-gap design**, not a code
   bug: the GAP is a licensing/activation observation (the paid CA customization is unused), and the
   customer copy correctly explains that the paid capability remains unused. It correctly returns GAP when
   security defaults are OFF with no enforced CA policies, and OK when security defaults are OFF with
   enforced CA. **Recommendation (documentation/clarity only, no evaluator status change):** ensure the
   finding's terminology and copy never imply a security deficiency — the customer copy already frames it
   as "paid capability remains unused," which is the intended wording.

2. **`id-ai-agents-risky-block`** — A heuristic keyword match on CA policy names is used to assert that
   "risky AI agents are blocked." AI-agent risk controls are not a stable, well-defined CA surface, so the
   check can both false-positive (match an unrelated policy) and false-negative (miss a real block).
   **Fix:** mark as MANUAL or UNKNOWN rather than a definitive GAP, and require specialist review.

### Tier 2 — Proxy evidence that cannot support the conclusion

3. **`mdi-sensors-missing`** — Uses Secure Score control completion as a **proxy** for MDI sensor health.
   A missing/unhealthy sensor may not be reflected in Secure Score, so a real sensor gap can be missed.
   **Fix:** add a direct MDI sensor-health API read; until then keep it labeled PROXY and never definitive.

4. **`mdo-p2-policies-default`** — Falls back to Secure Score when the direct Exchange Online PowerShell
   read is unavailable. The proxy path cannot confirm actual Safe Links/Attachments enforcement. **Fix:**
   keep the proxy path clearly labeled and never reaching OK (already demoted by the quality policy);
   prefer the direct EXO read.

5. **`pur-dlp-not-enforced`** — Falls back to Secure Score when the direct Graph DLP read is unavailable.
   The proxy path cannot confirm DLP enforce mode. **Fix:** keep the proxy path clearly labeled and never
   reaching OK (already demoted by the quality policy); prefer the direct Graph read.

### Tier 3 — Heuristic thresholds and policy-shape matching that cause false gaps/passes

6. **`id-ca-phishing-resistant-all`** — Requires phishing-resistant MFA for *all* users; orgs that
   legitimately scope it to privileged roles are flagged. **Fix:** document the SCuBA "all users" baseline
   and cross-reference `id-ca-phishing-resistant-privileged`.

7. **`id-ca-mfa-registration-managed`** — Requires a managed-device policy specifically targeting the
   security-info registration app; a broader managed-device policy that transitively covers it is flagged.
   **Fix:** relax the predicate to accept a broader managed-device policy.

8. **`id-app-password-addition-blocked`** — Only recognizes block policies whose display name contains
   "app password"; a block with a different name is missed. **Fix:** match on grant-control shape rather
   than policy name.

9. **`id-ga-count-bounds`** — Hard-coded 2–8 Global Admin bounds may not match an org's actual break-glass
   design. **Fix:** make the bounds configurable or document the SCuBA basis.

### Tier 4 — Inconclusive-vs-gap polarity on PIM alert checks

10. **`id-pim-ga-activation-alert`** — Returns GAP when GA policy rules are unavailable, which can be a
    false gap. **Fix:** return PARTIAL when GA policy rules are unavailable.

11. **`id-pim-privileged-assignment-alert`** — Returns GAP when policy rules are unavailable, which can be
    a false gap. **Fix:** return PARTIAL when policy rules are unavailable.

12. **`id-pim-other-activation-alert`** — Returns PARTIAL when no notification rules are found, which can
    under-report a real gap. **Fix:** return GAP when no notification rules are found.

### Tier 5 — Cross-surface integration and heuristic baselines

13. **`teams-guest-access-restricted`** — Flags guest access as "wide open" when calling/chat are on, even
    when the guest domain allowlist is managed in Entra (not Teams). **Fix:** cross-reference the Entra
    guest domain allowlist (from `id-guest-invite-domains`) to avoid flagging a domain-allowlisted tenant.

14. **`sen-analytics-rule-coverage`** — The ≥10 rules / ≥3 tactics baseline is arbitrary; a lean-but-
    effective workspace is flagged. **Fix:** document that the rule-count baseline is a heuristic, not a
    proof of detection effectiveness.

15. **`sen-data-connectors`** — The ≥3 total / ≥2 key connector baseline is arbitrary. **Fix:** document
    that connector counts are a heuristic, not proof of collection quality.

---

## End of Audit

This audit covers all **166** checks in the catalog. Every check is recorded as **not-yet-reviewed**; no
check has been externally validated by a practitioner. The assessment-type classification, confidence, and
required-changes backlog above are grounded in the actual evaluator source and the engine's fail-closed
quality policy, and are intended to guide the flagship-check hardening work in §5 of the product-maturity
goal.
