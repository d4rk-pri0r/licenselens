# Check tier classification

Locked rule (WS6-A / D5): **activation** = required capabilities include a paid
security product (`entitlement_kind` in `{included, add_on, consumption}` and id
in Entra P2 / CA / Identity Protection / workload identities / entitlement
management / Defender* / Sentinel / Log Analytics / Purview* / Intune / DfC).
**hygiene** = base-workload configuration (Exchange, EOP, SharePoint, OneDrive,
Teams, Power Platform, Power BI) regardless of collector.
MDO Safe Links / Attachments / impersonation stay **activation** even when
PowerShell-collected. EOP anti-spam / connection-filter / transport-rule stay
**hygiene**.

Totals: 109 activation · 61 hygiene · 170 enabled checks.

| Check | Tier | Required capabilities | Rationale |
|---|---|---|---|
| `az-cspm-out-of-scope` | activation | defender_for_cloud_cspm | paid security capability: defender_for_cloud_cspm |
| `az-defender-plan-enabled` | activation | defender_for_cloud_cspm,defender_for_cloud_servers | paid security capability: defender_for_cloud_cspm, defender_for_cloud_servers |
| `endpoint-compliance-noncompliance-action` | activation | intune | paid security capability: intune |
| `endpoint-compliance-policy-assigned` | activation | intune | paid security capability: intune |
| `endpoint-enrollment-coverage` | activation | intune | paid security capability: intune |
| `endpoint-mde-connector` | activation | intune | paid security capability: intune |
| `endpoint-security-baseline` | activation | intune | paid security capability: intune |
| `endpoint-security-policy-coverage` | activation | intune | paid security capability: intune |
| `ep-asr-rules` | activation | defender_endpoint_p2,defender_endpoint_p1 | paid security capability: defender_endpoint_p2, defender_endpoint_p1 |
| `ep-bitlocker-policy` | activation | intune | paid security capability: intune |
| `ep-compliance-enforcement` | activation | intune | paid security capability: intune |
| `ep-mam-app-protection` | activation | intune | paid security capability: intune |
| `ep-tamper-protection` | activation | defender_endpoint_p2,defender_endpoint_p1 | paid security capability: defender_endpoint_p2, defender_endpoint_p1 |
| `id-access-reviews-scope` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-access-reviews-unused` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-ai-agents-risky-block` | activation | identity_protection | paid security capability: identity_protection |
| `id-app-admin-consent-workflow` | activation | conditional_access | paid security capability: conditional_access |
| `id-app-certificate-lifetime` | activation | conditional_access | paid security capability: conditional_access |
| `id-app-expiring-credentials` | activation | conditional_access | paid security capability: conditional_access |
| `id-app-ownerless-or-stale` | activation | conditional_access | paid security capability: conditional_access |
| `id-app-password-addition-blocked` | activation | conditional_access | paid security capability: conditional_access |
| `id-app-password-lifetime` | activation | conditional_access | paid security capability: conditional_access |
| `id-app-registration-admin-only` | activation | conditional_access | paid security capability: conditional_access |
| `id-app-risky-delegated-consent` | activation | conditional_access | paid security capability: conditional_access |
| `id-app-user-consent-restricted` | activation | conditional_access | paid security capability: conditional_access |
| `id-auth-authenticator-context` | activation | conditional_access | paid security capability: conditional_access |
| `id-auth-methods-migration` | activation | conditional_access | paid security capability: conditional_access |
| `id-auth-weak-methods-disabled` | activation | conditional_access | paid security capability: conditional_access |
| `id-break-glass-exclusion` | activation | entra_id_p2,conditional_access | paid security capability: entra_id_p2, conditional_access |
| `id-ca-device-code-block` | activation | conditional_access | paid security capability: conditional_access |
| `id-ca-high-risk-signins` | activation | identity_protection | paid security capability: identity_protection |
| `id-ca-high-risk-users` | activation | identity_protection | paid security capability: identity_protection |
| `id-ca-legacy-auth-block` | activation | conditional_access | paid security capability: conditional_access |
| `id-ca-managed-devices` | activation | conditional_access,intune | paid security capability: conditional_access, intune |
| `id-ca-mfa-all-users` | activation | conditional_access | paid security capability: conditional_access |
| `id-ca-mfa-registration-managed` | activation | conditional_access,intune | paid security capability: conditional_access, intune |
| `id-ca-phishing-resistant-all` | activation | conditional_access | paid security capability: conditional_access |
| `id-ca-phishing-resistant-privileged` | activation | conditional_access | paid security capability: conditional_access |
| `id-ca-priv-gaps` | activation | conditional_access | paid security capability: conditional_access |
| `id-ca-workload-identity` | activation | workload_identities_premium | paid security capability: workload_identities_premium |
| `id-cross-tenant-defaults` | activation | conditional_access | paid security capability: conditional_access |
| `id-cross-tenant-mfa-trust` | activation | conditional_access | paid security capability: conditional_access |
| `id-dormant-privileged` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-entitlement-access-packages` | activation | entitlement_management | paid security capability: entitlement_management |
| `id-ga-count-bounds` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-ga-finer-roles` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-guest-directory-access-limited` | activation | conditional_access | paid security capability: conditional_access |
| `id-guest-invite-domains` | activation | conditional_access | paid security capability: conditional_access |
| `id-guest-inviter-restricted` | activation | conditional_access | paid security capability: conditional_access |
| `id-identity-protection-workload` | activation | workload_identities_premium | paid security capability: workload_identities_premium |
| `id-idprotect-notify-high-risk` | activation | identity_protection | paid security capability: identity_protection |
| `id-idprotect-off` | activation | identity_protection | paid security capability: identity_protection |
| `id-logs-to-soc` | activation | conditional_access | paid security capability: conditional_access |
| `id-number-matching` | activation | conditional_access | paid security capability: conditional_access |
| `id-password-never-expire` | activation | conditional_access | paid security capability: conditional_access |
| `id-pim-activation-controls` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-pim-ga-activation-alert` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-pim-ga-activation-approval` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-pim-no-outside-pam` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-pim-no-permanent-privileged` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-pim-other-activation-alert` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-pim-privileged-assignment-alert` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-pim-unused` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-priv-cloud-only` | activation | entra_id_p2 | paid security capability: entra_id_p2 |
| `id-protective-plan-assignment` | activation | entra_id_p2,identity_protection,defender_office_p2,defender_endpoint_p2,purview_dlp | paid security capability: entra_id_p2, identity_protection, defender_office_p2, defender_endpoint_p2, purview_dlp |
| `id-security-defaults-on` | activation | conditional_access | paid security capability: conditional_access |
| `mde-onboard-gap` | activation | defender_endpoint_p2,defender_endpoint_p1 | paid security capability: defender_endpoint_p2, defender_endpoint_p1 |
| `mde-sensor-health` | activation | defender_endpoint_p2,defender_endpoint_p1 | paid security capability: defender_endpoint_p2, defender_endpoint_p1 |
| `mdi-sensors-missing` | activation | defender_identity | paid security capability: defender_identity |
| `mdo-alert-policies-enabled` | activation | defender_office_p1 | paid security capability: defender_office_p1 |
| `mdo-audit-retention` | activation | purview_audit | paid security capability: purview_audit |
| `mdo-impersonation-domains-owned` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-impersonation-partner-domains` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-impersonation-users-protected` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-mailbox-intelligence` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-malware-file-filter` | activation | defender_office_p1 | paid security capability: defender_office_p1 |
| `mdo-malware-zap` | activation | defender_office_p1 | paid security capability: defender_office_p1 |
| `mdo-p2-policies-default` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-safe-attachments-block` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-safe-attachments-spo-teams` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-safe-documents` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-safe-links-block-list` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-safe-links-click-through` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-safe-links-click-tracking` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-safe-links-real-time-scan` | activation | defender_office_p2 | MDO Safe Links/Attachments/impersonation (paid MDO) |
| `mdo-safety-tips-enabled` | activation | defender_office_p2 | paid security capability: defender_office_p2 |
| `mdo-unified-audit-enabled` | activation | purview_audit | paid security capability: purview_audit |
| `pur-communication-compliance-readiness` | activation | purview_communication_compliance | paid security capability: purview_communication_compliance |
| `pur-default-and-mandatory-labels` | activation | purview_sensitivity_labels | paid security capability: purview_sensitivity_labels |
| `pur-dlp-enforcement-block` | activation | purview_dlp | paid security capability: purview_dlp |
| `pur-dlp-locations-complete` | activation | purview_dlp | paid security capability: purview_dlp |
| `pur-dlp-not-enforced` | activation | purview_dlp | paid security capability: purview_dlp |
| `pur-dlp-notifications` | activation | purview_dlp | paid security capability: purview_dlp |
| `pur-dlp-policy-present` | activation | purview_dlp | paid security capability: purview_dlp |
| `pur-ediscovery-readiness` | activation | purview_ediscovery | paid security capability: purview_ediscovery |
| `pur-endpoint-dlp` | activation | purview_dlp | paid security capability: purview_dlp |
| `pur-insider-risk-readiness` | activation | purview_insider_risk | paid security capability: purview_insider_risk |
| `pur-retention-policy-coverage` | activation | purview_retention | paid security capability: purview_retention |
| `pur-sensitivity-auto-labeling` | activation | purview_sensitivity_labels | paid security capability: purview_sensitivity_labels |
| `pur-sensitivity-labels-published` | activation | purview_sensitivity_labels | paid security capability: purview_sensitivity_labels |
| `sen-analytics-rule-coverage` | activation | microsoft_sentinel | paid security capability: microsoft_sentinel |
| `sen-automation-rules` | activation | microsoft_sentinel | paid security capability: microsoft_sentinel |
| `sen-data-connectors` | activation | microsoft_sentinel | paid security capability: microsoft_sentinel |
| `sen-entra-diagnostics-routed` | activation | microsoft_sentinel | paid security capability: microsoft_sentinel |
| `sen-log-analytics-retention` | activation | microsoft_sentinel,log_analytics | paid security capability: microsoft_sentinel, log_analytics |
| `sen-rule-telemetry-parity` | activation | microsoft_sentinel | paid security capability: microsoft_sentinel |
| `sen-telemetry-ingestion-coverage` | activation | microsoft_sentinel | paid security capability: microsoft_sentinel |
| `sen-ueba-not-enabled` | activation | microsoft_sentinel | paid security capability: microsoft_sentinel |
| `xdr-incident-readiness` | activation | defender_xdr | paid security capability: defender_xdr |
| `exo-dkim-enabled` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-dmarc-agency-contact` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-dmarc-federal-contact` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-dmarc-published` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-dmarc-reject` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-external-sender-warnings` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-forwarding-external-disabled` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-mailbox-audit-enabled` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-sharing-calendar-not-all-domains` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-sharing-contact-not-all-domains` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-smtp-auth-disabled` | hygiene | exchange_online | base-workload: exchange_online |
| `exo-spf-published` | hygiene | exchange_online | base-workload: exchange_online |
| `mdo-anti-spam-no-allowed-domains` | hygiene | exchange_online_protection | EOP anti-spam/connection-filter/transport-rule |
| `mdo-connection-filter-no-ip-allow` | hygiene | exchange_online_protection | EOP anti-spam/connection-filter/transport-rule |
| `mdo-connection-filter-no-safe-list` | hygiene | exchange_online_protection | EOP anti-spam/connection-filter/transport-rule |
| `mdo-outbound-spam-forwarding-block` | hygiene | exchange_online_protection | base-workload: exchange_online_protection |
| `mdo-quarantine-policy` | hygiene | exchange_online_protection | base-workload: exchange_online_protection |
| `mdo-spam-phish-not-inbox` | hygiene | exchange_online_protection | base-workload: exchange_online_protection |
| `mdo-transport-rule-external-forward` | hygiene | exchange_online_protection | EOP anti-spam/connection-filter/transport-rule |
| `pbi-export-controls` | hygiene | power_bi_pro | base-workload: power_bi_pro |
| `pbi-external-invite-disabled` | hygiene | power_bi_pro | base-workload: power_bi_pro |
| `pbi-guest-access-disabled` | hygiene | power_bi_pro | base-workload: power_bi_pro |
| `pbi-premium-capacity-governance` | hygiene | power_bi_premium | base-workload: power_bi_premium |
| `pbi-publish-to-web-disabled` | hygiene | power_bi_pro | base-workload: power_bi_pro |
| `pbi-python-r-visuals-disabled` | hygiene | power_bi_pro | base-workload: power_bi_pro |
| `pbi-resource-key-auth-blocked` | hygiene | power_bi_pro | base-workload: power_bi_pro |
| `pbi-sensitivity-labels-enabled` | hygiene | power_bi_pro | base-workload: power_bi_pro |
| `pbi-sp-api-restricted` | hygiene | power_bi_pro | base-workload: power_bi_pro |
| `pbi-sp-profiles-disabled` | hygiene | power_bi_pro | base-workload: power_bi_pro |
| `pp-dlp-all-environments` | hygiene | power_platform | base-workload: power_platform |
| `pp-dlp-nondefault-envs` | hygiene | power_platform | base-workload: power_platform |
| `pp-env-creation-admin-only` | hygiene | power_platform | base-workload: power_platform |
| `pp-pages-creation-admin-only` | hygiene | power_platform | base-workload: power_platform |
| `pp-share-with-everyone-disabled` | hygiene | power_platform | base-workload: power_platform |
| `pp-tenant-isolation-allowlist` | hygiene | power_platform | base-workload: power_platform |
| `pp-tenant-isolation-enabled` | hygiene | power_platform | base-workload: power_platform |
| `pp-trial-creation-admin-only` | hygiene | power_platform | base-workload: power_platform |
| `spo-anyone-link-expiration` | hygiene | sharepoint_online | base-workload: sharepoint_online |
| `spo-anyone-link-view` | hygiene | sharepoint_online | base-workload: sharepoint_online |
| `spo-default-link-specific` | hygiene | sharepoint_online | base-workload: sharepoint_online |
| `spo-default-link-view` | hygiene | sharepoint_online | base-workload: sharepoint_online |
| `spo-domain-restrictions` | hygiene | sharepoint_online | base-workload: sharepoint_online |
| `spo-onedrive-sharing-limited` | hygiene | onedrive_for_business | base-workload: onedrive_for_business |
| `spo-sharing-capability-limited` | hygiene | sharepoint_online | base-workload: sharepoint_online |
| `spo-unmanaged-device-access` | hygiene | sharepoint_online | base-workload: sharepoint_online |
| `spo-verification-reauth` | hygiene | sharepoint_online | base-workload: sharepoint_online |
| `teams-anonymous-lobby` | hygiene | teams | base-workload: teams |
| `teams-anonymous-start-disabled` | hygiene | teams | base-workload: teams |
| `teams-broadcast-not-always-record` | hygiene | teams | base-workload: teams |
| `teams-custom-apps-governed` | hygiene | teams | base-workload: teams |
| `teams-dialin-lobby` | hygiene | teams | base-workload: teams |
| `teams-email-integration-disabled` | hygiene | teams | base-workload: teams |
| `teams-external-access-per-domain` | hygiene | teams | base-workload: teams |
| `teams-external-control-disabled` | hygiene | teams | base-workload: teams |
| `teams-guest-access-restricted` | hygiene | teams | base-workload: teams |
| `teams-internal-auto-admit` | hygiene | teams | base-workload: teams |
| `teams-microsoft-apps-governed` | hygiene | teams | base-workload: teams |
| `teams-recording-disabled` | hygiene | teams | base-workload: teams |
| `teams-third-party-apps-governed` | hygiene | teams | base-workload: teams |
| `teams-unmanaged-inbound-blocked` | hygiene | teams | base-workload: teams |
| `teams-unmanaged-outbound-blocked` | hygiene | teams | base-workload: teams |
