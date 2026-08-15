"""Bootstrap all evaluator bindings into a registration catalog."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.bindings.azure_selective import register_azure_selective
from licenselens.evaluators.bindings.collaboration_sharing import register_collaboration_sharing
from licenselens.evaluators.bindings.collaboration_sharing_links import (
    register_collaboration_sharing_links,
)
from licenselens.evaluators.bindings.collaboration_teams_access import (
    register_collaboration_teams_access,
)
from licenselens.evaluators.bindings.collaboration_teams_apps import (
    register_collaboration_teams_apps,
)
from licenselens.evaluators.bindings.collaboration_teams_meeting import (
    register_collaboration_teams_meeting,
)
from licenselens.evaluators.bindings.defender import register_defender
from licenselens.evaluators.bindings.defender_endpoint import register_defender_endpoint
from licenselens.evaluators.bindings.defender_mdo import register_defender_mdo
from licenselens.evaluators.bindings.endpoint_intune import register_endpoint_intune
from licenselens.evaluators.bindings.endpoint_intune_policy import register_endpoint_intune_policy
from licenselens.evaluators.bindings.endpoint_mde_xdr import register_endpoint_mde_xdr
from licenselens.evaluators.bindings.exchange_email_auth import register_exchange_email_auth
from licenselens.evaluators.bindings.exchange_mailflow import register_exchange_mailflow
from licenselens.evaluators.bindings.identity_access import register_identity_access
from licenselens.evaluators.bindings.identity_apps_consent import register_identity_apps_consent
from licenselens.evaluators.bindings.identity_apps_credentials import (
    register_identity_apps_credentials,
)
from licenselens.evaluators.bindings.identity_auth_methods import register_identity_auth_methods
from licenselens.evaluators.bindings.identity_ca_coverage import register_identity_ca_coverage
from licenselens.evaluators.bindings.identity_ca_risk import register_identity_ca_risk
from licenselens.evaluators.bindings.identity_governance import register_identity_governance
from licenselens.evaluators.bindings.identity_guests import register_identity_guests
from licenselens.evaluators.bindings.identity_manual import register_identity_manual
from licenselens.evaluators.bindings.identity_pim_rules import register_identity_pim_rules
from licenselens.evaluators.bindings.identity_privileged import register_identity_privileged
from licenselens.evaluators.bindings.identity_privileged_extra import (
    register_identity_privileged_extra,
)
from licenselens.evaluators.bindings.identity_risk import register_identity_risk
from licenselens.evaluators.bindings.power_bi import register_power_bi
from licenselens.evaluators.bindings.power_platform_env import register_power_platform_env
from licenselens.evaluators.bindings.power_platform_tenant import register_power_platform_tenant
from licenselens.evaluators.bindings.purview import register_purview
from licenselens.evaluators.bindings.purview_governance import register_purview_governance
from licenselens.evaluators.bindings.purview_manual import register_purview_manual
from licenselens.evaluators.bindings.security_suite_dlp import register_security_suite_dlp
from licenselens.evaluators.bindings.security_suite_spam import register_security_suite_spam
from licenselens.evaluators.bindings.security_suite_threat import register_security_suite_threat
from licenselens.evaluators.bindings.sentinel import register_sentinel
from licenselens.evaluators.bindings.sentinel_extended import register_sentinel_extended


def register_all_evaluators(catalog: RegistrationCatalog) -> None:
    register_azure_selective(catalog)
    register_collaboration_sharing(catalog)
    register_collaboration_sharing_links(catalog)
    register_collaboration_teams_access(catalog)
    register_collaboration_teams_apps(catalog)
    register_collaboration_teams_meeting(catalog)
    register_defender(catalog)
    register_defender_endpoint(catalog)
    register_defender_mdo(catalog)
    register_endpoint_intune(catalog)
    register_endpoint_intune_policy(catalog)
    register_endpoint_mde_xdr(catalog)
    register_exchange_email_auth(catalog)
    register_exchange_mailflow(catalog)
    register_identity_access(catalog)
    register_identity_apps_consent(catalog)
    register_identity_apps_credentials(catalog)
    register_identity_auth_methods(catalog)
    register_identity_ca_coverage(catalog)
    register_identity_ca_risk(catalog)
    register_identity_governance(catalog)
    register_identity_guests(catalog)
    register_identity_manual(catalog)
    register_identity_pim_rules(catalog)
    register_identity_privileged(catalog)
    register_identity_privileged_extra(catalog)
    register_identity_risk(catalog)
    register_power_bi(catalog)
    register_power_platform_env(catalog)
    register_power_platform_tenant(catalog)
    register_purview(catalog)
    register_purview_governance(catalog)
    register_purview_manual(catalog)
    register_security_suite_dlp(catalog)
    register_security_suite_spam(catalog)
    register_security_suite_threat(catalog)
    register_sentinel(catalog)
    register_sentinel_extended(catalog)
