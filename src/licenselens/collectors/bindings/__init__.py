"""Typed collector registrations binding CollectorSpec factories."""

from __future__ import annotations

from collections.abc import Sequence

from licenselens.collectors.contracts import (
    CloudEnvironment,
    CollectorId,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
)
from licenselens.engine.planner import CollectionContext, CollectorSpec
from licenselens.engine.registration import RegistrationCatalog
from licenselens.engine.registry import Backend


def _stub_collect(key: EvidenceKey):
    def _collect(_context: CollectionContext) -> EvidenceEnvelope:
        return EvidenceEnvelope(
            key=key,
            health=EvidenceHealth.UNAVAILABLE,
            reason="collector factory registered; live collection wired by planner runtime",
        )

    return _collect


def _factory_for(collector_id: str, produces: tuple[str, ...], timeout: int):
    def factory() -> Sequence[CollectorSpec]:
        specs: list[CollectorSpec] = []
        for index, source_id in enumerate(produces):
            key = EvidenceKey(source_id)
            depends = tuple(EvidenceKey(p) for p in produces[:index])
            specs.append(
                CollectorSpec(
                    collector_id=CollectorId(f"{collector_id}:{source_id}"),
                    produces=key,
                    collect=_stub_collect(key),
                    depends_on=depends,
                    supported_clouds=(CloudEnvironment.PUBLIC,),
                    timeout_seconds=timeout,
                )
            )
        return tuple(specs)

    factory.__name__ = f"factory_{collector_id}"
    factory.__qualname__ = f"factory_{collector_id}"
    factory.__module__ = "licenselens.collectors.bindings"
    return factory


def register_all_collectors(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.collectors.bindings")
    try:
        _register_one(
            catalog,
            collector_id="collaboration_collector",
            backend=Backend.NOOP,
            permissions=(),
            dependencies=("collaboration_bundle",),
            timeout_seconds=120,
        )
        _register_one(
            catalog,
            collector_id="defender_pricings_collector",
            backend=Backend.ARM,
            permissions=(),
            dependencies=("defender_for_cloud_pricings",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="exchange_collector",
            backend=Backend.NOOP,
            permissions=(),
            dependencies=("exchange_bundle", "dns_records"),
            timeout_seconds=120,
        )
        _register_one(
            catalog,
            collector_id="graph_access_reviews",
            backend=Backend.GRAPH,
            permissions=("AccessReview.Read.All",),
            dependencies=("access_review_definitions",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_applications",
            backend=Backend.GRAPH,
            permissions=("Application.Read.All", "Directory.Read.All"),
            dependencies=("applications_bundle",),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="graph_auth_methods",
            backend=Backend.GRAPH,
            permissions=("Policy.Read.All",),
            dependencies=("auth_methods_bundle",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_authorization",
            backend=Backend.GRAPH,
            permissions=("Policy.Read.All",),
            dependencies=("authorization_policy", "admin_consent_request_policy"),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_ca",
            backend=Backend.GRAPH,
            permissions=("Policy.Read.All",),
            dependencies=("ca_policies", "break_glass_principal_ids"),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_domains",
            backend=Backend.GRAPH,
            permissions=("Domain.Read.All", "Directory.Read.All"),
            dependencies=("domains",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_entitlement_management",
            backend=Backend.GRAPH,
            permissions=("EntitlementManagement.Read.All",),
            dependencies=("access_packages",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_guests",
            backend=Backend.GRAPH,
            permissions=("Policy.Read.All", "User.Read.All"),
            dependencies=("guests_bundle", "approved_guest_domains", "authorization_policy"),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="graph_identity_protection",
            backend=Backend.GRAPH,
            permissions=("Policy.Read.All",),
            dependencies=("ca_policies", "break_glass_principal_ids"),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_mdo",
            backend=Backend.NOOP,
            permissions=(),
            dependencies=("secure_score_controls",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_pim",
            backend=Backend.GRAPH,
            permissions=("RoleManagement.Read.Directory",),
            dependencies=("role_assignments", "role_eligibilities"),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_pim_policies",
            backend=Backend.GRAPH,
            permissions=("RoleManagement.Read.Directory",),
            dependencies=("pim_policies_bundle",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_security_defaults",
            backend=Backend.GRAPH,
            permissions=("Policy.Read.All",),
            dependencies=("security_defaults_policy",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="graph_signins_roles",
            backend=Backend.GRAPH,
            permissions=(
                "Directory.Read.All",
                "AuditLog.Read.All",
                "RoleManagement.Read.Directory",
            ),
            dependencies=("role_assignments", "recent_signin_user_ids", "principal_directory"),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="intune_collector",
            backend=Backend.GRAPH,
            permissions=(
                "DeviceManagementConfiguration.Read.All",
                "DeviceManagementManagedDevices.Read.All",
            ),
            dependencies=("intune_bundle",),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="manual_identity",
            backend=Backend.NOOP,
            permissions=(),
            dependencies=("break_glass_principal_ids",),
            timeout_seconds=5,
        )
        _register_one(
            catalog,
            collector_id="mde_health_collector",
            backend=Backend.MDE,
            permissions=(),
            dependencies=("mde_health",),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="mde_onboarding",
            backend=Backend.MDE,
            permissions=(),
            dependencies=("mde_summary",),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="mdi_sensors",
            backend=Backend.PROXY,
            permissions=("SecurityEvents.Read.All",),
            dependencies=("secure_score_controls",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="power_data_collector",
            backend=Backend.NOOP,
            permissions=(),
            dependencies=("power_data_bundle",),
            timeout_seconds=120,
        )
        _register_one(
            catalog,
            collector_id="purview_dlp_collector",
            backend=Backend.PROXY,
            permissions=("SecurityEvents.Read.All",),
            dependencies=("purview_dlp",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="security_alerts_collector",
            backend=Backend.GRAPH,
            permissions=("SecurityIncident.Read.All", "SecurityAlert.Read.All"),
            dependencies=("security_alerts_bundle",),
            timeout_seconds=30,
        )
        _register_one(
            catalog,
            collector_id="sentinel_analytics",
            backend=Backend.ARM,
            permissions=(),
            dependencies=("sentinel_rules",),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="sentinel_automation_rules_collector",
            backend=Backend.ARM,
            permissions=(),
            dependencies=("sentinel_automation_rules",),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="sentinel_data_connectors_collector",
            backend=Backend.ARM,
            permissions=(),
            dependencies=("sentinel_data_connectors",),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="sentinel_ueba_collector",
            backend=Backend.ARM,
            permissions=(),
            dependencies=("sentinel_ueba",),
            timeout_seconds=45,
        )
        _register_one(
            catalog,
            collector_id="sentinel_workspace_collector",
            backend=Backend.ARM,
            permissions=(),
            dependencies=("sentinel_workspace",),
            timeout_seconds=45,
        )
    finally:
        catalog.exit_module("licenselens.collectors.bindings")


def _register_one(
    catalog: RegistrationCatalog,
    *,
    collector_id: str,
    backend: Backend,
    permissions: tuple[str, ...],
    dependencies: tuple[str, ...],
    timeout_seconds: int,
) -> None:
    catalog.add_collector(
        collector_id=collector_id,
        factory=_factory_for(collector_id, dependencies, timeout_seconds),
        output_model="EvidenceBundle",
        backend=backend,
        permissions=permissions,
        cloud_support=("public",),
        cache_key=f"collector:{collector_id}",
        timeout_seconds=timeout_seconds,
        dependencies=dependencies,
    )
