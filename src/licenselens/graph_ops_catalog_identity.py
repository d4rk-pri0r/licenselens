"""Identity/app Graph operation catalog."""

from __future__ import annotations

from licenselens.collectors.contracts import CloudEnvironment
from licenselens.graph_ops_types import ApiFamily, GraphOperation

_ALL = (
    CloudEnvironment.PUBLIC,
    CloudEnvironment.US_GOV,
    CloudEnvironment.CHINA,
)


def identity_operations() -> tuple[GraphOperation, ...]:
    policy = ("Policy.Read.All",)
    role = ("RoleManagement.Read.Directory",)
    app_read = ("Application.Read.All",)
    app_del = ("Application.Read.All", "Directory.Read.All")
    entitlement = ("EntitlementManagement.Read.All",)

    def op(
        operation_id: str,
        path: str,
        evidence_key: str,
        app: tuple[str, ...],
        delegated: tuple[str, ...],
        *,
        family: ApiFamily = ApiFamily.GRAPH,
        is_collection: bool = True,
        max_pages: int = 30,
        clouds: tuple[CloudEnvironment, ...] = _ALL,
        description: str = "",
    ) -> GraphOperation:
        return GraphOperation(
            operation_id=operation_id,
            family=family,
            path=path,
            evidence_key=evidence_key,
            application_permissions=app,
            delegated_permissions=delegated,
            supported_clouds=clouds,
            is_collection=is_collection,
            max_pages=max_pages,
            description=description,
        )

    return (
        op(
            "auth_methods_policy",
            "/policies/authenticationMethodsPolicy",
            "graph.auth_methods_policy",
            policy,
            policy,
            is_collection=False,
            description="Tenant authentication methods policy",
        ),
        op(
            "auth_strength_policies",
            "/policies/authenticationStrengthPolicies",
            "graph.auth_strength_policies",
            policy,
            policy,
            description="Authentication strength policies",
        ),
        op(
            "auth_method_configurations",
            "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations",
            "graph.auth_method_configurations",
            policy,
            policy,
            description="Per-method authentication configurations",
        ),
        op(
            "ca_named_locations",
            "/identity/conditionalAccess/namedLocations",
            "graph.ca_named_locations",
            policy,
            policy,
            description="CA named locations (IP / country)",
        ),
        op(
            "ca_policies",
            "/identity/conditionalAccess/policies",
            "graph.ca_policies",
            policy,
            policy,
            description="Conditional Access policies",
        ),
        op(
            "pim_role_management_policies",
            "/policies/roleManagementPolicies",
            "graph.pim_role_management_policies",
            role,
            role,
            max_pages=20,
            description="PIM role management policies",
        ),
        op(
            "pim_role_management_policy_assignments",
            "/policies/roleManagementPolicyAssignments",
            "graph.pim_role_management_policy_assignments",
            role,
            role,
            max_pages=20,
            description="PIM role management policy assignments",
        ),
        op(
            "pim_role_eligibility_schedules",
            "/roleManagement/directory/roleEligibilitySchedules",
            "graph.role_eligibilities",
            role,
            role,
            max_pages=20,
            description="PIM eligible role schedules",
        ),
        op(
            "pim_role_assignments",
            "/roleManagement/directory/roleAssignments",
            "graph.role_assignments",
            role,
            role,
            max_pages=30,
            description="Directory role assignments",
        ),
        op(
            "entitlement_access_packages",
            "/identityGovernance/entitlementManagement/accessPackages",
            "graph.access_packages",
            entitlement,
            entitlement,
            max_pages=10,
            description="Entitlement Management access packages",
        ),
        op(
            "risky_service_principals",
            "/identityProtection/riskyServicePrincipals",
            "graph.risky_service_principals",
            ("IdentityRiskyServicePrincipal.Read.All",),
            ("IdentityRiskyServicePrincipal.Read.All",),
            max_pages=10,
            description="Risky service principals (workload identity protection)",
        ),
        op(
            "applications",
            "/applications",
            "graph.applications",
            app_read,
            app_del,
            max_pages=40,
            description="App registrations",
        ),
        op(
            "service_principals",
            "/servicePrincipals",
            "graph.service_principals",
            app_read,
            app_del,
            max_pages=40,
            description="Enterprise applications / service principals",
        ),
        op(
            "oauth2_permission_grants",
            "/oauth2PermissionGrants",
            "graph.oauth2_permission_grants",
            ("DelegatedPermissionGrant.Read.All", "Directory.Read.All"),
            ("Directory.Read.All",),
            max_pages=40,
            description="Delegated OAuth2 permission grants",
        ),
        op(
            "cross_tenant_access_policy",
            "/policies/crossTenantAccessPolicy",
            "graph.cross_tenant_access_policy",
            policy,
            policy,
            is_collection=False,
            description="Cross-tenant access policy root",
        ),
        op(
            "cross_tenant_access_default",
            "/policies/crossTenantAccessPolicy/default",
            "graph.cross_tenant_access_default",
            policy,
            policy,
            is_collection=False,
            description="Default cross-tenant access settings",
        ),
        op(
            "cross_tenant_access_partners",
            "/policies/crossTenantAccessPolicy/partners",
            "graph.cross_tenant_access_partners",
            policy,
            policy,
            description="Partner cross-tenant access settings",
        ),
        op(
            "guest_users",
            "/users",
            "graph.guest_users",
            ("User.Read.All", "Directory.Read.All"),
            ("User.Read.All", "Directory.Read.All"),
            max_pages=40,
            description="Guest users (filter applied by collector)",
        ),
        op(
            "authorization_policy",
            "/policies/authorizationPolicy",
            "graph.authorization_policy",
            policy,
            policy,
            is_collection=False,
            description="Tenant authorization policy",
        ),
        op(
            "admin_consent_request_policy",
            "/policies/adminConsentRequestPolicy",
            "graph.admin_consent_request_policy",
            policy,
            policy,
            is_collection=False,
            description="Admin consent request workflow policy",
        ),
        op(
            "domains",
            "/domains",
            "graph.domains",
            ("Domain.Read.All", "Directory.Read.All"),
            ("Domain.Read.All", "Directory.Read.All"),
            max_pages=10,
            description="Verified domains including password validity",
        ),
    )
