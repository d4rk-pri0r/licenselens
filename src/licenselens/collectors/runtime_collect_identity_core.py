"""Core identity runtime collectors (CA, roles, sign-ins, defaults, reviews)."""

from __future__ import annotations

from licenselens.collectors.access_reviews import (
    DEMO_ACCESS_REVIEWS,
    collect_access_review_definitions,
)
from licenselens.collectors.conditional_access import DEMO_CA_POLICIES, collect_ca_policies
from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.entitlement_management import (
    DEMO_ACCESS_PACKAGES,
    collect_access_packages,
)
from licenselens.collectors.privileged_roles import (
    DEMO_PRINCIPAL_DIRECTORY,
    DEMO_RECENT_SIGNIN_USER_IDS,
    DEMO_ROLE_ASSIGNMENTS,
    DEMO_ROLE_ELIGIBILITIES,
    collect_role_assignments,
    collect_role_eligibility_schedules,
    privileged_principal_ids,
)
from licenselens.collectors.runtime_envelopes import envelope_value, graph_failure, ok
from licenselens.collectors.security_defaults import (
    DEMO_SECURITY_DEFAULTS,
    collect_security_defaults_policy,
)
from licenselens.collectors.signins import (
    collect_directory_objects_by_ids,
    collect_recent_success_signin_user_ids,
)
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import CollectionContext
from licenselens.errors import GraphError


def collect_ca_policies_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "ca_policies"
    if ctx.is_dry_run:
        return ok(key, list(DEMO_CA_POLICIES), source="demo", items=len(DEMO_CA_POLICIES))
    assert ctx.client is not None
    try:
        policies = collect_ca_policies(ctx.client)
        return ok(key, policies, source="graph.identity", items=len(policies))
    except GraphError as exc:
        return graph_failure(
            key,
            exc,
            f"Conditional Access policies could not be read: {exc}",
            ctx,
        )


def collect_role_assignments_runtime(
    ctx: ScanCollectionContext,
    _pc: CollectionContext,
) -> EvidenceEnvelope:
    key = "role_assignments"
    if ctx.is_dry_run:
        return ok(
            key,
            list(DEMO_ROLE_ASSIGNMENTS),
            source="demo",
            items=len(DEMO_ROLE_ASSIGNMENTS),
        )
    assert ctx.client is not None
    try:
        assignments = collect_role_assignments(ctx.client)
        return ok(key, assignments, source="graph.directoryRoles", items=len(assignments))
    except GraphError as exc:
        return graph_failure(
            key,
            exc,
            f"Directory role assignments could not be read: {exc}",
            ctx,
        )


def collect_role_eligibilities_runtime(
    ctx: ScanCollectionContext,
    _pc: CollectionContext,
) -> EvidenceEnvelope:
    key = "role_eligibilities"
    if ctx.is_dry_run:
        return ok(
            key, list(DEMO_ROLE_ELIGIBILITIES), source="demo", items=len(DEMO_ROLE_ELIGIBILITIES)
        )
    assert ctx.client is not None
    try:
        elig = collect_role_eligibility_schedules(ctx.client)
        return ok(key, elig, source="graph.roleManagement", items=len(elig))
    except GraphError as exc:
        # PIM eligibility may 403 if not licensed / not consented — treat as empty + warn.
        ctx.warn(f"PIM role eligibility schedules could not be read (treating as none): {exc}")
        return ok(key, [], source="graph.roleManagement", items=0)


def collect_recent_signins_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "recent_signin_user_ids"
    if ctx.is_dry_run:
        ids = set(DEMO_RECENT_SIGNIN_USER_IDS)
        ctx.extras["signin_lookback_days"] = 90
        ctx.extras["signin_sample_truncated"] = False
        return ok(key, ids, source="demo", items=len(ids))
    assert ctx.client is not None
    max_pages = 15
    try:
        signin_ids = collect_recent_success_signin_user_ids(
            ctx.client, lookback_days=90, max_pages=max_pages
        )
        truncated = len(signin_ids) >= max_pages * 400
        ctx.extras["signin_lookback_days"] = 90
        ctx.extras["signin_sample_truncated"] = truncated
        return ok(
            key,
            signin_ids,
            source="graph.auditLogs.signIns",
            items=len(signin_ids),
            truncated=truncated,
        )
    except GraphError as exc:
        return graph_failure(key, exc, f"Sign-in logs could not be read: {exc}", ctx)


def collect_principal_directory_runtime(
    ctx: ScanCollectionContext, pc: CollectionContext
) -> EvidenceEnvelope:
    key = "principal_directory"
    if ctx.is_dry_run:
        return ok(
            key,
            dict(DEMO_PRINCIPAL_DIRECTORY),
            source="demo",
            items=len(DEMO_PRINCIPAL_DIRECTORY),
        )
    assert ctx.client is not None
    assignments = list(envelope_value(pc, "role_assignments") or [])
    principal_ids = sorted(privileged_principal_ids(assignments))
    if not principal_ids:
        return ok(key, {}, source="graph.directoryObjects", items=0)
    try:
        directory = collect_directory_objects_by_ids(ctx.client, principal_ids)
        return ok(key, directory, source="graph.directoryObjects", items=len(directory))
    except GraphError as exc:
        return graph_failure(key, exc, f"Privileged principal directory lookup failed: {exc}", ctx)


def collect_security_defaults_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "security_defaults_policy"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_SECURITY_DEFAULTS), source="demo")
    assert ctx.client is not None
    try:
        policy = collect_security_defaults_policy(ctx.client)
        return ok(key, policy, source="graph.policies.identitySecurityDefaultsEnforcementPolicy")
    except GraphError as exc:
        return graph_failure(key, exc, f"Security defaults policy could not be read: {exc}", ctx)


def collect_access_reviews_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "access_review_definitions"
    if ctx.is_dry_run:
        return ok(key, list(DEMO_ACCESS_REVIEWS), source="demo", items=len(DEMO_ACCESS_REVIEWS))
    assert ctx.client is not None
    try:
        definitions = collect_access_review_definitions(ctx.client)
        return ok(key, definitions, source="graph.identityGovernance", items=len(definitions))
    except GraphError as exc:
        return graph_failure(key, exc, f"Access review definitions could not be read: {exc}", ctx)


def collect_access_packages_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "access_packages"
    if ctx.is_dry_run:
        return ok(key, list(DEMO_ACCESS_PACKAGES), source="demo", items=len(DEMO_ACCESS_PACKAGES))
    assert ctx.client is not None
    try:
        packages = collect_access_packages(ctx.client)
        return ok(
            key,
            packages,
            source="graph.identityGovernance.entitlementManagement",
            items=len(packages),
        )
    except GraphError as exc:
        return graph_failure(key, exc, f"Entitlement access packages could not be read: {exc}", ctx)
