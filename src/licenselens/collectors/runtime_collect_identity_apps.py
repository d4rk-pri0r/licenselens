"""Identity apps, guests, PIM, and profile-sourced runtime collectors."""

from __future__ import annotations

from licenselens.collectors.applications import (
    DEMO_APPLICATIONS_BUNDLE,
    collect_applications_bundle,
)
from licenselens.collectors.auth_methods import (
    DEMO_AUTH_METHODS_BUNDLE,
    collect_auth_methods_bundle,
)
from licenselens.collectors.authorization_policy import (
    DEMO_AUTHORIZATION_BUNDLE,
    collect_authorization_bundle,
)
from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.domains import DEMO_DOMAINS, collect_domains
from licenselens.collectors.guests import DEMO_GUESTS_BUNDLE, collect_guests_bundle
from licenselens.collectors.pim_policies import (
    DEMO_PIM_POLICIES_BUNDLE,
    collect_pim_policies_bundle,
)
from licenselens.collectors.runtime_envelopes import graph_failure, ok
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import CollectionContext
from licenselens.errors import GraphError


def collect_auth_methods_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "auth_methods_bundle"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_AUTH_METHODS_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_auth_methods_bundle(ctx.client)
        return ok(key, bundle, source="graph.policies.authenticationMethodsPolicy")
    except GraphError as exc:
        return graph_failure(
            key, exc, f"Authentication methods policy could not be read: {exc}", ctx
        )


def collect_applications_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "applications_bundle"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_APPLICATIONS_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_applications_bundle(ctx.client)
        return ok(key, bundle, source="graph.applications")
    except GraphError as exc:
        return graph_failure(key, exc, f"Applications inventory could not be read: {exc}", ctx)


def collect_authorization_policy_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "authorization_policy"
    if ctx.is_dry_run:
        return ok(
            key,
            dict(DEMO_AUTHORIZATION_BUNDLE["authorization_policy"]),
            source="demo",
        )
    assert ctx.client is not None
    try:
        authz = collect_authorization_bundle(ctx.client)
        ctx.extras["_admin_consent_request_policy_cache"] = (
            authz.get("admin_consent_request_policy") or {}
        )
        return ok(
            key,
            authz.get("authorization_policy") or {},
            source="graph.policies.authorizationPolicy",
        )
    except GraphError as exc:
        return graph_failure(key, exc, f"Authorization policy could not be read: {exc}", ctx)


def collect_admin_consent_policy_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "admin_consent_request_policy"
    if ctx.is_dry_run:
        return ok(
            key,
            dict(DEMO_AUTHORIZATION_BUNDLE["admin_consent_request_policy"]),
            source="demo",
        )
    cached = ctx.extras.get("_admin_consent_request_policy_cache")
    if cached is not None:
        return ok(key, dict(cached), source="graph.policies.adminConsentRequestPolicy")
    assert ctx.client is not None
    try:
        authz = collect_authorization_bundle(ctx.client)
        return ok(
            key,
            authz.get("admin_consent_request_policy") or {},
            source="graph.policies.adminConsentRequestPolicy",
        )
    except GraphError as exc:
        return graph_failure(key, exc, f"Authorization policy could not be read: {exc}", ctx)


def collect_guests_runtime(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "guests_bundle"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_GUESTS_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_guests_bundle(ctx.client)
        return ok(key, bundle, source="graph.policies.crossTenantAccess")
    except GraphError as exc:
        return graph_failure(
            key, exc, f"Guest / cross-tenant settings could not be read: {exc}", ctx
        )


def collect_pim_policies_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "pim_policies_bundle"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_PIM_POLICIES_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_pim_policies_bundle(ctx.client)
        return ok(key, bundle, source="graph.roleManagement.policies")
    except GraphError as exc:
        return graph_failure(
            key, exc, f"PIM role management policies could not be read: {exc}", ctx
        )


def collect_domains_runtime(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "domains"
    if ctx.is_dry_run:
        return ok(key, list(DEMO_DOMAINS), source="demo", items=len(DEMO_DOMAINS))
    assert ctx.client is not None
    try:
        domains = collect_domains(ctx.client)
        return ok(key, domains, source="graph.domains", items=len(domains))
    except GraphError as exc:
        return graph_failure(key, exc, f"Domain password settings could not be read: {exc}", ctx)


def collect_break_glass_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "break_glass_principal_ids"
    value = list(ctx.extras.get("break_glass_principal_ids") or [])
    return ok(key, value, source="profile", items=len(value))


def collect_approved_guest_domains_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "approved_guest_domains"
    value = list(ctx.extras.get("approved_guest_domains") or [])
    return ok(key, value, source="profile", items=len(value))
