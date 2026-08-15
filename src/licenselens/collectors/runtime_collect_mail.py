"""Mail, DNS, collaboration, and Power Platform runtime collectors."""

from __future__ import annotations

from licenselens.collectors.collaboration_demo import demo_collaboration_evidence
from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.dns_records import (
    DEMO_DNS_RECORDS,
    collect_dns_evidence,
    system_resolver,
)
from licenselens.collectors.exchange_demo import demo_exchange_evidence
from licenselens.collectors.power_data_demo import demo_power_data_evidence
from licenselens.collectors.runtime_envelopes import envelope_value, error, graph_failure, ok
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import CollectionContext


def collect_exchange_runtime(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "exchange_bundle"
    if ctx.is_dry_run:
        payload = demo_exchange_evidence()
        return ok(key, payload, source="demo")
    try:
        from licenselens.collectors.exchange import (
            ExchangeCollectOptions,
            collect_exchange_evidence,
        )
        from licenselens.collectors.exchange_models import EXCHANGE_ADAPTERS

        exo = collect_exchange_evidence(ExchangeCollectOptions(adapters=EXCHANGE_ADAPTERS))
        if not exo.get("exchange_threat_usable"):
            ctx.warn(
                "Exchange Online PowerShell threat policies were not fully readable; "
                "MDO check stays skipped unless --allow-email-proxy is set."
            )
        return ok(key, exo, source="powershell.exchange")
    except Exception as exc:  # noqa: BLE001
        ctx.warn(f"Exchange Online PowerShell collectors unavailable: {exc}")
        return error(key, str(exc))


def collect_dns_runtime(ctx: ScanCollectionContext, pc: CollectionContext) -> EvidenceEnvelope:
    key = "dns_records"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_DNS_RECORDS), source="demo")
    try:
        tenant_domains = list(envelope_value(pc, "domains") or [])
        records = collect_dns_evidence(tenant_domains, system_resolver())
        return ok(key, records, source="dns.system")
    except Exception as exc:  # noqa: BLE001
        ctx.warn(f"DNS email-authentication checks failed: {exc}")
        return error(key, str(exc))


def collect_collaboration_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "collaboration_bundle"
    if ctx.is_dry_run:
        return ok(key, demo_collaboration_evidence(), source="demo")
    try:
        from licenselens.collectors.collaboration import (
            CollaborationCollectOptions,
            collect_collaboration_evidence,
        )

        collab = collect_collaboration_evidence(CollaborationCollectOptions())
        return ok(key, collab, source="powershell.collaboration")
    except Exception as exc:  # noqa: BLE001
        ctx.warn(f"Collaboration PowerShell collectors unavailable: {exc}")
        return error(key, str(exc))


def collect_power_data_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "power_data_bundle"
    if ctx.is_dry_run:
        return ok(key, demo_power_data_evidence(), source="demo")
    try:
        from licenselens.collectors.power_data import (
            PowerDataCollectOptions,
            collect_power_data_evidence,
        )

        power = collect_power_data_evidence(PowerDataCollectOptions())
        return ok(key, power, source="powershell.power_data")
    except Exception as exc:  # noqa: BLE001
        ctx.warn(f"Power Platform / Power BI PowerShell collectors unavailable: {exc}")
        return error(key, str(exc))
