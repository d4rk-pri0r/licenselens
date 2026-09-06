"""Offline execution preview: entitlements, checks, collectors, no tenant writes."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS, AuthContext, AuthMode
from licenselens.catalog.loader import load_capabilities, resolve_owned_capabilities
from licenselens.collectors.contracts import CloudEnvironment
from licenselens.collectors.runtime_specs import (
    build_runtime_collector_specs,
    check_requirements_for,
)
from licenselens.collectors.skus import demo_skus
from licenselens.engine._registry_source_meta import SOURCE_META
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import EvidencePlanner
from licenselens.engine.profiles import ResolvedProfile
from licenselens.engine.registry import Backend, default_registry
from licenselens.engine.runner_collect import select_checks
from licenselens.engine.runner_findings import eligible
from licenselens.graph_ops import iter_operations
from licenselens.models import CheckPack, CheckTier, SubscribedSku, Workload
from licenselens.schema_contracts import EvaluationMode

NEVER_DO: tuple[str, ...] = (
    "No writes — collectors only call read APIs.",
    "No Graph beta unless --allow-preview is set on a live scan.",
    "No KQL beyond the single allowlisted Usage meter (usage_by_datatype_7d).",
)


@dataclass(frozen=True, slots=True)
class PlanCollectorRow:
    collector_id: str
    produces: str
    backend: str
    permissions: tuple[str, ...]
    path: str
    max_pages: int
    timeout_seconds: int
    powershell_module: str = ""


@dataclass(frozen=True, slots=True)
class PlanPreview:
    owned: tuple[str, ...]
    not_owned: tuple[str, ...]
    unknown_consumption: tuple[str, ...]
    will_evaluate: tuple[str, ...]
    not_licensed: tuple[str, ...]
    manual: tuple[str, ...]
    not_implemented: tuple[str, ...]
    collectors: tuple[PlanCollectorRow, ...]
    graph_permissions: tuple[str, ...]
    arm_rbac: tuple[str, ...]
    mde_permissions: tuple[str, ...]
    estimated_max_requests: int
    never_do: tuple[str, ...] = NEVER_DO
    sku_part_numbers: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "owned": list(self.owned),
            "not_owned": list(self.not_owned),
            "unknown_consumption": list(self.unknown_consumption),
            "will_evaluate": list(self.will_evaluate),
            "not_licensed": list(self.not_licensed),
            "manual": list(self.manual),
            "not_implemented": list(self.not_implemented),
            "collectors": [
                {
                    "collector_id": row.collector_id,
                    "produces": row.produces,
                    "backend": row.backend,
                    "permissions": list(row.permissions),
                    "path": row.path,
                    "max_pages": row.max_pages,
                    "timeout_seconds": row.timeout_seconds,
                    "powershell_module": row.powershell_module,
                }
                for row in self.collectors
            ],
            "graph_permissions": list(self.graph_permissions),
            "arm_rbac": list(self.arm_rbac),
            "mde_permissions": list(self.mde_permissions),
            "estimated_max_requests": self.estimated_max_requests,
            "never_do": list(self.never_do),
            "sku_part_numbers": list(self.sku_part_numbers),
        }


def skus_from_assume(part_numbers: Sequence[str]) -> list[SubscribedSku]:
    """Build SKUs for --assume-sku. SPE_E5 uses the demo catalog (full plans)."""

    wanted = [name.strip().upper() for name in part_numbers if name and name.strip()]
    if not wanted:
        return demo_skus()
    if wanted == ["SPE_E5"] or set(wanted) == {"SPE_E5"}:
        return demo_skus()
    demo_by = {sku.sku_part_number.upper(): sku for sku in demo_skus()}
    out: list[SubscribedSku] = []
    for name in wanted:
        if name in demo_by:
            out.append(demo_by[name])
        else:
            out.append(
                SubscribedSku(
                    sku_id=f"assume-{name.lower()}",
                    sku_part_number=name,
                    capability_status="Enabled",
                    prepaid_units=1,
                    consumed_units=1,
                    service_plans=[],
                )
            )
    return out


def build_plan_preview(
    *,
    skus: list[SubscribedSku] | None = None,
    profile: ResolvedProfile | None = None,
    workloads: list[Workload] | None = None,
    packs: list[CheckPack] | None = None,
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
    tiers: list[CheckTier] | None = None,
) -> PlanPreview:
    capabilities = load_capabilities()
    sku_list = list(skus if skus is not None else demo_skus())
    owned_list = resolve_owned_capabilities(capabilities, sku_list)
    owned = set(owned_list)
    all_cap_ids = [cap.id for cap in capabilities]
    not_owned = tuple(sorted(cid for cid in all_cap_ids if cid not in owned))
    unknown_consumption = tuple(
        sorted(
            cap.id
            for cap in capabilities
            if getattr(cap, "entitlement_kind", None)
            and str(cap.entitlement_kind) == "consumption"
            and cap.id not in owned
        )
    )

    checks = select_checks(profile=profile, workloads=workloads, tiers=tiers)
    if packs:
        pack_set = set(packs)
        checks = [check for check in checks if check.pack in pack_set]

    registry = default_registry()
    will: list[str] = []
    not_licensed: list[str] = []
    manual: list[str] = []
    not_implemented: list[str] = []
    for check in checks:
        if not eligible(check, owned):
            not_licensed.append(check.id)
            continue
        try:
            entry = registry.evaluator_for(check.id)
        except KeyError:
            not_implemented.append(check.id)
            continue
        mode = entry.evaluation_mode
        if mode is EvaluationMode.MANUAL:
            manual.append(check.id)
        elif mode is EvaluationMode.UNSUPPORTED:
            not_implemented.append(check.id)
        else:
            will.append(check.id)

    dummy_auth = AuthContext(mode=AuthMode.DRY_RUN)
    ctx = ScanCollectionContext(
        scan_mode="dry_run",
        auth=dummy_auth,
        client=None,
        skus=sku_list,
        warnings=[],
    )
    specs = build_runtime_collector_specs(ctx, registry)
    requirements = check_requirements_for(
        will,
        registry,
        profile_ids=tuple(profile.profile_ids) if profile is not None else (),
    )
    planner = EvidencePlanner(collectors=specs, cloud=cloud)
    plan = planner.build_plan(requirements)

    ops_by_key: dict[str, list[Any]] = {}
    for op in iter_operations():
        ops_by_key.setdefault(op.evidence_key, []).append(op)
        # also index by trailing path fragment
        ops_by_key.setdefault(op.path, []).append(op)

    rows: list[PlanCollectorRow] = []
    graph_perms: set[str] = set()
    arm_rbac: set[str] = set()
    mde_perms: set[str] = set()
    estimated = 0
    for step in plan.steps:
        key = str(step.collector.produces)
        meta = SOURCE_META.get(key)
        backend = meta[0] if meta else Backend.NOOP
        permissions = meta[1] if meta else ()
        timeout = (
            step.collector.timeout_seconds
            if step.collector.timeout_seconds is not None
            else (meta[3] if meta else 30)
        )
        path = ""
        max_pages = 1
        matching_ops = [
            op
            for op in iter_operations()
            if op.evidence_key.endswith(key) or key in op.evidence_key
        ]
        if matching_ops:
            op = matching_ops[0]
            path = op.path
            max_pages = op.max_pages
        if backend is Backend.GRAPH:
            graph_perms.update(permissions)
            estimated += max(max_pages, 1)
        elif backend is Backend.ARM:
            arm_rbac.update(permissions or ("Reader",))
            estimated += max(max_pages, 1)
        elif backend is Backend.MDE:
            mde_perms.update(permissions or ("Machine.Read.All",))
            estimated += max(max_pages, 1)
        powershell = ""
        if key in {"exchange_bundle", "dns_records"}:
            powershell = "ExchangeOnlineManagement"
        rows.append(
            PlanCollectorRow(
                collector_id=str(step.collector.collector_id),
                produces=key,
                backend=backend.value if isinstance(backend, Backend) else str(backend),
                permissions=tuple(sorted(permissions)),
                path=path,
                max_pages=max_pages,
                timeout_seconds=int(timeout),
                powershell_module=powershell,
            )
        )

    # Full unfiltered scope: Graph permissions from SOURCE_META GRAPH backends.
    if profile is None and not workloads and not packs:
        full_graph: set[str] = set()
        for _sid, meta in SOURCE_META.items():
            if meta[0] is Backend.GRAPH:
                full_graph.update(meta[1])
        # REQUIRED is the operator-facing app-permission set.
        graph_out = tuple(REQUIRED_GRAPH_APP_PERMISSIONS)
    else:
        graph_out = tuple(sorted(graph_perms))

    return PlanPreview(
        owned=tuple(sorted(owned)),
        not_owned=not_owned,
        unknown_consumption=unknown_consumption,
        will_evaluate=tuple(will),
        not_licensed=tuple(not_licensed),
        manual=tuple(manual),
        not_implemented=tuple(not_implemented),
        collectors=tuple(rows),
        graph_permissions=graph_out,
        arm_rbac=tuple(sorted(arm_rbac)),
        mde_permissions=tuple(sorted(mde_perms)),
        estimated_max_requests=estimated,
        sku_part_numbers=tuple(sku.sku_part_number for sku in sku_list if sku.sku_part_number),
    )


def render_plan_markdown(preview: PlanPreview) -> str:
    lines = [
        "# Execution plan",
        "",
        "## Entitlements resolved",
        "",
        f"- Owned ({len(preview.owned)}): {', '.join(preview.owned) or '—'}",
        f"- Not owned ({len(preview.not_owned)}): {', '.join(preview.not_owned) or '—'}",
        f"- Unknown consumption ({len(preview.unknown_consumption)}): "
        f"{', '.join(preview.unknown_consumption) or '—'}",
        "",
        "## Checks",
        "",
        f"- Will evaluate ({len(preview.will_evaluate)})",
        f"- Not licensed ({len(preview.not_licensed)})",
        f"- Manual ({len(preview.manual)})",
        f"- Not implemented ({len(preview.not_implemented)})",
        "",
        "## Collectors",
        "",
        "| Collector | Backend | Path | Permissions | Max pages | Timeout |",
        "|-----------|---------|------|-------------|-----------|---------|",
    ]
    for row in preview.collectors:
        perms = ", ".join(row.permissions) or "—"
        lines.append(
            f"| `{row.produces}` | {row.backend} | `{row.path or '—'}` | {perms} | "
            f"{row.max_pages} | {row.timeout_seconds}s |"
        )
    lines += [
        "",
        "## Totals",
        "",
        f"- Graph application permissions ({len(preview.graph_permissions)}): "
        f"{', '.join(preview.graph_permissions) or '—'}",
        f"- ARM RBAC: {', '.join(preview.arm_rbac) or '—'}",
        f"- MDE permissions: {', '.join(preview.mde_permissions) or '—'}",
        f"- Estimated max requests: {preview.estimated_max_requests}",
        "",
        "## What this tool will never do",
        "",
    ]
    for item in preview.never_do:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def render_plan_json(preview: PlanPreview) -> str:
    import json

    return json.dumps(preview.to_dict(), indent=2, sort_keys=True) + "\n"
