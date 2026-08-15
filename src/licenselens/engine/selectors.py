from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from licenselens.config_models import RuleSelector
from licenselens.models import Finding
from licenselens.schema_contracts import CollectionSummary

type RuleScalar = str | int | float | bool
type RuleValue = RuleScalar | tuple[RuleScalar, ...] | None
type SelectorAccessor = Callable[[SelectorContext], tuple[RuleValue, ...]]


@dataclass(frozen=True, slots=True)
class SelectorContext:
    findings: list[Finding]
    tenant_domains: list[str]
    sensitive_users: list[str]
    collection_summaries: list[CollectionSummary]


@dataclass(frozen=True, slots=True)
class SelectorLookupError(Exception):
    selector: str

    def __str__(self) -> str:
        return f"unknown selector: {self.selector}"


def select_values(selector: RuleSelector | str, context: SelectorContext) -> tuple[RuleValue, ...]:
    try:
        parsed = RuleSelector(selector)
    except ValueError as exc:
        raise SelectorLookupError(selector=str(selector)) from exc
    return SELECTORS[parsed](context)


def _finding_status(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(finding.status.value for finding in context.findings)


def _finding_severity(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(finding.severity.value for finding in context.findings)


def _finding_pack(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(finding.pack.value for finding in context.findings)


def _finding_workload(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(finding.workload.value for finding in context.findings)


def _finding_check_id(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(finding.check_id for finding in context.findings)


def _finding_confidence(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(finding.confidence.value for finding in context.findings)


def _finding_evaluation_mode(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(finding.evaluation_mode.value for finding in context.findings)


def _finding_entitlements(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(
        entitlement for finding in context.findings for entitlement in finding.entitlements_used
    )


def _tenant_domains(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(context.tenant_domains)


def _tenant_sensitive_users(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(context.sensitive_users)


def _collection_status(context: SelectorContext) -> tuple[RuleValue, ...]:
    return tuple(summary.status.value for summary in context.collection_summaries)


SELECTORS: Final[dict[RuleSelector, SelectorAccessor]] = {
    RuleSelector.FINDING_STATUS: _finding_status,
    RuleSelector.FINDING_SEVERITY: _finding_severity,
    RuleSelector.FINDING_PACK: _finding_pack,
    RuleSelector.FINDING_WORKLOAD: _finding_workload,
    RuleSelector.FINDING_CHECK_ID: _finding_check_id,
    RuleSelector.FINDING_CONFIDENCE: _finding_confidence,
    RuleSelector.FINDING_EVALUATION_MODE: _finding_evaluation_mode,
    RuleSelector.FINDING_ENTITLEMENTS: _finding_entitlements,
    RuleSelector.TENANT_DOMAINS: _tenant_domains,
    RuleSelector.TENANT_SENSITIVE_USERS: _tenant_sensitive_users,
    RuleSelector.COLLECTION_STATUS: _collection_status,
}
