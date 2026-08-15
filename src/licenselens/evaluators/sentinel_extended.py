"""Sentinel data-connector, automation-rule, and retention evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus


def _as_dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _workspace_missing(check_id: str) -> Evaluation:
    return Evaluation(
        status=FindingStatus.ERROR,
        summary=(
            f"Sentinel workspace was not provided. Pass --workspace-resource-id "
            f"to evaluate {check_id}."
        ),
        evidence={"hint": "workspace_required"},
        customer_summary=("We need the security workspace location to check this setting."),
    )


def evaluate_sen_data_connectors(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    if evidence.get("sentinel_workspace_missing"):
        return _workspace_missing("data connectors")

    connectors = _as_dict(evidence.get("sentinel_data_connectors"))
    if evidence.get("sentinel_data_connectors_error") and not connectors:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Could not read Sentinel data connectors: "
                f"{evidence['sentinel_data_connectors_error']}"
            ),
            evidence=connectors,
            customer_summary=(
                "We could not verify which data sources feed your security workspace. "
                "This is often missing Azure permissions."
            ),
        )

    total = int(connectors.get("total_connectors") or 0)
    key = list(connectors.get("key_connectors_connected") or [])
    evidence_out = dict(connectors)

    if total == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Sentinel data connectors were found in the workspace.",
            evidence=evidence_out,
            customer_summary=(
                "Your security command center has no data sources connected, so "
                "there is nothing to watch."
            ),
        )

    if total >= 3 and len(key) >= 2:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Sentinel data connectors look healthy: {total} connector(s), "
                f"{len(key)} high-value source(s) connected."
            ),
            evidence=evidence_out,
            customer_summary=("Your security workspace is fed by several high-value data sources."),
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Thin Sentinel data connectors: {total} connector(s), only "
            f"{len(key)} high-value source(s)."
        ),
        evidence=evidence_out,
        customer_summary=(
            "A few data sources are connected, but the main identity and "
            "Microsoft 365 signals may still be missing."
        ),
    )


def evaluate_sen_automation_rules(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    if evidence.get("sentinel_workspace_missing"):
        return _workspace_missing("automation rules")

    rules = _as_dict(evidence.get("sentinel_automation_rules"))
    if evidence.get("sentinel_automation_rules_error") and not rules:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Could not read Sentinel automation rules: "
                f"{evidence['sentinel_automation_rules_error']}"
            ),
            evidence=rules,
            customer_summary=("We could not verify automation on your security workspace."),
        )

    total = int(rules.get("total_automation_rules") or 0)
    playbook = int(rules.get("playbook_automation_rules") or 0)
    evidence_out = dict(rules)

    if total == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Sentinel automation rules or playbooks were found.",
            evidence=evidence_out,
            customer_summary=(
                "Your security workspace reacts to nothing automatically — every "
                "alert waits for a person."
            ),
        )

    if playbook >= 1:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"Sentinel automation is configured with {playbook} playbook action(s).",
            evidence=evidence_out,
            customer_summary=("Your workspace can react to alerts automatically."),
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(f"Found {total} automation rule(s) but none triggers a playbook (SOAR response)."),
        evidence=evidence_out,
        customer_summary=(
            "Automation rules exist, but they do not yet run automated playbook responses."
        ),
    )


def evaluate_sen_log_analytics_retention(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    if evidence.get("sentinel_workspace_missing"):
        return _workspace_missing("Log Analytics retention")

    workspace = _as_dict(evidence.get("sentinel_workspace"))
    if evidence.get("sentinel_workspace_error") and not workspace:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Could not read the Log Analytics workspace: "
                f"{evidence['sentinel_workspace_error']}"
            ),
            evidence=workspace,
            customer_summary=(
                "We could not verify log retention on the workspace (permissions or RBAC)."
            ),
        )

    retention = workspace.get("retention_in_days")
    evidence_out = dict(workspace)
    if retention is None:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Log Analytics retention could not be determined for the workspace.",
            evidence=evidence_out,
            customer_summary=("We could not confirm how long security logs are kept."),
        )

    if retention >= 90:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"Log Analytics retention is {retention} day(s), meeting the 90-day target.",
            evidence=evidence_out,
            customer_summary=("Security logs are kept long enough for investigations."),
        )

    if retention >= 60:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"Log Analytics retention is {retention} day(s), below the 90-day target.",
            evidence=evidence_out,
            customer_summary=("Log retention is workable but shorter than recommended."),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=f"Log Analytics retention is only {retention} day(s).",
        evidence=evidence_out,
        customer_summary=("Security logs may be erased before investigations can complete."),
    )
