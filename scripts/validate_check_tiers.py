#!/usr/bin/env python3
"""Fail closed if enabled checks violate the WS6-A activation/hygiene rule."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

from licenselens.catalog.loader import load_capabilities
from licenselens.engine.loader import load_checks
from licenselens.models import CheckTier

_SECURITY_PREFIXES: Final = (
    "entra_id_p2",
    "conditional_access",
    "identity_protection",
    "workload_identities_premium",
    "entitlement_management",
    "defender_",
    "microsoft_sentinel",
    "log_analytics",
    "purview_",
    "intune",
)
_BASE_WORKLOAD: Final = frozenset(
    {
        "exchange_online",
        "exchange_online_protection",
        "sharepoint_online",
        "onedrive_for_business",
        "teams",
        "power_platform",
        "power_bi_pro",
        "power_bi_premium",
    }
)
_PAID_KINDS: Final = frozenset({"included", "add_on", "consumption"})


def _is_paid_security(cap_id: str, kinds: dict[str, str]) -> bool:
    if cap_id in _BASE_WORKLOAD:
        return False
    if kinds.get(cap_id) not in _PAID_KINDS:
        return False
    return any(cap_id == prefix or cap_id.startswith(prefix) for prefix in _SECURITY_PREFIXES)


def validate_check_tiers(checks_root: Path | None = None) -> list[str]:
    kinds = {cap.id: cap.entitlement_kind for cap in load_capabilities()}
    violations: list[str] = []
    for check in load_checks(checks_root):
        if not check.enabled:
            continue
        paid = [cid for cid in check.required_capabilities if _is_paid_security(cid, kinds)]
        only_base = bool(check.required_capabilities) and all(
            cid in _BASE_WORKLOAD for cid in check.required_capabilities
        )
        if check.tier is CheckTier.HYGIENE and paid:
            violations.append(f"hygiene_requires_paid_security:{check.id}:{','.join(paid)}")
        if check.tier is CheckTier.ACTIVATION and only_base:
            violations.append(
                f"activation_only_base_workload:{check.id}:{','.join(check.required_capabilities)}"
            )
        if check.tier not in {CheckTier.ACTIVATION, CheckTier.HYGIENE}:
            violations.append(f"unknown_tier:{check.id}:{check.tier}")
    return violations


def main() -> int:
    violations = validate_check_tiers()
    if violations:
        print("Check tier validation FAILED:")
        for message in violations:
            print(f"  - {message}")
        return 1
    print("Check tier validation OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
