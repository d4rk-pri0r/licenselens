"""RED contracts: capability closure (AF-D). Owned by todo 13."""

from __future__ import annotations

from licenselens.catalog.reference import build_reference_model

ORPHAN_CAPABILITIES_FORBIDDEN = frozenset(
    {
        "defender_endpoint_p1",
        "log_analytics",
        "power_bi_premium",
    }
)


def test_every_capability_has_non_empty_required_by_checks() -> None:
    """Capability closure: no shipped capability may have an empty required_by_checks mapping."""
    model = build_reference_model()
    orphans = sorted(cap.id for cap in model.capabilities if not cap.required_by_checks)
    assert not orphans, (
        "every capability must map to at least one check; "
        f"empty required_by_checks={orphans} (AF-D)"
    )
    still_forbidden = sorted(ORPHAN_CAPABILITIES_FORBIDDEN & set(orphans))
    assert not still_forbidden, f"audit-orphaned capabilities still empty: {still_forbidden}"
